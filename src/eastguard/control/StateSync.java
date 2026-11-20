package eastguard.control;

import eastguard.common.CodecException;
import eastguard.common.Config;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.EnforcementView;
import eastguard.common.Ids;
import eastguard.common.SnapshotCodec;
import eastguard.control.Dto.SyncResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Authoritative state for an enforcement point (spec §6.2 steps 3-4), kept off the data path: a background
 * thread polls the control plane about once per {@code poll} (±20 % jitter) and publishes an immutable view.
 * Gateways and the token service read it through {@link #get()}, which never blocks or does I/O.
 *
 * <ul>
 *   <li><b>Fail closed from the start.</b> Until the first valid sync, {@link #get()} is
 *       {@link EnforcementView#NOT_READY}: no admissions, no issuance.</li>
 *   <li><b>Only a successful sync renews freshness</b>, for at most {@code maxAge} measured from the moment
 *       the request <em>started</em> (monotonic time), so a slow reply cannot stretch the window.</li>
 *   <li>An "unchanged" reply renews only if it acknowledges exactly the installed revision. A snapshot older than
 *       the installed one, from another cluster, or that does not decode is neither installed nor allowed to
 *       renew. Failures and error replies renew nothing; after {@code maxAge} the view is unusable and
 *       enforcement points deny and close sessions.</li>
 *   <li>Listeners run on the sync thread after a new revision is installed (the gateway re-evaluates its
 *       sessions); they must not block.</li>
 * </ul>
 */
public final class StateSync implements Supplier<EnforcementView>, AutoCloseable {
    private static final Logger LOG = Logger.getLogger(StateSync.class.getName());

    /** One sync call; the production source is {@link ControlClient#sync}. */
    @FunctionalInterface
    public interface Source {
        SyncResponse sync(long knownRevision) throws IOException;
    }

    /**
     * <pre>
     * cluster.id=eg-demo          the snapshot must belong to this cluster
     * state.pollMillis=1000       poll interval, jittered by +-20 %
     * state.maxAgeMillis=5000     freshness after a successful sync, from request start
     * </pre>
     */
    public record Settings(String clusterId, Duration poll, Duration maxAge) {
        public Settings {
            Ids.require(clusterId, "clusterId");
            if (poll.toMillis() < 10 || maxAge.toMillis() < 10 || maxAge.compareTo(Duration.ofSeconds(60)) > 0) {
                throw new IllegalArgumentException("poll and maxAge out of range");
            }
        }

        public static Settings from(Config c) {
            return new Settings(c.id("cluster.id"), c.millis("state.pollMillis", 1_000, 10, 60_000),
                    c.millis("state.maxAgeMillis", 5_000, 10, 60_000));
        }
    }

    public record Stats(long ok, long failed, long rejected, long installs, long revision) {
    }

    private record Installed(EnforcementSnapshot snapshot, long freshUntilNanos) {
    }

    private final String name;
    private final Source source;
    private final Settings settings;
    private final LongSupplier nanos;
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private final AtomicLong ok = new AtomicLong();
    private final AtomicLong failed = new AtomicLong();
    private final AtomicLong rejected = new AtomicLong();
    private final AtomicLong installs = new AtomicLong();
    private volatile Installed installed;
    private volatile boolean running;
    private Thread thread;

    /** @param nanos monotonic time source ({@code System::nanoTime}); injectable for tests */
    public StateSync(String name, Source source, Settings settings, LongSupplier nanos) {
        this.name = Objects.requireNonNull(name, "name");
        this.source = Objects.requireNonNull(source, "source");
        this.settings = Objects.requireNonNull(settings, "settings");
        this.nanos = Objects.requireNonNull(nanos, "nanos");
    }

    public void addListener(Runnable onNewRevision) {
        listeners.add(Objects.requireNonNull(onNewRevision));
    }

    /** The current view. Never blocks; cheap enough to call per admission. */
    @Override
    public EnforcementView get() {
        Installed i = installed;
        if (i == null) {
            return EnforcementView.NOT_READY;
        }
        boolean fresh = nanos.getAsLong() - i.freshUntilNanos() < 0;
        // Task 8 adds the newest revision seen in a verified notice and the quarantine overlay.
        return new EnforcementView(i.snapshot(), fresh, i.snapshot().revision(), Set.of());
    }

    public Stats stats() {
        Installed i = installed;
        return new Stats(ok.get(), failed.get(), rejected.get(), installs.get(), i == null ? 0 : i.snapshot().revision());
    }

    /**
     * Performs one sync. Returns true if it renewed freshness. Called by the background thread, and directly by
     * tests.
     */
    public boolean syncOnce() {
        long start = nanos.getAsLong();
        Installed cur = installed;
        long known = cur == null ? 0 : cur.snapshot().revision(); // 0 never exists: forces a full snapshot
        SyncResponse r;
        try {
            r = source.sync(known);
        } catch (IOException | RuntimeException e) {
            failed.incrementAndGet();
            LOG.log(Level.FINE, name + ": sync failed", e);
            return false;
        }
        if (r == null || !r.ok()) {
            failed.incrementAndGet();
            LOG.fine(() -> name + ": sync refused: " + (r == null ? "no reply" : r.error() + " " + r.message()));
            return false;
        }
        long until = start + settings.maxAge().toNanos();
        if (r.unchanged()) {
            if (cur == null || r.revision() != cur.snapshot().revision()) {
                return reject("acknowledgement of revision " + r.revision() + " does not match installed "
                        + (cur == null ? "nothing" : cur.snapshot().revision()));
            }
            renew(cur.snapshot(), cur, until);
            return true;
        }
        EnforcementSnapshot s;
        try {
            s = SnapshotCodec.decode(Objects.requireNonNull(r.snapshot(), "snapshot").toArray());
        } catch (CodecException | NullPointerException e) {
            return reject("undecodable snapshot: " + e.getMessage());
        }
        if (s.revision() != r.revision()) {
            return reject("snapshot revision " + s.revision() + " disagrees with the reply's " + r.revision());
        }
        if (!s.clusterId().equals(settings.clusterId())) {
            return reject("snapshot for another cluster");
        }
        if (cur != null && s.revision() < cur.snapshot().revision()) {
            return reject("snapshot revision " + s.revision() + " is older than installed " + cur.snapshot().revision());
        }
        boolean changed = cur == null || s.revision() != cur.snapshot().revision();
        renew(changed ? s : cur.snapshot(), cur, until);
        if (changed) {
            installs.incrementAndGet();
            LOG.info(() -> name + ": installed enforcement revision " + s.revision());
            for (Runnable l : listeners) {
                try {
                    l.run();
                } catch (RuntimeException e) {
                    LOG.log(Level.WARNING, name + ": state listener failed", e);
                }
            }
        }
        return true;
    }

    /** Freshness only moves forward; each candidate deadline is at most maxAge after its own request start. */
    private void renew(EnforcementSnapshot s, Installed cur, long until) {
        long keep = cur == null || until - cur.freshUntilNanos() > 0 ? until : cur.freshUntilNanos();
        installed = new Installed(s, keep);
        ok.incrementAndGet();
    }

    private boolean reject(String why) {
        rejected.incrementAndGet();
        LOG.warning(() -> name + ": " + why + "; freshness not renewed");
        return false;
    }

    public synchronized StateSync start() {
        if (thread != null) {
            throw new IllegalStateException("already started");
        }
        running = true;
        thread = Thread.ofPlatform().daemon().name(name + "-state-sync").start(this::loop);
        return this;
    }

    /** Asks the background thread to sync now instead of at the next poll (Task 8: on a newer notice). */
    public void syncSoon() {
        Thread t = thread;
        if (t != null) {
            LockSupport.unpark(t);
        }
    }

    private void loop() {
        while (running) {
            syncOnce();
            long base = settings.poll().toNanos();
            long jitter = (long) (base * 0.2);
            long wait = base - jitter + ThreadLocalRandom.current().nextLong(2 * jitter + 1);
            LockSupport.parkNanos(this, wait); // syncSoon() unparks early; an early wake-up just syncs sooner
            if (Thread.interrupted()) {
                return;
            }
        }
    }

    @Override
    public void close() {
        Thread t;
        synchronized (this) {
            running = false;
            t = thread;
        }
        if (t != null) {
            t.interrupt();
            try {
                t.join(2_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
