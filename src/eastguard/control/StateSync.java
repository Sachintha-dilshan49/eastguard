package eastguard.control;

import eastguard.common.CodecException;
import eastguard.common.Config;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.EnforcementView;
import eastguard.common.Ids;
import eastguard.common.Notice;
import eastguard.common.NoticeOperation;
import eastguard.common.Selector;
import eastguard.common.SnapshotCodec;
import eastguard.control.Dto.SyncResponse;
import java.io.IOException;
import java.security.PublicKey;
import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Authoritative state for an enforcement point (spec §6.2), kept off the data path: a background thread polls the
 * control plane about once per {@code poll} (±20 % jitter), verified multicast notices arrive through
 * {@link #onNotice} on the listener's thread, and readers get an immutable view through {@link #get()}, which
 * never blocks or does I/O.
 *
 * <h2>Freshness (steps 3-4)</h2>
 * <ul>
 *   <li><b>Fail closed from the start.</b> Until the first valid sync, {@link #get()} is not usable.</li>
 *   <li><b>Only a successful sync renews freshness</b>, for at most {@code maxAge} measured from the moment the
 *       request <em>started</em> (monotonic time).</li>
 *   <li>An "unchanged" reply renews only if it acknowledges exactly the installed revision. A snapshot older than
 *       the installed one, from another cluster, or that does not decode is neither installed nor renewing.</li>
 *   <li><b>Never renew from a response older than the newest verified notice.</b> Such a snapshot is still
 *       installed if it is newer than the current one (it is authoritative for its revision), but freshness is
 *       not renewed, and the thread re-polls quickly until it catches up.</li>
 * </ul>
 *
 * <h2>Notices and the overlay (steps 2, 3, 5)</h2>
 * <ul>
 *   <li>A notice at or below the installed revision is old news: ignored, so a late or replayed notice can never
 *       roll state back. Duplicates (same revision and nonce) are applied once.</li>
 *   <li>A newer QUARANTINE adds its selectors to a restrictive <em>overlay</em> at once, keyed per selector with
 *       the notice revision; {@code overlayListeners} are told about selectors that were not yet blocked (the
 *       gateway closes matching sessions through its session index). Each selector is tracked on its own, so a
 *       newer notice for another selector never displaces it.</li>
 *   <li>Any newer notice raises the "newest known revision" and asks for an immediate sync. While it is above the
 *       installed revision the view is <em>catching up</em>: {@link eastguard.common.PolicyEvaluator} pauses new
 *       issuance and admissions; established unrelated sessions continue within the freshness window.</li>
 *   <li>A RELEASE never clears anything by itself. An overlay entry is removed only when an installed snapshot's
 *       revision covers it; that snapshot then says whether the selector is still restricted.</li>
 * </ul>
 *
 * <p>Listeners run on the sync thread (new revision) or on the notice thread (overlay additions); they must not
 * block.
 */
public final class StateSync implements Supplier<EnforcementView>, AutoCloseable {
    private static final Logger LOG = Logger.getLogger(StateSync.class.getName());
    private static final int RECENT_NOTICES = 1_024;
    private static final long CATCH_UP_POLL_NANOS = 100_000_000L;

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

    /**
     * @param accepted     newer notices applied (each once)
     * @param duplicates   copies of a notice already applied
     * @param stale        notices at or below the installed revision (old news; ignored)
     * @param behindNotice sync replies that did not renew because they were older than the newest notice
     * @param newest       newest verified notice revision
     * @param overlay      selectors currently blocked by notices alone
     */
    public record NoticeStats(long accepted, long duplicates, long stale, long behindNotice, long newest, int overlay) {
    }

    private record Installed(EnforcementSnapshot snapshot, long freshUntilNanos) {
    }

    /** Everything {@link #get()} needs, published as one immutable value. */
    private record Published(Installed installed, Set<Selector> overlay, long newestNotice) {
    }

    private final String name;
    private final Source source;
    private final Settings settings;
    private final LongSupplier nanos;
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<Set<Selector>>> overlayListeners = new CopyOnWriteArrayList<>();
    private final AtomicLong ok = new AtomicLong();
    private final AtomicLong failed = new AtomicLong();
    private final AtomicLong rejected = new AtomicLong();
    private final AtomicLong installs = new AtomicLong();

    private final Object lock = new Object();
    private Installed installed; // guarded by lock
    private final Map<Selector, Long> overlay = new HashMap<>(); // selector -> newest quarantine notice; lock
    private final LinkedHashSet<String> recent = new LinkedHashSet<>(); // revision/nonce of applied notices; lock
    private long newestNotice; // guarded by lock
    private long accepted;
    private long duplicates;
    private long stale;
    private long behindNotice; // all four guarded by lock

    private volatile Published published = new Published(null, Set.of(), 0);
    private volatile boolean running;
    private Thread thread;

    /** @param nanos monotonic time source ({@code System::nanoTime}); injectable for tests */
    public StateSync(String name, Source source, Settings settings, LongSupplier nanos) {
        this.name = Objects.requireNonNull(name, "name");
        this.source = Objects.requireNonNull(source, "source");
        this.settings = Objects.requireNonNull(settings, "settings");
        this.nanos = Objects.requireNonNull(nanos, "nanos");
    }

    public String clusterId() {
        return settings.clusterId();
    }

    public void addListener(Runnable onNewRevision) {
        listeners.add(Objects.requireNonNull(onNewRevision));
    }

    /** Called with the selectors a notice newly blocked (not those already in the overlay). */
    public void addOverlayListener(Consumer<Set<Selector>> onNewlyBlocked) {
        overlayListeners.add(Objects.requireNonNull(onNewlyBlocked));
    }

    /** The current view. Never blocks; cheap enough to call per admission. */
    @Override
    public EnforcementView get() {
        Published p = published;
        Installed i = p.installed();
        if (i == null) {
            return EnforcementView.NOT_READY;
        }
        boolean fresh = nanos.getAsLong() - i.freshUntilNanos() < 0;
        long rev = i.snapshot().revision();
        return new EnforcementView(i.snapshot(), fresh, Math.max(rev, p.newestNotice()), p.overlay());
    }

    /**
     * The trusted notice key for {@code keyId} from the last installed snapshot (fresh or not: it is still the last
     * authenticated key set), or {@code null}. Used by the notice listener.
     */
    public PublicKey controlKey(String keyId) {
        Installed i = published.installed();
        return i == null ? null : i.snapshot().controlKey(keyId);
    }

    public Stats stats() {
        Installed i = published.installed();
        return new Stats(ok.get(), failed.get(), rejected.get(), installs.get(), i == null ? 0 : i.snapshot().revision());
    }

    public NoticeStats noticeStats() {
        synchronized (lock) {
            return new NoticeStats(accepted, duplicates, stale, behindNotice, newestNotice, overlay.size());
        }
    }

    /**
     * Applies one <em>verified</em> notice (signature, cluster, key, bounds and timestamp already checked by the
     * listener). Called on the notice listener's thread.
     */
    public void onNotice(Notice n) {
        Objects.requireNonNull(n, "notice");
        Set<Selector> added = new LinkedHashSet<>();
        synchronized (lock) {
            long installedRev = installed == null ? 0 : installed.snapshot().revision();
            if (n.revision() <= installedRev) {
                stale++; // already covered by authoritative state, so it can neither add nor remove anything
                return;
            }
            if (!recent.add(n.revision() + "/" + n.nonce().hex())) {
                duplicates++;
                return;
            }
            if (recent.size() > RECENT_NOTICES) {
                recent.remove(recent.iterator().next());
            }
            accepted++;
            newestNotice = Math.max(newestNotice, n.revision());
            if (n.operation() == NoticeOperation.QUARANTINE) {
                for (Selector s : n.selectors()) {
                    Long prev = overlay.get(s);
                    if (prev == null) {
                        added.add(s);
                    }
                    overlay.put(s, prev == null ? n.revision() : Math.max(prev, n.revision()));
                }
            }
            publishLocked();
        }
        LOG.info(() -> name + ": notice " + n.operation() + " revision " + n.revision() + " " + n.selectors()
                + (n.operation() == NoticeOperation.RELEASE ? " (sync requested; nothing cleared yet)" : ""));
        if (!added.isEmpty()) {
            Set<Selector> blocked = Set.copyOf(added);
            for (Consumer<Set<Selector>> l : overlayListeners) {
                try {
                    l.accept(blocked);
                } catch (RuntimeException e) {
                    LOG.log(Level.WARNING, name + ": overlay listener failed", e);
                }
            }
        }
        syncSoon();
    }

    /**
     * Performs one sync. Returns true if it renewed freshness. Called by the background thread, and directly by
     * tests.
     */
    public boolean syncOnce() {
        long start = nanos.getAsLong();
        long known;
        synchronized (lock) {
            known = installed == null ? 0 : installed.snapshot().revision(); // 0 never exists: forces a snapshot
        }
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
        EnforcementSnapshot fromReply = null;
        if (!r.unchanged()) {
            try {
                fromReply = SnapshotCodec.decode(Objects.requireNonNull(r.snapshot(), "snapshot").toArray());
            } catch (CodecException | NullPointerException e) {
                return reject("undecodable snapshot: " + e.getMessage());
            }
            if (fromReply.revision() != r.revision()) {
                return reject("snapshot revision " + fromReply.revision() + " disagrees with the reply's " + r.revision());
            }
            if (!fromReply.clusterId().equals(settings.clusterId())) {
                return reject("snapshot for another cluster");
            }
        }
        long until = start + settings.maxAge().toNanos();
        boolean changed;
        boolean behind;
        long newest;
        EnforcementSnapshot target;
        synchronized (lock) {
            Installed cur = installed;
            if (fromReply == null) {
                if (cur == null || r.revision() != cur.snapshot().revision()) {
                    return reject("acknowledgement of revision " + r.revision() + " does not match installed "
                            + (cur == null ? "nothing" : cur.snapshot().revision()));
                }
                target = cur.snapshot();
            } else {
                if (cur != null && fromReply.revision() < cur.snapshot().revision()) {
                    return reject("snapshot revision " + fromReply.revision() + " is older than installed "
                            + cur.snapshot().revision());
                }
                target = cur != null && fromReply.revision() == cur.snapshot().revision() ? cur.snapshot() : fromReply;
            }
            changed = cur == null || target.revision() != cur.snapshot().revision();
            newest = newestNotice;
            behind = r.revision() < newest;
            long keep;
            if (behind) {
                behindNotice++;
                keep = cur == null ? start : cur.freshUntilNanos(); // installed, but freshness not renewed
            } else {
                keep = cur == null || until - cur.freshUntilNanos() > 0 ? until : cur.freshUntilNanos();
            }
            installed = new Installed(target, keep);
            long rev = target.revision();
            overlay.values().removeIf(noticeRev -> noticeRev <= rev); // covered: the snapshot is authoritative
            publishLocked();
        }
        if (!behind) {
            ok.incrementAndGet();
        }
        if (changed) {
            installs.incrementAndGet();
            LOG.info(() -> name + ": installed enforcement revision " + target.revision());
            for (Runnable l : listeners) {
                try {
                    l.run();
                } catch (RuntimeException e) {
                    LOG.log(Level.WARNING, name + ": state listener failed", e);
                }
            }
        }
        if (behind) {
            LOG.fine(() -> name + ": reply at revision " + r.revision() + " is older than notice " + newest
                    + "; freshness not renewed");
            return false;
        }
        return true;
    }

    private void publishLocked() {
        published = new Published(installed, Set.copyOf(overlay.keySet()), newestNotice);
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

    /** Asks the background thread to sync now instead of at the next poll (a newer notice arrived). */
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
            if (get().catchingUp()) {
                wait = Math.min(wait, CATCH_UP_POLL_NANOS); // a known newer revision exists: fetch it soon
            }
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
