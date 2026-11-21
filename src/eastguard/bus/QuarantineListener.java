package eastguard.bus;

import eastguard.common.CodecException;
import eastguard.common.Ids;
import eastguard.common.Notice;
import eastguard.common.NoticeCodec;
import java.io.IOException;
import java.security.PublicKey;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Enforcement-point side of the quarantine bus (spec §5.4, §6.2), used by gateways and the token service.
 *
 * <ul>
 *   <li>{@link #start} joins the group <em>before</em> returning, so callers start it before their first sync and
 *       cannot miss a notice committed after that sync began.</li>
 *   <li>Runs on its own platform thread, never on a gateway selector.</li>
 *   <li>Each datagram is checked by {@link NoticeCodec#decode}: size, format and bounds (1..8 selectors), cluster,
 *       a trusted control key (from the installed snapshot), the Ed25519 signature, and {@code sentAt} within
 *       ±30 s of the local clock. Only verified notices reach the sink ({@code StateSync::onNotice}).</li>
 *   <li>A notice that arrives before any control key is trusted (before the first snapshot) is held, at most
 *       {@value #MAX_EARLY} of them, and retried every {@value #TICK_MILLIS} ms until it verifies or its
 *       timestamp leaves the skew window.</li>
 * </ul>
 * Rejections are counted by reason and logged at FINE (forged traffic must not flood the log); never the bytes.
 */
public final class QuarantineListener implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(QuarantineListener.class.getName());
    static final int MAX_EARLY = 16;
    static final int TICK_MILLIS = 200;

    private final String name;
    private final String clusterId;
    private final NoticeTransport.Receiver receiver;
    private final Function<String, PublicKey> trustedKeys;
    private final Clock clock;
    private final Consumer<Notice> sink;
    private record Held(byte[] datagram, long receivedNanos) {
    }

    private final ArrayDeque<Held> early = new ArrayDeque<>(); // listener thread only
    private final AtomicLong received = new AtomicLong();
    private final AtomicLong accepted = new AtomicLong();
    private final Map<String, AtomicLong> rejected = new ConcurrentHashMap<>();
    private volatile boolean running = true;
    private final Thread thread;

    private QuarantineListener(String name, String clusterId, NoticeTransport.Receiver receiver,
            Function<String, PublicKey> trustedKeys, Clock clock, Consumer<Notice> sink) {
        this.name = name;
        this.clusterId = clusterId;
        this.receiver = receiver;
        this.trustedKeys = trustedKeys;
        this.clock = clock;
        this.sink = sink;
        this.thread = Thread.ofPlatform().daemon().name(name + "-notices").unstarted(this::loop);
    }

    /**
     * Joins and starts listening.
     *
     * @param trustedKeys trusted control-plane key for a key ID, or {@code null}; typically
     *                    {@code StateSync::controlKey}
     * @param sink        receives verified notices on the listener thread; must not block
     */
    public static QuarantineListener start(String name, String clusterId, NoticeTransport transport,
            Function<String, PublicKey> trustedKeys, Clock clock, Consumer<Notice> sink) throws IOException {
        Objects.requireNonNull(name, "name");
        Ids.require(clusterId, "clusterId");
        Objects.requireNonNull(trustedKeys, "trustedKeys");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(sink, "sink");
        NoticeTransport.Receiver r = transport.join(); // membership is in place when this returns
        QuarantineListener l = new QuarantineListener(name, clusterId, r, trustedKeys, clock, sink);
        l.thread.start();
        return l;
    }

    /**
     * The usual wiring: notices are verified against the control keys of {@code sync}'s installed snapshot and
     * applied to it. Call before {@code sync.start()}.
     */
    public static QuarantineListener forSync(String name, NoticeTransport transport, eastguard.control.StateSync sync,
            Clock clock) throws IOException {
        return start(name, sync.clusterId(), transport, sync::controlKey, clock, sync::onNotice);
    }

    public long received() {
        return received.get();
    }

    public long accepted() {
        return accepted.get();
    }

    /** Rejected datagrams by reason ("bad signature", "wrong cluster", "untrusted control key", ...). */
    public Map<String, Long> rejected() {
        Map<String, Long> out = new TreeMap<>();
        rejected.forEach((k, v) -> out.put(k, v.get()));
        return out;
    }

    public long rejectedTotal() {
        long n = 0;
        for (AtomicLong v : rejected.values()) {
            n += v.get();
        }
        return n;
    }

    public long rejected(String reason) {
        AtomicLong n = rejected.get(reason);
        return n == null ? 0 : n.get();
    }

    private void loop() {
        byte[] buf = new byte[NoticeTransport.MAX_DATAGRAM + 1];
        while (running) {
            int n;
            try {
                n = receiver.receive(buf, TICK_MILLIS);
            } catch (IOException e) {
                if (!running) {
                    return;
                }
                LOG.log(Level.WARNING, name + ": notice receive failed", e);
                n = 0;
                sleepBriefly();
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, name + ": notice receive failed", e);
                n = 0;
                sleepBriefly();
            }
            if (n < 0) {
                return;
            }
            if (n > 0) {
                received.incrementAndGet();
                handle(buf, n, true);
            }
            retryEarly();
        }
    }

    private void handle(byte[] buf, int length, boolean fresh) {
        Notice notice;
        try {
            notice = NoticeCodec.decode(buf, 0, length, clusterId, trustedKeys, clock);
        } catch (CodecException e) {
            String why = e.getMessage();
            if (fresh && "untrusted control key".equals(why) && length <= NoticeTransport.MAX_DATAGRAM) {
                if (early.size() == MAX_EARLY) {
                    early.removeFirst();
                }
                byte[] copy = new byte[length];
                System.arraycopy(buf, 0, copy, 0, length);
                early.addLast(new Held(copy, System.nanoTime()));
            }
            if (fresh) {
                rejected.computeIfAbsent(why == null ? "invalid" : why, k -> new AtomicLong()).incrementAndGet();
                LOG.fine(() -> name + ": notice rejected: " + why);
            }
            return;
        } catch (RuntimeException e) {
            rejected.computeIfAbsent("invalid", k -> new AtomicLong()).incrementAndGet();
            return;
        }
        deliver(notice);
    }

    /** Hands a verified notice to the sink; {@link #accepted()} counts it once the sink has applied it. */
    private void deliver(Notice notice) {
        try {
            sink.accept(notice);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, name + ": notice sink failed", e);
        } finally {
            accepted.incrementAndGet();
        }
    }

    /** Re-verifies held notices; drops those that verified or whose timestamp left the skew window. */
    private void retryEarly() {
        for (int i = early.size(); i > 0; i--) {
            Held h = early.removeFirst();
            if (System.nanoTime() - h.receivedNanos() > NoticeCodec.MAX_CLOCK_SKEW_MS * 1_000_000L) {
                continue; // could not be verified within the skew window: gone
            }
            byte[] d = h.datagram();
            try {
                deliver(NoticeCodec.decode(d, 0, d.length, clusterId, trustedKeys, clock));
            } catch (CodecException e) {
                if ("untrusted control key".equals(e.getMessage())) {
                    early.addLast(h); // still no trusted key: keep waiting
                }
            } catch (RuntimeException e) {
                LOG.log(Level.FINE, name + ": held notice dropped", e);
            }
        }
    }

    private static void sleepBriefly() {
        try {
            Thread.sleep(TICK_MILLIS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public void close() {
        running = false;
        receiver.close();
        thread.interrupt();
        try {
            thread.join(2_000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
