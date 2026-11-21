package eastguard.bus;

import eastguard.common.Bytes;
import eastguard.common.Ids;
import eastguard.common.Notice;
import eastguard.common.NoticeCodec;
import eastguard.common.NoticeOperation;
import eastguard.common.Selector;
import eastguard.control.ControlPlaneImpl;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Control-plane side of the quarantine bus (spec §5.4, §6.2 step 1). Registered with
 * {@link ControlPlaneImpl#onContainment}, it receives each committed quarantine or release <em>after</em> the
 * journal record was forced, and on its own thread signs one EGC1 notice (1..8 selectors) with the control-plane
 * signer and sends the same bytes {@link #COPIES} times, a short gap apart.
 *
 * <ul>
 *   <li>{@link #committed} never blocks the writer: it enqueues on a bounded queue, or drops and counts.</li>
 *   <li>A send failure is counted and logged. It never undoes, delays or fails the commit; receivers converge
 *       through their authoritative sync.</li>
 *   <li>The signer is the control-plane key, never the lease key; its public key is published in the snapshot
 *       under {@code keyId}.</li>
 * </ul>
 */
public final class QuarantineSender implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(QuarantineSender.class.getName());
    public static final int COPIES = 3;
    private static final int QUEUE = 1_024;

    public record Stats(long committed, long notices, long datagrams, long sendFailures, long dropped, long skipped) {
    }

    private final String clusterId;
    private final String keyId;
    private final PrivateKey signer;
    private final NoticeTransport transport;
    private final Clock clock;
    private final SecureRandom random;
    private final Duration gap;
    private final BlockingQueue<ControlPlaneImpl.Containment> queue = new ArrayBlockingQueue<>(QUEUE);
    private final AtomicLong committed = new AtomicLong();
    private final AtomicLong notices = new AtomicLong();
    private final AtomicLong datagrams = new AtomicLong();
    private final AtomicLong sendFailures = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong skipped = new AtomicLong();
    private volatile boolean running;
    private Thread thread;

    /**
     * @param gap pause between the copies of one notice, so a short loss burst does not take all three
     */
    public QuarantineSender(String clusterId, String keyId, PrivateKey signer, NoticeTransport transport, Clock clock,
            SecureRandom random, Duration gap) {
        this.clusterId = Ids.require(clusterId, "clusterId");
        this.keyId = Ids.require(keyId, "keyId");
        this.signer = Objects.requireNonNull(signer, "signer");
        this.transport = Objects.requireNonNull(transport, "transport");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.random = Objects.requireNonNull(random, "random");
        this.gap = Objects.requireNonNull(gap, "gap");
        if (gap.isNegative() || gap.toMillis() > 1_000) {
            throw new IllegalArgumentException("gap 0..1000 ms");
        }
    }

    /**
     * Loads the control-plane notice signer and checks it against the key the journal publishes. A mismatch is
     * logged loudly: receivers would reject every notice (they still converge by polling).
     */
    public static QuarantineSender fromConfig(eastguard.control.ControlConfig.NoticeSigner cfg,
            eastguard.common.EnforcementSnapshot published, NoticeTransport transport, Clock clock) {
        char[] pw = cfg.password().read();
        java.security.PrivateKey key;
        java.security.PublicKey own;
        try {
            java.security.KeyStore ks = eastguard.common.KeyStores.load(cfg.keyStore(), pw);
            key = eastguard.common.KeyStores.privateKey(ks, cfg.alias(), pw, cfg.keyStore());
            own = eastguard.common.KeyStores.certificate(ks, cfg.alias(), cfg.keyStore()).getPublicKey();
            eastguard.common.Ed25519.rawPublicKey(own); // must be Ed25519
        } finally {
            java.util.Arrays.fill(pw, '\0');
        }
        java.security.PublicKey pub = published == null ? null : published.controlKey(cfg.keyId());
        if (pub == null || !java.util.Arrays.equals(pub.getEncoded(), own.getEncoded())) {
            LOG.severe("the enforcement snapshot does not publish this notice signer under key ID " + cfg.keyId()
                    + ": receivers will reject every notice. Bootstrap with bootstrap.controlKeys=" + cfg.keyId());
        }
        return new QuarantineSender(published == null ? "unbootstrapped" : published.clusterId(), cfg.keyId(), key,
                transport, clock, new SecureRandom(), cfg.repeatGap());
    }

    public synchronized QuarantineSender start() {
        if (thread != null) {
            throw new IllegalStateException("already started");
        }
        running = true;
        thread = Thread.ofPlatform().daemon().name("quarantine-sender").start(this::loop);
        return this;
    }

    /** Listener for {@link ControlPlaneImpl#onContainment}. Never blocks. */
    public void committed(ControlPlaneImpl.Containment c) {
        committed.incrementAndGet();
        if (!queue.offer(c)) {
            dropped.incrementAndGet();
            LOG.warning(() -> "notice queue full: revision " + c.revision() + " not multicast; receivers converge by sync");
        }
    }

    public Stats stats() {
        return new Stats(committed.get(), notices.get(), datagrams.get(), sendFailures.get(), dropped.get(),
                skipped.get());
    }

    private void loop() {
        while (running) {
            ControlPlaneImpl.Containment c;
            try {
                c = queue.poll(500, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                return;
            }
            if (c != null) {
                try {
                    send(c);
                } catch (InterruptedException e) {
                    return;
                } catch (RuntimeException e) {
                    sendFailures.incrementAndGet();
                    LOG.log(Level.WARNING, "notice for revision " + c.revision() + " not sent", e);
                }
            }
        }
    }

    private void send(ControlPlaneImpl.Containment c) throws InterruptedException {
        List<Selector> all = c.selectors();
        for (int i = 0; i < all.size(); i += Notice.MAX_SELECTORS) {
            List<Selector> chunk = all.subList(i, Math.min(all.size(), i + Notice.MAX_SELECTORS));
            long now = clock.millis();
            if (c.operation() == NoticeOperation.QUARANTINE && c.expiresAtMillis() <= now) {
                skipped.incrementAndGet(); // already due: the control plane commits its expiry next
                continue;
            }
            byte[] nonce = new byte[Notice.NONCE_LENGTH];
            random.nextBytes(nonce);
            Notice n = new Notice(clusterId, keyId, c.revision(), now, Bytes.copyOf(nonce), c.operation(),
                    c.operation() == NoticeOperation.QUARANTINE ? c.expiresAtMillis() : 0, chunk, c.reason());
            byte[] datagram = NoticeCodec.encode(n, signer);
            notices.incrementAndGet();
            for (int copy = 0; copy < COPIES; copy++) {
                if (copy > 0 && !gap.isZero()) {
                    Thread.sleep(gap.toMillis());
                }
                try {
                    transport.send(datagram);
                    datagrams.incrementAndGet();
                } catch (IOException e) {
                    sendFailures.incrementAndGet();
                    LOG.log(Level.WARNING, "multicast send failed for revision " + c.revision() + " (copy " + (copy + 1)
                            + "); the commit stands and receivers converge by sync", e);
                }
            }
            LOG.fine(() -> "notice " + n.operation() + " revision " + n.revision() + " " + n.selectors() + " sent");
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
