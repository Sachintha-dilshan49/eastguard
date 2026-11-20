package eastguard.common;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.StandardProtocolFamily;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Best-effort authenticated UDP telemetry producer (spec §5.3), used by gateways and the token service.
 *
 * <ul>
 *   <li>{@link #offer} never blocks: it builds the record and puts it on a bounded queue, or drops and counts it.
 *       It is safe to call from the gateway selector thread.</li>
 *   <li>One sender thread takes records off the queue, MACs them with this producer's own key, and sends them on
 *       a {@link DatagramChannel}. A send failure is counted; it never reaches the caller.</li>
 *   <li>Each start has a fresh random 16-byte boot ID and a sequence that starts at 0 and increases by one per
 *       offered record, <em>including dropped ones</em>, so the detector sees local drops as sequence gaps.</li>
 * </ul>
 *
 * A collector outage changes nothing about authorization: callers decide first and report afterwards.
 */
public final class TelemetrySender implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(TelemetrySender.class.getName());

    /**
     * Producer settings, from a component's properties. Telemetry is off when {@code telemetry.collector} is
     * absent.
     *
     * <pre>
     * telemetry.collector=127.0.0.1:5514          detector UDP listener (numeric)
     * telemetry.producerId=gw-app-02              must match the detector's trusted inventory
     * telemetry.keyId=tk1
     * telemetry.keyEnv=EASTGUARD_TELEMETRY_KEY    base64url HMAC key, else from the file below
     * telemetry.keyFile=keys/telemetry/gw-app-02.key
     * telemetry.queue=4096                        bounded queue; excess events are dropped and counted
     * </pre>
     */
    public record Settings(Endpoint collector, String producerId, String keyId, SecretSource key, int queueCapacity) {
        public Settings {
            Objects.requireNonNull(collector, "collector");
            Ids.require(producerId, "producerId");
            Ids.require(keyId, "keyId");
            Objects.requireNonNull(key, "key");
            if (queueCapacity < 1 || queueCapacity > 1_000_000) {
                throw new IllegalArgumentException("queueCapacity out of range");
            }
        }

        /** {@code null} when {@code telemetry.collector} is not configured. */
        public static Settings from(Config c) {
            if (c.optional("telemetry.collector") == null) {
                for (String k : new String[] {"telemetry.producerId", "telemetry.keyId", "telemetry.keyEnv",
                        "telemetry.keyFile", "telemetry.queue"}) {
                    if (c.optional(k) != null) {
                        throw new IllegalArgumentException("config " + c.source() + ": " + k
                                + " is set but telemetry.collector is not");
                    }
                }
                return null;
            }
            return new Settings(c.endpoint("telemetry.collector"), c.id("telemetry.producerId"), c.id("telemetry.keyId"),
                    new SecretSource(c.string("telemetry.keyEnv", "EASTGUARD_TELEMETRY_KEY"),
                            Path.of(c.string("telemetry.keyFile"))),
                    c.intIn("telemetry.queue", 4_096, 1, 1_000_000));
        }
    }

    /** Monotonic counters. {@code dropped} counts queue overflow; {@code invalid} counts unencodable events. */
    public record Stats(long offered, long dropped, long invalid, long sent, long sendErrors) {
    }

    private final String cluster;
    private final String producerId;
    private final String keyId;
    private final byte[] key;
    private final InetSocketAddress collector;
    private final Bytes bootId;
    private final ArrayBlockingQueue<Telemetry> queue;
    private final AtomicLong seq = new AtomicLong();
    private final AtomicLong offered = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong invalid = new AtomicLong();
    private final AtomicLong sent = new AtomicLong();
    private final AtomicLong sendErrors = new AtomicLong();

    private volatile boolean running;
    private Thread thread;
    private DatagramChannel channel;

    /** @param macKey this producer's HMAC key (at least 32 bytes); copied */
    public TelemetrySender(String cluster, String producerId, String keyId, byte[] macKey, InetSocketAddress collector,
            int queueCapacity, SecureRandom random) {
        this.cluster = Ids.require(cluster, "cluster");
        this.producerId = Ids.require(producerId, "producerId");
        this.keyId = Ids.require(keyId, "keyId");
        if (macKey == null || macKey.length < Hmac.MIN_KEY_LENGTH) {
            throw new IllegalArgumentException("telemetry key must be at least 32 bytes");
        }
        this.key = macKey.clone();
        this.collector = Objects.requireNonNull(collector, "collector");
        if (collector.isUnresolved()) {
            throw new IllegalArgumentException("collector must be a numeric address");
        }
        this.queue = new ArrayBlockingQueue<>(queueCapacity);
        byte[] b = new byte[Telemetry.BOOT_ID_LENGTH];
        random.nextBytes(b);
        this.bootId = Bytes.copyOf(b);
    }

    /** Reads the key named by {@code s} and builds a sender for {@code cluster}. Call {@link #start()} next. */
    public static TelemetrySender create(String cluster, Settings s) {
        byte[] k = readKey(s.key());
        try {
            return new TelemetrySender(cluster, s.producerId(), s.keyId(), k, s.collector().toSocketAddress(),
                    s.queueCapacity(), new SecureRandom());
        } finally {
            Arrays.fill(k, (byte) 0);
        }
    }

    /** Decodes a base64url key of 32..64 bytes (as written by {@code scripts/gen-credentials.ps1}). */
    public static byte[] readKey(SecretSource source) {
        char[] chars = source.read();
        byte[] ascii = new byte[chars.length];
        try {
            for (int i = 0; i < chars.length; i++) {
                ascii[i] = (byte) chars[i];
            }
            byte[] raw;
            try {
                raw = Base64.getUrlDecoder().decode(ascii);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("telemetry key from " + source + " is not base64url");
            }
            if (raw.length < Hmac.MIN_KEY_LENGTH || raw.length > 64) {
                Arrays.fill(raw, (byte) 0);
                throw new IllegalArgumentException("telemetry key from " + source + " must be 32..64 bytes");
            }
            return raw;
        } finally {
            Arrays.fill(chars, '\0');
            Arrays.fill(ascii, (byte) 0);
        }
    }

    public Bytes bootId() {
        return bootId;
    }

    public String producerId() {
        return producerId;
    }

    public synchronized void start() throws IOException {
        if (thread != null) {
            throw new IllegalStateException("already started");
        }
        channel = openChannel();
        running = true;
        thread = Thread.ofPlatform().daemon().name("telemetry-" + producerId).start(this::sendLoop);
        LOG.info(() -> "telemetry producer " + producerId + " sending to " + collector + " boot=" + bootId.hex());
    }

    private DatagramChannel openChannel() throws IOException {
        return DatagramChannel.open(collector.getAddress() instanceof java.net.Inet6Address
                ? StandardProtocolFamily.INET6 : StandardProtocolFamily.INET);
    }

    /**
     * Queues one decision event without blocking. Returns false if it was dropped (queue full or invalid
     * fields). Never throws.
     *
     * @param sourceIdentity identity established by TLS, or {@code null}; never a claim from an unverified token
     * @param destination    the listener the event concerns (gateway listener, decoy, or token service)
     */
    public boolean offer(long eventAtMs, String sourceIdentity, IpAddress sourceIp, String service, Endpoint destination,
            Verdict verdict, ReasonCode reason, boolean outsideApprovedGraph, long policyRevision) {
        offered.incrementAndGet();
        long n = seq.getAndIncrement(); // taken even if dropped, so the detector sees the loss as a gap
        Telemetry t;
        try {
            t = new Telemetry(cluster, producerId, keyId, bootId, n, eventAtMs, policyRevision, sourceIdentity,
                    sourceIp, service, destination.ip(), destination.port(), verdict, reason, outsideApprovedGraph);
        } catch (RuntimeException e) {
            invalid.incrementAndGet();
            return false;
        }
        if (!queue.offer(t)) {
            dropped.incrementAndGet();
            return false;
        }
        return true;
    }

    public Stats stats() {
        return new Stats(offered.get(), dropped.get(), invalid.get(), sent.get(), sendErrors.get());
    }

    private void sendLoop() {
        while (running || !queue.isEmpty()) {
            Telemetry t;
            try {
                t = queue.poll(200, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                break;
            }
            if (t == null) {
                continue;
            }
            try {
                channel.send(ByteBuffer.wrap(TelemetryCodec.encode(t, key)), collector);
                sent.incrementAndGet();
            } catch (ClosedChannelException e) {
                sendErrors.incrementAndGet();
                if (!running) {
                    break;
                }
                reopen();
            } catch (IOException | RuntimeException e) {
                sendErrors.incrementAndGet();
                LOG.log(Level.FINE, "telemetry send failed", e);
            }
        }
    }

    private void reopen() {
        try {
            channel = openChannel();
        } catch (IOException e) {
            LOG.log(Level.WARNING, "cannot reopen telemetry channel", e);
        }
    }

    /** Sends what is already queued for up to one second, then stops. */
    @Override
    public void close() {
        Thread t;
        synchronized (this) {
            running = false;
            t = thread;
        }
        if (t != null) {
            try {
                t.join(1_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        DatagramChannel c = channel;
        if (c != null) {
            try {
                c.close();
            } catch (IOException ignored) {
                // closing
            }
        }
        if (t == null || !t.isAlive()) {
            Arrays.fill(key, (byte) 0);
        }
    }
}
