package eastguard.detector;

import eastguard.common.Bytes;
import eastguard.common.CodecException;
import eastguard.common.Ids;
import eastguard.common.Telemetry;
import eastguard.common.TelemetryCodec;
import java.time.Clock;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Verifies and deduplicates flow telemetry before anything scores it (spec §5.3, §6.1). In order:
 *
 * <ol>
 *   <li>Size: more than {@value TelemetryCodec#MAX_DATAGRAM} bytes is rejected without parsing.</li>
 *   <li>Format, cluster, producer key ID and HMAC with that producer's own key ({@link TelemetryCodec}).</li>
 *   <li>Producer-to-listener scope against the trusted inventory ({@link ProducerInventory#inScope}).</li>
 *   <li>Event time inside the acceptance window: not older than {@code acceptance}, not further in the future
 *       than {@code maxSkew}. This bounds how long a captured datagram stays replayable.</li>
 *   <li>Sequence: a {@link SeqWindow} per {@code (producerId, bootId)}. Duplicates and sequences that fell out of
 *       the window are rejected. Boot state is kept at least for the acceptance window; a producer with too many
 *       live boots gets no new one (fail closed).</li>
 * </ol>
 *
 * It also keeps a short history of input quality: when trusted producers' sequence gaps (lost or dropped
 * datagrams) exceed 10 % of the expected events in the last 10 s, {@link #degraded} is true and automation must
 * pause. Forged or malformed datagrams are counted but do not degrade input, so junk cannot switch automation
 * off. Thread-safe (one lock; in practice only the receive thread verifies).
 */
public final class TelemetryVerifier {
    public enum Result { ACCEPTED, OVERSIZE, MALFORMED, UNAUTHENTICATED, OUT_OF_SCOPE, STALE, DUPLICATE, TOO_OLD, BOOT_LIMIT }

    /**
     * @param acceptanceMillis how old an event may be (also the dedup retention and the restart guard)
     * @param maxSkewMillis    how far in the future an event time may be
     * @param seqWindow        sequence window size (power of two)
     * @param maxBootsPerProducer live boot IDs tracked per producer
     */
    public record Settings(long acceptanceMillis, long maxSkewMillis, int seqWindow, int maxBootsPerProducer) {
        public Settings {
            if (acceptanceMillis < 1_000 || maxSkewMillis < 0 || maxBootsPerProducer < 1) {
                throw new IllegalArgumentException("verifier settings out of range");
            }
            new SeqWindow(seqWindow); // validates the size
        }

        public static Settings defaults() {
            return new Settings(30_000, 5_000, 1_024, 8);
        }
    }

    /** An authenticated, in-scope, first-seen event with its monotonic receipt time. */
    public record Verified(Telemetry event, ProducerInventory.Kind producerKind, long receivedNanos) {
        public Verified {
            Objects.requireNonNull(event, "event");
            Objects.requireNonNull(producerKind, "producerKind");
        }

        /** Evidence reference: producer, boot and sequence; never payload. */
        public String ref() {
            return event.producerId() + "/" + event.bootId().hex().substring(0, 8) + "/" + event.seq();
        }
    }

    public record Outcome(Result result, Verified verified) {
        public boolean accepted() {
            return result == Result.ACCEPTED;
        }
    }

    /** @param missing sequence numbers skipped by trusted producers and never received */
    public record Stats(Map<Result, Long> results, long missing, long reordered, int liveBoots) {
        public Stats {
            results = Map.copyOf(results);
        }

        public long count(Result r) {
            return results.getOrDefault(r, 0L);
        }
    }

    private static final class Boot {
        final SeqWindow window;
        long lastSeenNanos;

        Boot(int size, long now) {
            this.window = new SeqWindow(size);
            this.lastSeenNanos = now;
        }
    }

    private static final int BUCKETS = 10;
    private static final long BUCKET_NANOS = 1_000_000_000L;

    private final String cluster;
    private final ProducerInventory inventory;
    private final Settings settings;
    private final Clock clock;
    private final Map<String, LinkedHashMap<Bytes, Boot>> boots = new HashMap<>();
    private final EnumMap<Result, Long> counts = new EnumMap<>(Result.class);
    private long missingRetired; // missing counts of evicted boots
    private long reorderedRetired;
    // Input quality: per one-second bucket, accepted events and newly missing sequence numbers.
    private final long[] bucketAccepted = new long[BUCKETS];
    private final long[] bucketMissing = new long[BUCKETS];
    private long bucketEpoch = Long.MIN_VALUE;

    public TelemetryVerifier(String cluster, ProducerInventory inventory, Settings settings, Clock clock) {
        this.cluster = Ids.require(cluster, "cluster");
        this.inventory = Objects.requireNonNull(inventory, "inventory");
        this.settings = Objects.requireNonNull(settings, "settings");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public Settings settings() {
        return settings;
    }

    /** Verifies {@code buf[0, length)}, received at monotonic {@code nowNanos}. */
    public synchronized Outcome verify(byte[] buf, int length, long nowNanos) {
        if (length > TelemetryCodec.MAX_DATAGRAM) {
            return reject(Result.OVERSIZE);
        }
        Telemetry t;
        try {
            t = TelemetryCodec.decode(buf, 0, length, cluster, inventory::key);
        } catch (CodecException e) {
            String m = String.valueOf(e.getMessage());
            boolean auth = m.equals("bad mac") || m.equals("unknown producer key") || m.equals("wrong cluster");
            return reject(auth ? Result.UNAUTHENTICATED : Result.MALFORMED);
        }
        if (!inventory.inScope(t)) {
            return reject(Result.OUT_OF_SCOPE);
        }
        long now = clock.millis();
        if (t.eventAtMs() < now - settings.acceptanceMillis() || t.eventAtMs() > now + settings.maxSkewMillis()) {
            return reject(Result.STALE);
        }
        Boot boot = boot(t, nowNanos);
        if (boot == null) {
            return reject(Result.BOOT_LIMIT);
        }
        long missingBefore = boot.window.missing();
        SeqWindow.Mark mark = boot.window.mark(t.seq());
        if (mark == SeqWindow.Mark.DUPLICATE) {
            return reject(Result.DUPLICATE);
        }
        if (mark == SeqWindow.Mark.TOO_OLD) {
            return reject(Result.TOO_OLD);
        }
        boot.lastSeenNanos = nowNanos;
        roll(nowNanos);
        int b = bucket(nowNanos);
        bucketAccepted[b]++;
        bucketMissing[b] += boot.window.missing() - missingBefore; // may be negative when a gap is filled
        counts.merge(Result.ACCEPTED, 1L, Long::sum);
        return new Outcome(Result.ACCEPTED,
                new Verified(t, inventory.producer(t.producerId()).kind(), nowNanos));
    }

    private Outcome reject(Result r) {
        counts.merge(r, 1L, Long::sum);
        return new Outcome(r, null);
    }

    private Boot boot(Telemetry t, long nowNanos) {
        LinkedHashMap<Bytes, Boot> perProducer = boots.computeIfAbsent(t.producerId(), k -> new LinkedHashMap<>());
        Boot b = perProducer.get(t.bootId());
        if (b != null) {
            return b;
        }
        if (perProducer.size() >= settings.maxBootsPerProducer()) {
            // Evict the least recently seen boot, but only once it is older than the acceptance window: until then
            // its datagrams could still be replayed and must still be recognised as duplicates.
            Map.Entry<Bytes, Boot> oldest = null;
            for (Map.Entry<Bytes, Boot> e : perProducer.entrySet()) {
                if (oldest == null || e.getValue().lastSeenNanos < oldest.getValue().lastSeenNanos) {
                    oldest = e;
                }
            }
            if (oldest == null || nowNanos - oldest.getValue().lastSeenNanos < settings.acceptanceMillis() * 1_000_000L) {
                return null;
            }
            missingRetired += oldest.getValue().window.missing();
            reorderedRetired += oldest.getValue().window.reordered();
            perProducer.remove(oldest.getKey());
        }
        b = new Boot(settings.seqWindow(), nowNanos);
        perProducer.put(t.bootId(), b);
        return b;
    }

    // ---- input quality ----

    private int bucket(long nowNanos) {
        return (int) Math.floorMod(Math.floorDiv(nowNanos, BUCKET_NANOS), (long) BUCKETS);
    }

    private void roll(long nowNanos) {
        long epoch = Math.floorDiv(nowNanos, BUCKET_NANOS);
        if (bucketEpoch == Long.MIN_VALUE || epoch - bucketEpoch >= BUCKETS) {
            java.util.Arrays.fill(bucketAccepted, 0);
            java.util.Arrays.fill(bucketMissing, 0);
        } else {
            for (long e = bucketEpoch + 1; e <= epoch; e++) {
                int i = (int) Math.floorMod(e, (long) BUCKETS);
                bucketAccepted[i] = 0;
                bucketMissing[i] = 0;
            }
        }
        bucketEpoch = Math.max(bucketEpoch, epoch);
    }

    /**
     * True when, over the last 10 s, at least 5 sequence numbers from trusted producers are missing and they are
     * more than 10 % of the events expected (received + missing).
     */
    public synchronized boolean degraded(long nowNanos) {
        roll(nowNanos);
        long accepted = 0;
        long missing = 0;
        for (int i = 0; i < BUCKETS; i++) {
            accepted += bucketAccepted[i];
            missing += bucketMissing[i];
        }
        return missing >= 5 && missing * 10 > accepted + missing;
    }

    public synchronized Stats stats() {
        long missing = missingRetired;
        long reordered = reorderedRetired;
        int live = 0;
        for (Map<Bytes, Boot> m : boots.values()) {
            for (Boot b : m.values()) {
                missing += b.window.missing();
                reordered += b.window.reordered();
                live++;
            }
        }
        return new Stats(counts, missing, reordered, live);
    }
}
