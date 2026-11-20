package eastguard.detector;

import eastguard.common.Edge;
import eastguard.common.Telemetry;
import eastguard.common.Verdict;
import eastguard.control.Dto;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Learning observations (spec §3.2): a verified gateway ALLOW for an authenticated identity carrying flag bit 0
 * (outside the approved graph) is a successful pilot admission. Each distinct edge is aggregated (first/last event
 * time, count) and sent to the control plane in bounded batches, where pilot scope is rechecked. Nothing here
 * grants anything: a lost datagram only omits a candidate, and only an operator's freeze turns candidates into
 * approved edges. Single-threaded (the receive thread).
 */
public final class LearningCollector {
    private record Pending(long first, long last, long count) {
    }

    private final int maxPending;
    private final int batchSize;
    private final long flushNanos;
    private final Map<Edge, Pending> pending = new LinkedHashMap<>();
    private long lastFlushNanos;
    private long dropped;
    private long observed;

    /**
     * @param maxPending distinct edges held between flushes; further new edges are dropped and counted
     * @param batchSize  observations per {@code recordObservations} call (at most 500)
     * @param flushMillis send pending observations at least this often
     */
    public LearningCollector(int maxPending, int batchSize, long flushMillis, long startNanos) {
        if (maxPending < 1 || batchSize < 1 || batchSize > Dto.ObservationBatch.MAX_OBSERVATIONS || flushMillis < 1) {
            throw new IllegalArgumentException("learning settings out of range");
        }
        this.maxPending = maxPending;
        this.batchSize = batchSize;
        this.flushNanos = flushMillis * 1_000_000L;
        this.lastFlushNanos = startNanos;
    }

    /** True for the events that are learning observations. */
    public static boolean isObservation(TelemetryVerifier.Verified v) {
        Telemetry t = v.event();
        return v.producerKind() == ProducerInventory.Kind.GATEWAY && t.verdict() == Verdict.ALLOW
                && t.outsideApprovedGraph() && t.sourceIdentity() != null;
    }

    public void accept(TelemetryVerifier.Verified v) {
        if (!isObservation(v)) {
            return;
        }
        Telemetry t = v.event();
        Edge e = new Edge(t.sourceIdentity(), t.service());
        Pending p = pending.get(e);
        if (p == null) {
            if (pending.size() >= maxPending) {
                dropped++;
                return;
            }
            p = new Pending(t.eventAtMs(), t.eventAtMs(), 0);
        }
        pending.put(e, new Pending(Math.min(p.first(), t.eventAtMs()), Math.max(p.last(), t.eventAtMs()), p.count() + 1));
        observed++;
    }

    /** Batches to send now: when a full batch is waiting, or the flush interval passed with anything pending. */
    public List<List<Dto.Observation>> due(long nowNanos) {
        if (pending.isEmpty() || (pending.size() < batchSize && nowNanos - lastFlushNanos < flushNanos)) {
            return List.of();
        }
        lastFlushNanos = nowNanos;
        List<List<Dto.Observation>> out = new ArrayList<>();
        List<Dto.Observation> batch = new ArrayList<>();
        for (Iterator<Map.Entry<Edge, Pending>> it = pending.entrySet().iterator(); it.hasNext();) {
            Map.Entry<Edge, Pending> e = it.next();
            it.remove();
            batch.add(new Dto.Observation(e.getKey(), e.getValue().first(), e.getValue().last(), e.getValue().count()));
            if (batch.size() == batchSize) {
                out.add(List.copyOf(batch));
                batch.clear();
            }
        }
        if (!batch.isEmpty()) {
            out.add(List.copyOf(batch));
        }
        return out;
    }

    public int pending() {
        return pending.size();
    }

    public long dropped() {
        return dropped;
    }

    public long observed() {
        return observed;
    }
}
