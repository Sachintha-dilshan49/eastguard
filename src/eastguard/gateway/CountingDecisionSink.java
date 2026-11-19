package eastguard.gateway;

import eastguard.common.ReasonCode;
import eastguard.common.Verdict;
import java.util.concurrent.atomic.AtomicLongArray;

/**
 * Non-blocking {@link DecisionSink} that only counts decisions by verdict and reason. Used until the UDP
 * telemetry producer exists (Task 7), and by tests and demos. Thread-safe.
 */
public final class CountingDecisionSink implements DecisionSink {
    private final AtomicLongArray byVerdict = new AtomicLongArray(Verdict.values().length);
    private final AtomicLongArray byReason = new AtomicLongArray(ReasonCode.values().length);

    @Override
    public void record(GatewayDecision d) {
        byVerdict.incrementAndGet(d.verdict().ordinal());
        byReason.incrementAndGet(d.reason().ordinal());
    }

    public long count(Verdict v) {
        return byVerdict.get(v.ordinal());
    }

    public long count(ReasonCode r) {
        return byReason.get(r.ordinal());
    }

    public long total() {
        long n = 0;
        for (int i = 0; i < byVerdict.length(); i++) {
            n += byVerdict.get(i);
        }
        return n;
    }

    /** Non-zero reason counts, e.g. {@code OK=500 POLICY_DENY=1}. */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (ReasonCode r : ReasonCode.values()) {
            long n = count(r);
            if (n > 0) {
                sb.append(sb.isEmpty() ? "" : " ").append(r).append('=').append(n);
            }
        }
        return sb.isEmpty() ? "none" : sb.toString();
    }
}
