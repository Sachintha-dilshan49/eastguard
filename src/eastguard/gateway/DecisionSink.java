package eastguard.gateway;

import eastguard.common.TelemetrySender;

/**
 * Where the gateway reports connection decisions (spec §5.3 producer side): {@link #udp} in production,
 * {@link CountingDecisionSink} in tests and demos.
 *
 * <p>Called on the gateway selector thread: implementations must not block, must not do I/O inline, and should
 * drop (and count) events they cannot accept. A failing sink never affects an authorization decision; the
 * gateway catches and ignores runtime exceptions from it.
 */
@FunctionalInterface
public interface DecisionSink {
    void record(GatewayDecision decision);

    DecisionSink NONE = d -> { };

    /** Hands every decision to the non-blocking UDP producer, which drops (and counts) when its queue is full. */
    static DecisionSink udp(TelemetrySender sender) {
        return d -> sender.offer(d.eventAtMs(), d.sourceIdentity(), d.sourceIp(), d.service(), d.destination(),
                d.verdict(), d.reason(), d.outsideApprovedGraph(), d.policyRevision());
    }

    /** Both sinks, in order. */
    static DecisionSink both(DecisionSink a, DecisionSink b) {
        return d -> {
            a.record(d);
            b.record(d);
        };
    }
}
