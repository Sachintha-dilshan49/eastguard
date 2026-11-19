package eastguard.gateway;

/**
 * Where the gateway reports connection decisions (spec §5.3 producer side). The UDP telemetry producer
 * implements this in Task 7.
 *
 * <p>Called on the gateway selector thread: implementations must not block, must not do I/O inline, and should
 * drop (and count) events they cannot accept. A failing sink never affects an authorization decision; the
 * gateway catches and ignores runtime exceptions from it.
 */
@FunctionalInterface
public interface DecisionSink {
    void record(GatewayDecision decision);

    DecisionSink NONE = d -> { };
}
