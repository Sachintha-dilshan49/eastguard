package eastguard.common;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Detector alert (spec §3.1).
 *
 * @param sourceIdentity trusted attribution only: an identity established by TLS, or {@code null}; never a
 *                       claim taken from an unverified token
 * @param signals        contributing signal names, e.g. {@code DECOY_TOUCH}, {@code POLICY_DENY_BURST}
 * @param evidenceRefs   references to telemetry events (producer/boot/seq), never payloads
 */
public record Alert(String id, String sourceIdentity, IpAddress sourceIp, List<String> signals, int score,
        AlertStatus status, List<String> evidenceRefs, Instant raisedAt) {
    public Alert {
        Ids.require(id, "alert id");
        Ids.requireOptional(sourceIdentity, "sourceIdentity");
        Objects.requireNonNull(sourceIp, "sourceIp");
        signals = List.copyOf(Objects.requireNonNull(signals, "signals"));
        Objects.requireNonNull(status, "status");
        evidenceRefs = List.copyOf(Objects.requireNonNull(evidenceRefs, "evidenceRefs"));
        Objects.requireNonNull(raisedAt, "raisedAt");
        if (score < 0) {
            throw new IllegalArgumentException("score negative");
        }
        if (signals.isEmpty()) {
            throw new IllegalArgumentException("alert needs at least one signal");
        }
    }
}
