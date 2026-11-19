package eastguard.gateway;

import eastguard.common.Endpoint;
import eastguard.common.Ids;
import eastguard.common.IpAddress;
import eastguard.common.ReasonCode;
import eastguard.common.Verdict;
import java.util.Objects;

/**
 * One connection decision, as handed to a {@link DecisionSink}. Carries what a {@code EGF1} telemetry record
 * needs (spec §5.3) apart from the producer's own fields (key ID, boot ID, sequence), which the UDP producer adds
 * in Task 7. Never carries the token or any payload.
 *
 * @param sourceIdentity identity established by TLS and mapped from the certificate SAN, or {@code null}; never
 *                       a claim taken from an unverified token
 * @param destination    the listener the connection arrived on (the gateway listener or a decoy)
 * @param outsideApprovedGraph telemetry flag bit 0
 */
public record GatewayDecision(long eventAtMs, String sourceIdentity, IpAddress sourceIp, String service,
        Endpoint destination, Verdict verdict, ReasonCode reason, boolean outsideApprovedGraph, long policyRevision) {

    public GatewayDecision {
        Ids.requireOptional(sourceIdentity, "sourceIdentity");
        Objects.requireNonNull(sourceIp, "sourceIp");
        Ids.require(service, "service");
        Objects.requireNonNull(destination, "destination");
        Objects.requireNonNull(verdict, "verdict");
        Objects.requireNonNull(reason, "reason");
        boolean consistent = switch (verdict) {
            case ALLOW -> reason == ReasonCode.OK;
            case DENY -> reason != ReasonCode.OK && reason != ReasonCode.DECOY_TOUCH;
            case DECOY -> reason == ReasonCode.DECOY_TOUCH;
        };
        if (!consistent) {
            throw new IllegalArgumentException("verdict and reason disagree");
        }
    }
}
