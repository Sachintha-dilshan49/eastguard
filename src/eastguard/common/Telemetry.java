package eastguard.common;

import java.util.Objects;

/**
 * One gateway (or token-service) decision event (spec §5.3). Times are Unix milliseconds as on the wire.
 *
 * @param sourceIdentity identity established by TLS, or {@code null}; never a claim from an unverified token
 * @param outsideApprovedGraph flag bit 0: the edge is not in the approved graph (a pilot observation when
 *                             combined with ALLOW)
 */
public record Telemetry(String cluster, String producerId, String keyId, Bytes bootId, long seq, long eventAtMs,
        long policyRevision, String sourceIdentity, IpAddress sourceIp, String service, IpAddress dstIp,
        int dstPort, Verdict verdict, ReasonCode reason, boolean outsideApprovedGraph) {

    public static final int BOOT_ID_LENGTH = 16;

    public Telemetry {
        Ids.require(cluster, "cluster");
        Ids.require(producerId, "producerId");
        Ids.require(keyId, "keyId");
        Objects.requireNonNull(bootId, "bootId").requireLength(BOOT_ID_LENGTH, "bootId");
        if (seq < 0 || eventAtMs < 0 || policyRevision < 0) {
            throw new IllegalArgumentException("seq, eventAt and policyRevision must be nonnegative");
        }
        Ids.requireOptional(sourceIdentity, "sourceIdentity");
        Objects.requireNonNull(sourceIp, "sourceIp");
        Ids.require(service, "service");
        Objects.requireNonNull(dstIp, "dstIp");
        if (dstPort < 1 || dstPort > 65535) {
            throw new IllegalArgumentException("dstPort out of range");
        }
        Objects.requireNonNull(verdict, "verdict");
        Objects.requireNonNull(reason, "reason");
        // Keep verdict and reason consistent so a detector never has to guess which one to believe.
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
