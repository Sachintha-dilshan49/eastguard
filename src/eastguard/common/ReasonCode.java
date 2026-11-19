package eastguard.common;

/**
 * Stable decision reason codes (spec §5.3). The numeric code is part of the telemetry and notice wire formats:
 * never renumber or reuse a value, only append.
 */
public enum ReasonCode {
    OK(0),
    INVALID_TOKEN(1),
    EXPIRED(2),
    WRONG_AUDIENCE(3),
    IDENTITY_MISMATCH(4),
    IP_MISMATCH(5),
    POLICY_DENY(6),
    QUARANTINED(7),
    NOT_READY(8),
    BACKEND_UNAVAILABLE(9),
    THROTTLED(10),
    DECOY_TOUCH(11),
    /** Workload unknown or disabled in the installed snapshot. */
    IDENTITY_DISABLED(12),
    /** Client certificate or lease signing key revoked. */
    REVOKED(13),
    /** Lease issued before the release watermark of a matching selector (spec §6.3). */
    LEASE_SUPERSEDED(14),
    /** Notice reasons: why a restriction was committed or removed. */
    OPERATOR_ACTION(15),
    RISK_SCORE(16),
    RESTRICTION_EXPIRED(17);

    private static final ReasonCode[] BY_CODE = new ReasonCode[18];

    static {
        for (ReasonCode r : values()) {
            BY_CODE[r.code] = r;
        }
    }

    private final int code;

    ReasonCode(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }

    public static ReasonCode fromCode(int code) throws CodecException {
        if (code < 0 || code >= BY_CODE.length || BY_CODE[code] == null) {
            throw new CodecException("unknown reason code");
        }
        return BY_CODE[code];
    }
}
