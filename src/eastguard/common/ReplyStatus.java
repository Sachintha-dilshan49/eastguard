package eastguard.common;

/**
 * Status byte of the issuer and gateway replies (spec §5.1). Detailed reasons stay in internal telemetry; the
 * peer only learns this coarse status.
 */
public enum ReplyStatus {
    SUCCESS(0),
    DENY(1),
    QUARANTINED(2),
    UNAVAILABLE(3);

    private final int code;

    ReplyStatus(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }

    public static ReplyStatus fromCode(int code) throws CodecException {
        for (ReplyStatus s : values()) {
            if (s.code == code) {
                return s;
            }
        }
        throw new CodecException("unknown reply status");
    }

    /** Coarse status for a decision reason. Temporary conditions map to UNAVAILABLE; everything else denies. */
    public static ReplyStatus forReason(ReasonCode reason) {
        return switch (reason) {
            case OK -> SUCCESS;
            case QUARANTINED -> QUARANTINED;
            case NOT_READY, BACKEND_UNAVAILABLE, THROTTLED -> UNAVAILABLE;
            default -> DENY;
        };
    }
}
