package eastguard.common;

/** Telemetry verdict (spec §5.3). Wire codes are stable. */
public enum Verdict {
    ALLOW(0),
    DENY(1),
    DECOY(2);

    private final int code;

    Verdict(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }

    public static Verdict fromCode(int code) throws CodecException {
        for (Verdict v : values()) {
            if (v.code == code) {
                return v;
            }
        }
        throw new CodecException("unknown verdict");
    }
}
