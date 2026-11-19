package eastguard.common;

/** Restriction selector type (spec §3.1, §5.4). Wire codes are stable. */
public enum SelectorType {
    IDENTITY(1),
    IP(2);

    private final int code;

    SelectorType(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }

    public static SelectorType fromCode(int code) throws CodecException {
        for (SelectorType t : values()) {
            if (t.code == code) {
                return t;
            }
        }
        throw new CodecException("unknown selector type");
    }
}
