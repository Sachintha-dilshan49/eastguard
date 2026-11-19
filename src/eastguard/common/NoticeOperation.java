package eastguard.common;

/** Multicast notice operation (spec §5.4). Wire codes are stable. */
public enum NoticeOperation {
    QUARANTINE(1),
    RELEASE(2);

    private final int code;

    NoticeOperation(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }

    public static NoticeOperation fromCode(int code) throws CodecException {
        for (NoticeOperation o : values()) {
            if (o.code == code) {
                return o;
            }
        }
        throw new CodecException("unknown notice operation");
    }
}
