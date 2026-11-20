package eastguard.control;

import eastguard.common.CodecException;

/**
 * Control-plane roles (spec §7.1). Each API credential carries exactly one. {@link #SYSTEM} marks transitions the
 * control plane commits by itself (quarantine expiry) and can never be assigned to a credential. Codes are
 * stored in the journal: never renumber.
 */
public enum Role {
    VIEWER(1),
    OPERATOR(2),
    ADMIN(3),
    GATEWAY(4),
    ISSUER(5),
    DETECTOR(6),
    SYSTEM(7);

    private final int code;

    Role(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }

    public static Role fromCode(int code) throws CodecException {
        for (Role r : values()) {
            if (r.code == code) {
                return r;
            }
        }
        throw new CodecException("unknown role");
    }
}
