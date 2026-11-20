package eastguard.common;

import java.util.Objects;

/**
 * Restriction target: exactly one of a workload identity or an IP address (spec §3.1, §5.4). IDENTITY and IP
 * selectors are independent; a match on any active selector denies.
 */
public record Selector(SelectorType type, String identity, IpAddress ip) implements java.io.Serializable {
    public Selector {
        Objects.requireNonNull(type, "type");
        switch (type) {
            case IDENTITY -> {
                Ids.require(identity, "identity");
                if (ip != null) {
                    throw new IllegalArgumentException("identity selector must not carry an ip");
                }
            }
            case IP -> {
                Objects.requireNonNull(ip, "ip");
                if (identity != null) {
                    throw new IllegalArgumentException("ip selector must not carry an identity");
                }
            }
        }
    }

    public static Selector identity(String identity) {
        return new Selector(SelectorType.IDENTITY, identity, null);
    }

    public static Selector ip(IpAddress ip) {
        return new Selector(SelectorType.IP, null, ip);
    }

    /** True if this selector covers a peer with the given verified identity (may be null) and IP. */
    public boolean matches(String peerIdentity, IpAddress peerIp) {
        return switch (type) {
            case IDENTITY -> identity.equals(peerIdentity);
            case IP -> ip.equals(peerIp);
        };
    }

    @Override
    public String toString() {
        return type == SelectorType.IDENTITY ? "identity:" + identity : "ip:" + ip;
    }
}
