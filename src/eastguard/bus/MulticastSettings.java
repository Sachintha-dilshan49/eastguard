package eastguard.bus;

import eastguard.common.Config;
import eastguard.common.IpAddress;
import java.io.IOException;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Objects;

/**
 * Multicast channel for control notices (spec §9.1):
 *
 * <pre>
 * multicast.group=239.20.20.20     administratively scoped group (must be a multicast address)
 * multicast.port=4446
 * multicast.interface=127.0.0.1    REQUIRED: an address of the interface, or its name (e.g. eth0, loopback_0)
 * multicast.ttl=1                  sender only; TTL is not a security boundary
 * </pre>
 *
 * Notices are off when {@code multicast.group} is absent; enforcement points then converge by polling only.
 */
public record MulticastSettings(IpAddress group, int port, String networkInterface, int ttl) {
    public static final String DEFAULT_GROUP = "239.20.20.20";
    public static final int DEFAULT_PORT = 4446;

    public MulticastSettings {
        Objects.requireNonNull(group, "group");
        if (!group.toInetAddress().isMulticastAddress()) {
            throw new IllegalArgumentException("multicast.group " + group + " is not a multicast address");
        }
        if (port < 1 || port > 65_535 || ttl < 0 || ttl > 255) {
            throw new IllegalArgumentException("multicast port or ttl out of range");
        }
        if (networkInterface == null || networkInterface.isBlank()) {
            throw new IllegalArgumentException("multicast.interface must name the interface explicitly");
        }
    }

    /** {@code null} when {@code multicast.group} is not configured. */
    public static MulticastSettings from(Config c) {
        if (c.optional("multicast.group") == null) {
            return null;
        }
        IpAddress group;
        try {
            group = IpAddress.parse(c.string("multicast.group"));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("config " + c.source() + ": multicast.group must be a numeric address");
        }
        try {
            return new MulticastSettings(group, c.intIn("multicast.port", DEFAULT_PORT, 1, 65_535),
                    c.string("multicast.interface"), c.intIn("multicast.ttl", 1, 0, 255));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("config " + c.source() + ": " + e.getMessage());
        }
    }

    /** The configured interface, by address or by name. Fails if it does not exist, is down, or lacks multicast. */
    public NetworkInterface resolveInterface() throws IOException {
        NetworkInterface nif = null;
        try {
            nif = NetworkInterface.getByInetAddress(IpAddress.parse(networkInterface).toInetAddress());
        } catch (IllegalArgumentException notALiteral) {
            nif = NetworkInterface.getByName(networkInterface);
        }
        if (nif == null) {
            throw new SocketException("multicast.interface " + networkInterface + " not found");
        }
        if (!nif.isUp() || !nif.supportsMulticast()) {
            throw new SocketException("interface " + nif.getName() + " is down or does not support multicast");
        }
        return nif;
    }
}
