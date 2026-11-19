package eastguard.common;

import java.io.Serial;
import java.io.Serializable;

/**
 * IPv4 or IPv6 prefix compared on numeric address bytes (spec §8). Parsing is strict: the prefix length must
 * fit the family and host bits must be zero, so {@code 10.0.0.1/8} is rejected rather than silently widened.
 *
 * <p>An IPv4 prefix never matches an IPv6 address and vice versa. IPv4-mapped IPv6 addresses are already
 * normalized to IPv4 by {@link IpAddress}, so they match IPv4 prefixes.
 */
public final class Cidr implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private final IpAddress network;
    private final int prefixLength;

    private Cidr(IpAddress network, int prefixLength) {
        this.network = network;
        this.prefixLength = prefixLength;
    }

    public static Cidr of(IpAddress network, int prefixLength) {
        int maxBits = network.length() * 8;
        if (prefixLength < 0 || prefixLength > maxBits) {
            throw new IllegalArgumentException("prefix length out of range");
        }
        for (int bit = prefixLength; bit < maxBits; bit++) {
            if (bitAt(network, bit)) {
                throw new IllegalArgumentException("host bits set in network address");
            }
        }
        return new Cidr(network, prefixLength);
    }

    /** Parses {@code a.b.c.d/n} or {@code v6literal/n}. A bare address is a full-width prefix. */
    public static Cidr parse(String text) {
        if (text == null) {
            throw new IllegalArgumentException("invalid cidr");
        }
        int slash = text.indexOf('/');
        if (slash < 0) {
            IpAddress ip = IpAddress.parse(text);
            return new Cidr(ip, ip.length() * 8);
        }
        String bits = text.substring(slash + 1);
        if (bits.isEmpty() || bits.length() > 3 || (bits.length() > 1 && bits.charAt(0) == '0')) {
            throw new IllegalArgumentException("invalid prefix length");
        }
        for (int i = 0; i < bits.length(); i++) {
            if (bits.charAt(i) < '0' || bits.charAt(i) > '9') {
                throw new IllegalArgumentException("invalid prefix length");
            }
        }
        return of(IpAddress.parse(text.substring(0, slash)), Integer.parseInt(bits));
    }

    public boolean contains(IpAddress ip) {
        if (ip.length() != network.length()) {
            return false;
        }
        int fullBytes = prefixLength / 8;
        for (int i = 0; i < fullBytes; i++) {
            if (ip.byteAt(i) != network.byteAt(i)) {
                return false;
            }
        }
        int rest = prefixLength % 8;
        if (rest == 0) {
            return true;
        }
        int mask = (0xFF << (8 - rest)) & 0xFF;
        return (ip.byteAt(fullBytes) & mask) == (network.byteAt(fullBytes) & mask);
    }

    private static boolean bitAt(IpAddress ip, int bit) {
        return (ip.byteAt(bit / 8) & (0x80 >>> (bit % 8))) != 0;
    }

    public IpAddress network() {
        return network;
    }

    public int prefixLength() {
        return prefixLength;
    }

    public boolean isIpv4() {
        return network.isIpv4();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Cidr other && prefixLength == other.prefixLength && network.equals(other.network);
    }

    @Override
    public int hashCode() {
        return network.hashCode() * 31 + prefixLength;
    }

    @Override
    public String toString() {
        return network + "/" + prefixLength;
    }

    @Serial
    private Object readResolve() {
        return of(network, prefixLength);
    }
}
