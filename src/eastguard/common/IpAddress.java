package eastguard.common;

import java.io.Serial;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

/**
 * Canonical IP address as raw bytes: 4 bytes for IPv4, 16 for IPv6. IPv4-mapped IPv6 addresses
 * ({@code ::ffff:a.b.c.d}) are always normalized to their 4-byte form so comparisons are consistent (spec §4.1).
 * Never performs DNS lookups.
 */
public final class IpAddress implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private final byte[] addr;

    private IpAddress(byte[] owned) {
        this.addr = owned;
    }

    /** Accepts 4 or 16 bytes; normalizes IPv4-mapped IPv6 to IPv4. */
    public static IpAddress of(byte[] raw) {
        if (raw == null || (raw.length != 4 && raw.length != 16)) {
            throw new IllegalArgumentException("ip must be 4 or 16 bytes");
        }
        if (isIpv4Mapped(raw)) {
            return new IpAddress(Arrays.copyOfRange(raw, 12, 16));
        }
        return new IpAddress(raw.clone());
    }

    public static IpAddress of(InetAddress address) {
        return of(address.getAddress());
    }

    /**
     * Parses an IPv4 dotted quad (strict: exactly four decimal octets) or an IPv6 literal without a scope ID.
     * Rejects hostnames instead of resolving them.
     */
    public static IpAddress parse(String literal) {
        if (literal == null || literal.isEmpty() || literal.length() > 45) {
            throw new IllegalArgumentException("invalid ip literal");
        }
        if (literal.indexOf(':') < 0) {
            return new IpAddress(parseIpv4(literal));
        }
        for (int i = 0; i < literal.length(); i++) {
            char c = literal.charAt(i);
            boolean ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':' || c == '.';
            if (!ok) {
                throw new IllegalArgumentException("invalid ip literal");
            }
        }
        try {
            // A string containing ':' and only hex/':'/'.' is parsed as an IPv6 literal; no lookup happens.
            return of(InetAddress.getByName(literal));
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("invalid ip literal");
        }
    }

    private static byte[] parseIpv4(String s) {
        String[] parts = s.split("\\.", -1);
        if (parts.length != 4) {
            throw new IllegalArgumentException("invalid ip literal");
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            String p = parts[i];
            if (p.isEmpty() || p.length() > 3 || (p.length() > 1 && p.charAt(0) == '0')) {
                throw new IllegalArgumentException("invalid ip literal");
            }
            int v = 0;
            for (int j = 0; j < p.length(); j++) {
                char c = p.charAt(j);
                if (c < '0' || c > '9') {
                    throw new IllegalArgumentException("invalid ip literal");
                }
                v = v * 10 + (c - '0');
            }
            if (v > 255) {
                throw new IllegalArgumentException("invalid ip literal");
            }
            out[i] = (byte) v;
        }
        return out;
    }

    public static boolean isIpv4Mapped(byte[] raw) {
        if (raw.length != 16) {
            return false;
        }
        for (int i = 0; i < 10; i++) {
            if (raw[i] != 0) {
                return false;
            }
        }
        return raw[10] == (byte) 0xff && raw[11] == (byte) 0xff;
    }

    public boolean isIpv4() {
        return addr.length == 4;
    }

    public int length() {
        return addr.length;
    }

    byte byteAt(int i) {
        return addr[i];
    }

    public byte[] toBytes() {
        return addr.clone();
    }

    public InetAddress toInetAddress() {
        try {
            return InetAddress.getByAddress(addr);
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e); // unreachable: length is always 4 or 16
        }
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof IpAddress other && Arrays.equals(addr, other.addr);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(addr);
    }

    @Override
    public String toString() {
        return toInetAddress().getHostAddress();
    }

    @Serial
    private Object readResolve() {
        return of(addr);
    }
}
