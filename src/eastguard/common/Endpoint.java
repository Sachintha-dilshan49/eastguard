package eastguard.common;

import java.net.InetSocketAddress;
import java.util.Objects;

/** Numeric TCP endpoint. Never a hostname, so using it cannot trigger DNS lookups. */
public record Endpoint(IpAddress ip, int port) {
    public Endpoint {
        Objects.requireNonNull(ip, "ip");
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("port out of range");
        }
    }

    /** Parses {@code 10.0.0.1:8443} or {@code [2001:db8::1]:8443}. */
    public static Endpoint parse(String text) {
        if (text == null) {
            throw new IllegalArgumentException("invalid endpoint");
        }
        String host;
        String port;
        if (text.startsWith("[")) {
            int close = text.indexOf("]:");
            if (close < 0) {
                throw new IllegalArgumentException("invalid endpoint");
            }
            host = text.substring(1, close);
            port = text.substring(close + 2);
        } else {
            int colon = text.lastIndexOf(':');
            if (colon < 0 || text.indexOf(':') != colon) {
                throw new IllegalArgumentException("invalid endpoint");
            }
            host = text.substring(0, colon);
            port = text.substring(colon + 1);
        }
        if (port.isEmpty() || port.length() > 5 || !port.chars().allMatch(c -> c >= '0' && c <= '9')) {
            throw new IllegalArgumentException("invalid port");
        }
        return new Endpoint(IpAddress.parse(host), Integer.parseInt(port));
    }

    public InetSocketAddress toSocketAddress() {
        return new InetSocketAddress(ip.toInetAddress(), port);
    }

    @Override
    public String toString() {
        return ip.isIpv4() ? ip + ":" + port : "[" + ip + "]:" + port;
    }
}
