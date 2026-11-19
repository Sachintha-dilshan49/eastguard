package eastguard.common;

import java.util.Objects;

/**
 * The authenticated peer as established by the transport, never by anything the peer sent.
 *
 * @param identity   workload ID mapped from the verified client certificate's URI SAN
 * @param leafSha256 SHA-256 of the verified leaf certificate (DER)
 * @param ip         address read from the accepted socket (IPv4-mapped IPv6 already normalized)
 */
public record Peer(String identity, Bytes leafSha256, IpAddress ip) {
    public Peer {
        Ids.require(identity, "identity");
        Objects.requireNonNull(leafSha256, "leafSha256").requireLength(Sha256.LENGTH, "leafSha256");
        Objects.requireNonNull(ip, "ip");
    }
}
