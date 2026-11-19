package eastguard.common;

import java.util.Objects;
import java.util.Set;

/**
 * Registered workload (spec §3.1).
 *
 * @param id                   stable identity, mapped from the approved URI SAN
 * @param enabled              a disabled workload gets no leases and no admissions
 * @param revokedCertificates  credential restrictions: SHA-256 fingerprints of revoked leaf certificates
 * @param ipZone               optional managed IP zone; when set, the peer IP must fall inside it
 */
public record Workload(String id, boolean enabled, Set<Bytes> revokedCertificates, Cidr ipZone) {
    public Workload {
        Ids.require(id, "workload id");
        revokedCertificates = Set.copyOf(Objects.requireNonNull(revokedCertificates, "revokedCertificates"));
        for (Bytes fp : revokedCertificates) {
            fp.requireLength(Sha256.LENGTH, "certificate fingerprint");
        }
    }

    public static Workload enabled(String id) {
        return new Workload(id, true, Set.of(), null);
    }

    public boolean isCertificateRevoked(Bytes leafSha256) {
        return revokedCertificates.contains(leafSha256);
    }

    public boolean allowsIp(IpAddress ip) {
        return ipZone == null || ipZone.contains(ip);
    }
}
