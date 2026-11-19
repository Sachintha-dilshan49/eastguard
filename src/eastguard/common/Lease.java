package eastguard.common;

import java.util.Objects;

/**
 * Lease body claims (spec §5.2). Times are Unix milliseconds exactly as on the wire. The constructor enforces
 * {@code 0 < exp - iat <= 60 s} with overflow-checked arithmetic; time-of-use checks belong to
 * {@link PolicyEvaluator}.
 *
 * @param subject  workload identity the lease is bound to ({@code sub})
 * @param audience target service ID ({@code aud})
 * @param jti      16 random bytes; a correlation ID, not a one-time nonce
 */
public record Lease(String cluster, String keyId, String subject, String audience, IpAddress sourceIp,
        Bytes leafSha256, long issuedAtMs, long expiresAtMs, Bytes jti, long issuedAtRevision) {

    public static final long MAX_LIFETIME_MS = 60_000;
    public static final int JTI_LENGTH = 16;

    public Lease {
        Ids.require(cluster, "cluster");
        Ids.require(keyId, "keyId");
        Ids.require(subject, "sub");
        Ids.require(audience, "aud");
        Objects.requireNonNull(sourceIp, "srcIp");
        Objects.requireNonNull(leafSha256, "leafSha256").requireLength(Sha256.LENGTH, "leafSha256");
        Objects.requireNonNull(jti, "jti").requireLength(JTI_LENGTH, "jti");
        if (issuedAtMs < 0 || issuedAtRevision < 0) {
            throw new IllegalArgumentException("iat and issuedAtRevision must be nonnegative");
        }
        long lifetime;
        try {
            lifetime = Math.subtractExact(expiresAtMs, issuedAtMs);
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException("lease lifetime overflow");
        }
        if (lifetime <= 0 || lifetime > MAX_LIFETIME_MS) {
            throw new IllegalArgumentException("lease lifetime must be in (0, 60s]");
        }
    }

    /** No claim values: a lease must never end up in a log line. */
    @Override
    public String toString() {
        return "Lease[keyId=" + keyId + ", aud=" + audience + "]";
    }
}
