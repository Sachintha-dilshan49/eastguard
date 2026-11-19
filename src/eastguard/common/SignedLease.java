package eastguard.common;

import java.security.PublicKey;
import java.util.Objects;

/**
 * A structurally valid token whose signature has <em>not</em> been checked yet. Callers must look up the key by
 * {@code lease().keyId()} in their trusted key set and call {@link #verify(PublicKey)} before trusting any claim.
 *
 * @param body      the exact signed bytes, so verification never depends on re-encoding
 * @param signature 64-byte Ed25519 signature
 */
public record SignedLease(Lease lease, Bytes body, Bytes signature) {
    public SignedLease {
        Objects.requireNonNull(lease, "lease");
        Objects.requireNonNull(body, "body");
        Objects.requireNonNull(signature, "signature").requireLength(Ed25519.SIGNATURE_LENGTH, "signature");
    }

    public boolean verify(PublicKey key) {
        return Ed25519.verify(key, body.toArray(), signature.toArray());
    }

    @Override
    public String toString() {
        return "SignedLease[" + lease + "]";
    }
}
