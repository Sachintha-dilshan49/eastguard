package eastguard.common;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** SHA-256 digests, e.g. the leaf-certificate fingerprint bound into a lease (spec §5.2). */
public final class Sha256 {
    public static final int LENGTH = 32;

    private Sha256() {
    }

    public static Bytes digest(byte[] data) {
        try {
            return Bytes.copyOf(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
