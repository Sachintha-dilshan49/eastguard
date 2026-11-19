package eastguard.common;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HMAC-SHA256 for telemetry datagrams (spec §5.3). Keys are at least 32 bytes, one per producer. MAC
 * comparison is constant-time via {@link MessageDigest#isEqual}.
 */
public final class Hmac {
    public static final String ALGORITHM = "HmacSHA256";
    public static final int MAC_LENGTH = 32;
    public static final int MIN_KEY_LENGTH = 32;

    private Hmac() {
    }

    public static byte[] sha256(byte[] key, byte[] data) {
        return sha256(key, data, 0, data.length);
    }

    public static byte[] sha256(byte[] key, byte[] data, int offset, int length) {
        if (key == null || key.length < MIN_KEY_LENGTH) {
            throw new IllegalArgumentException("HMAC key must be at least 32 bytes");
        }
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(key, ALGORITHM));
            mac.update(data, offset, length);
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC unavailable", e);
        }
    }

    /** Constant-time check of {@code mac} over {@code data[offset, offset+length)}; false on a short key. */
    public static boolean verify(byte[] key, byte[] data, int offset, int length, byte[] mac) {
        if (key == null || key.length < MIN_KEY_LENGTH || mac == null || mac.length != MAC_LENGTH) {
            return false;
        }
        byte[] expected = sha256(key, data, offset, length);
        boolean ok = MessageDigest.isEqual(expected, mac);
        Arrays.fill(expected, (byte) 0);
        return ok;
    }
}
