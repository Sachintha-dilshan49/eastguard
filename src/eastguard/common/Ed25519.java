package eastguard.common;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Ed25519 signing for leases and control notices. The algorithm is fixed by the wire format; there is no
 * negotiation (spec §5.2). Raw keys are 32 bytes; signatures are 64 bytes.
 */
public final class Ed25519 {
    public static final String ALGORITHM = "Ed25519";
    public static final int SIGNATURE_LENGTH = 64;
    public static final int KEY_LENGTH = 32;

    /** DER prefixes that wrap a raw 32-byte key as X.509 SubjectPublicKeyInfo / PKCS#8 (RFC 8410). */
    private static final byte[] X509_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");
    private static final byte[] PKCS8_PREFIX = HexFormat.of().parseHex("302e020100300506032b657004220420");

    private Ed25519() {
    }

    public static KeyPair generate() {
        try {
            return KeyPairGenerator.getInstance(ALGORITHM).generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 unavailable", e);
        }
    }

    public static byte[] sign(PrivateKey key, byte[] message) {
        try {
            Signature s = Signature.getInstance(ALGORITHM);
            s.initSign(key);
            s.update(message);
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 signing failed", e);
        }
    }

    /** Returns false for any malformed key, signature length, or verification failure; never throws. */
    public static boolean verify(PublicKey key, byte[] message, byte[] signature) {
        if (key == null || message == null || signature == null || signature.length != SIGNATURE_LENGTH) {
            return false;
        }
        try {
            Signature s = Signature.getInstance(ALGORITHM);
            s.initVerify(key);
            s.update(message);
            return s.verify(signature);
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    public static PublicKey publicKeyFromRaw(byte[] raw) {
        if (raw == null || raw.length != KEY_LENGTH) {
            throw new IllegalArgumentException("Ed25519 public key must be 32 bytes");
        }
        try {
            return KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(concat(X509_PREFIX, raw)));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("invalid Ed25519 public key", e);
        }
    }

    /** Builds a private key from its 32-byte seed (used for known-answer tests and file-based demo keys). */
    public static PrivateKey privateKeyFromSeed(byte[] seed) {
        if (seed == null || seed.length != KEY_LENGTH) {
            throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
        }
        try {
            return KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(concat(PKCS8_PREFIX, seed)));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("invalid Ed25519 seed", e);
        }
    }

    /** Raw 32-byte form of an Ed25519 public key, for config files and fingerprints. */
    public static byte[] rawPublicKey(PublicKey key) {
        byte[] enc = key.getEncoded();
        if (!ALGORITHM.equals(key.getAlgorithm()) && !"EdDSA".equals(key.getAlgorithm())
                || enc == null || enc.length != X509_PREFIX.length + KEY_LENGTH
                || !Arrays.equals(enc, 0, X509_PREFIX.length, X509_PREFIX, 0, X509_PREFIX.length)) {
            throw new IllegalArgumentException("not an Ed25519 public key");
        }
        return Arrays.copyOfRange(enc, X509_PREFIX.length, enc.length);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
