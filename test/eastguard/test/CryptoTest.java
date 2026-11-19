package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Bytes;
import eastguard.common.Ed25519;
import eastguard.common.Hmac;
import eastguard.common.Sha256;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HexFormat;

public final class CryptoTest {
    private static final HexFormat HEX = HexFormat.of();

    /** RFC 8032 §7.1, TEST 1 (empty message). */
    public void testEd25519KnownAnswer() {
        PrivateKey sk = Ed25519.privateKeyFromSeed(
                HEX.parseHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
        PublicKey pk = Ed25519.publicKeyFromRaw(
                HEX.parseHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
        byte[] expected = HEX.parseHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
                + "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        assertArrayEquals(expected, Ed25519.sign(sk, new byte[0]));
        assertTrue(Ed25519.verify(pk, new byte[0], expected), "KAT verifies");
    }

    public void testEd25519RoundTripAndTamper() {
        KeyPair kp = Ed25519.generate();
        byte[] msg = "lease body".getBytes(StandardCharsets.US_ASCII);
        byte[] sig = Ed25519.sign(kp.getPrivate(), msg);
        assertEquals(64, sig.length);
        assertTrue(Ed25519.verify(kp.getPublic(), msg, sig), "valid signature");

        byte[] badMsg = msg.clone();
        badMsg[0] ^= 1;
        assertFalse(Ed25519.verify(kp.getPublic(), badMsg, sig), "tampered message");
        byte[] badSig = sig.clone();
        badSig[10] ^= 1;
        assertFalse(Ed25519.verify(kp.getPublic(), msg, badSig), "tampered signature");
        assertFalse(Ed25519.verify(Ed25519.generate().getPublic(), msg, sig), "wrong key");
    }

    public void testEd25519VerifyNeverThrows() {
        PublicKey pk = Ed25519.generate().getPublic();
        byte[] msg = {1};
        assertFalse(Ed25519.verify(pk, msg, new byte[63]), "short signature");
        assertFalse(Ed25519.verify(pk, msg, new byte[65]), "long signature");
        assertFalse(Ed25519.verify(pk, msg, new byte[64]), "all-zero signature");
        byte[] ff = new byte[64];
        Arrays.fill(ff, (byte) 0xff);
        assertFalse(Ed25519.verify(pk, msg, ff), "non-canonical S");
        assertFalse(Ed25519.verify(null, msg, new byte[64]), "null key");
        assertFalse(Ed25519.verify(pk, msg, null), "null signature");
    }

    public void testEd25519RawKeyRoundTrip() {
        PublicKey pk = Ed25519.generate().getPublic();
        byte[] raw = Ed25519.rawPublicKey(pk);
        assertEquals(32, raw.length);
        assertArrayEquals(pk.getEncoded(), Ed25519.publicKeyFromRaw(raw).getEncoded());
        assertThrows(IllegalArgumentException.class, () -> Ed25519.publicKeyFromRaw(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> Ed25519.privateKeyFromSeed(new byte[33]));
    }

    /** RFC 4231 test case 6 (131-byte key). */
    public void testHmacKnownAnswer() {
        byte[] key = new byte[131];
        Arrays.fill(key, (byte) 0xaa);
        byte[] data = "Test Using Larger Than Block-Size Key - Hash Key First".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = HEX.parseHex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
        assertArrayEquals(expected, Hmac.sha256(key, data));
        assertTrue(Hmac.verify(key, data, 0, data.length, expected), "KAT verifies");
    }

    public void testHmacRejects() {
        byte[] key = new byte[32];
        byte[] data = {1, 2, 3, 4};
        byte[] mac = Hmac.sha256(key, data, 1, 2);
        assertTrue(Hmac.verify(key, data, 1, 2, mac), "range MAC verifies");
        assertFalse(Hmac.verify(key, data, 0, 3, mac), "different range");
        byte[] bad = mac.clone();
        bad[31] ^= 1;
        assertFalse(Hmac.verify(key, data, 1, 2, bad), "tampered MAC");
        assertFalse(Hmac.verify(key, data, 1, 2, Arrays.copyOf(mac, 31)), "short MAC");
        assertFalse(Hmac.verify(new byte[31], data, 1, 2, mac), "short key verify");
        byte[] otherKey = new byte[32];
        otherKey[0] = 1;
        assertFalse(Hmac.verify(otherKey, data, 1, 2, mac), "wrong key");
        assertThrows(IllegalArgumentException.class, () -> Hmac.sha256(new byte[31], data));
    }

    public void testSha256KnownAnswer() {
        Bytes d = Sha256.digest("abc".getBytes(StandardCharsets.US_ASCII));
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", d.hex());
    }
}
