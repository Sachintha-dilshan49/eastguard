package eastguard.test;

import static eastguard.test.Assert.*;
import static eastguard.test.Fixtures.*;

import eastguard.common.CodecException;
import eastguard.common.Ed25519;
import eastguard.common.IpAddress;
import eastguard.common.Lease;
import eastguard.common.LeaseCodec;
import eastguard.common.SignedLease;
import eastguard.common.WireWriter;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public final class LeaseCodecTest {
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private static byte[] token(byte[] body, byte[] sig) {
        return (B64.encodeToString(body) + "." + B64.encodeToString(sig)).getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] validSig(byte[] body) {
        return Ed25519.sign(LEASE_KEYS.getPrivate(), body);
    }

    public void testBodyRoundTrip() throws Exception {
        Lease l = lease();
        assertEquals(l, LeaseCodec.decodeBody(LeaseCodec.encodeBody(l)));
        Lease v6 = new Lease(CLUSTER, KEY_ID, CLIENT, SERVICE, IpAddress.parse("2001:db8::10"), LEAF, 0, 1, JTI, 0);
        assertEquals(v6, LeaseCodec.decodeBody(LeaseCodec.encodeBody(v6)));
    }

    public void testBodyLayout() {
        byte[] b = LeaseCodec.encodeBody(lease());
        assertEquals("EGT1", new String(b, 0, 4, StandardCharsets.US_ASCII));
        assertEquals(CLUSTER.length(), b[4]);
        // 4 magic + 4 ids (1+len each) + ip (1+4) + 32 leaf + 8 iat + 8 exp + 16 jti + 8 revision
        int expected = 4 + (1 + CLUSTER.length()) + (1 + KEY_ID.length()) + (1 + CLIENT.length())
                + (1 + SERVICE.length()) + 5 + 32 + 8 + 8 + 16 + 8;
        assertEquals(expected, b.length);
    }

    public void testIssueParseVerify() throws Exception {
        byte[] token = LeaseCodec.issue(lease(), LEASE_KEYS.getPrivate());
        assertTrue(token.length <= LeaseCodec.MAX_TOKEN_LENGTH, "fits the preamble");
        SignedLease s = LeaseCodec.parse(token);
        assertEquals(lease(), s.lease());
        assertTrue(s.verify(LEASE_KEYS.getPublic()), "valid signature");
        assertFalse(s.verify(Ed25519.generate().getPublic()), "other key");
        // Deterministic key + deterministic Ed25519 => reproducible token.
        assertArrayEquals(token, LeaseCodec.issue(lease(), LEASE_KEYS.getPrivate()));
    }

    public void testTamperedBodyFailsVerification() throws Exception {
        byte[] body = LeaseCodec.encodeBody(lease());
        byte[] sig = validSig(body);
        body[body.length - 1] ^= 1; // issuedAtRevision 5 -> 4: still a valid body
        SignedLease s = LeaseCodec.parse(token(body, sig));
        assertFalse(s.verify(LEASE_KEYS.getPublic()), "signature covers the body");
    }

    public void testRejectsUnknownVersion() {
        byte[] body = LeaseCodec.encodeBody(lease());
        body[3] = '2'; // EGT2
        assertThrows(CodecException.class, () -> LeaseCodec.parse(token(body, validSig(body))));
    }

    public void testRejectsTruncatedAndTrailingBody() {
        byte[] body = LeaseCodec.encodeBody(lease());
        byte[] cut = Arrays.copyOf(body, body.length - 1);
        byte[] longer = Arrays.copyOf(body, body.length + 1);
        assertThrows(CodecException.class, () -> LeaseCodec.parse(token(cut, validSig(cut))));
        assertThrows(CodecException.class, () -> LeaseCodec.parse(token(longer, validSig(longer))));
        assertThrows(CodecException.class, () -> LeaseCodec.decodeBody(new byte[0]));
    }

    public void testRejectsBadSignatureLength() {
        byte[] body = LeaseCodec.encodeBody(lease());
        assertThrows(CodecException.class, () -> LeaseCodec.parse(token(body, new byte[63])));
        assertThrows(CodecException.class, () -> LeaseCodec.parse(token(body, new byte[65])));
    }

    public void testRejectsMalformedTokens() {
        String good = new String(LeaseCodec.issue(lease(), LEASE_KEYS.getPrivate()), StandardCharsets.US_ASCII);
        int dot = good.indexOf('.');
        String[] bad = {
            "", ".", good.substring(0, dot), good.substring(0, dot + 1), good.substring(dot),
            good + ".", good + "=", good.substring(0, dot) + "=" + good.substring(dot),
            good.replace('-', '+').replace('_', '/') + "+", // standard alphabet
            " " + good, good + "\n",
        };
        for (String t : bad) {
            assertThrows(CodecException.class, () -> LeaseCodec.parse(t));
        }
    }

    public void testRejectsNonCanonicalBase64() throws Exception {
        // 64-byte signature encodes to 86 chars; the last char carries 4 unused bits. Setting them must fail.
        String good = new String(LeaseCodec.issue(lease(), LEASE_KEYS.getPrivate()), StandardCharsets.US_ASCII);
        char last = good.charAt(good.length() - 1);
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        int v = alphabet.indexOf(last);
        String twisted = good.substring(0, good.length() - 1) + alphabet.charAt(v ^ 1);
        assertThrows(CodecException.class, () -> LeaseCodec.parse(twisted));
    }

    public void testRejectsOversizeToken() {
        byte[] big = new byte[LeaseCodec.MAX_TOKEN_LENGTH + 1];
        Arrays.fill(big, (byte) 'A');
        big[100] = '.';
        CodecException e = assertThrows(CodecException.class, () -> LeaseCodec.parse(big));
        assertEquals("token too long", e.getMessage());
    }

    public void testRejectsBadLifetimes() {
        for (long[] times : new long[][] {
                {NOW_MS, NOW_MS}, {NOW_MS, NOW_MS - 1}, {NOW_MS, NOW_MS + 60_001}, {0, Long.MIN_VALUE}}) {
            byte[] body = new WireWriter()
                    .ascii("EGT1").id(CLUSTER).id(KEY_ID).id(CLIENT).id(SERVICE).ip(CLIENT_IP)
                    .raw(LEAF.toArray()).i64(times[0]).i64(times[1]).raw(JTI.toArray()).i64(5)
                    .toByteArray();
            assertThrows(CodecException.class, () -> LeaseCodec.decodeBody(body));
        }
        assertThrows(IllegalArgumentException.class, () -> lease(Long.MAX_VALUE - 10, Long.MIN_VALUE + 10, 0));
    }

    public void testRejectsNegativeIatAndRevision() {
        byte[] negRev = new WireWriter()
                .ascii("EGT1").id(CLUSTER).id(KEY_ID).id(CLIENT).id(SERVICE).ip(CLIENT_IP)
                .raw(LEAF.toArray()).i64(NOW_MS).i64(NOW_MS + 1).raw(JTI.toArray()).i64(-1).toByteArray();
        assertThrows(CodecException.class, () -> LeaseCodec.decodeBody(negRev));
    }

    public void testToStringHidesClaims() {
        String s = lease().toString();
        assertFalse(s.contains(CLIENT), "subject not printed");
        assertFalse(s.contains(LEAF.hex()), "fingerprint not printed");
    }
}
