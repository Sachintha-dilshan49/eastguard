package eastguard.common;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Base64;

/**
 * Lease wire format (spec §5.2):
 *
 * <pre>
 * token = base64url(body) "." base64url(signature)        // no padding, ASCII
 * body  = "EGT1" | cluster:id | keyId:id | sub:id | aud:id | srcIp:ip | leafSha256:32
 *       | iat:i64 | exp:i64 | jti:16 | issuedAtRevision:i64
 * </pre>
 *
 * The algorithm is fixed (Ed25519); there is no header and no algorithm negotiation.
 */
public final class LeaseCodec {
    public static final String MAGIC = "EGT1";
    public static final int MAX_TOKEN_LENGTH = 2048;

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    private LeaseCodec() {
    }

    public static byte[] encodeBody(Lease l) {
        return new WireWriter(384)
                .ascii(MAGIC)
                .id(l.cluster()).id(l.keyId()).id(l.subject()).id(l.audience())
                .ip(l.sourceIp())
                .fixed(l.leafSha256(), Sha256.LENGTH, "leafSha256")
                .nonNegative(l.issuedAtMs(), "iat")
                .i64(l.expiresAtMs())
                .fixed(l.jti(), Lease.JTI_LENGTH, "jti")
                .nonNegative(l.issuedAtRevision(), "issuedAtRevision")
                .toByteArray();
    }

    public static Lease decodeBody(byte[] body) throws CodecException {
        WireReader r = new WireReader(body);
        r.magic(MAGIC);
        String cluster = r.id();
        String keyId = r.id();
        String sub = r.id();
        String aud = r.id();
        IpAddress srcIp = r.ip();
        Bytes leaf = r.fixed(Sha256.LENGTH);
        long iat = r.nonNegative("iat");
        long exp = r.i64();
        Bytes jti = r.fixed(Lease.JTI_LENGTH);
        long rev = r.nonNegative("issuedAtRevision");
        r.end();
        try {
            return new Lease(cluster, keyId, sub, aud, srcIp, leaf, iat, exp, jti, rev);
        } catch (IllegalArgumentException e) {
            throw new CodecException("invalid lease: " + e.getMessage());
        }
    }

    /** Signs {@code lease} and returns the ASCII token bytes. */
    public static byte[] issue(Lease lease, PrivateKey signingKey) {
        byte[] body = encodeBody(lease);
        byte[] sig = Ed25519.sign(signingKey, body);
        byte[] b = B64.encode(body);
        byte[] s = B64.encode(sig);
        byte[] token = Arrays.copyOf(b, b.length + 1 + s.length);
        token[b.length] = '.';
        System.arraycopy(s, 0, token, b.length + 1, s.length);
        if (token.length > MAX_TOKEN_LENGTH) {
            throw new IllegalStateException("token exceeds 2048 bytes"); // unreachable with id <= 64
        }
        return token;
    }

    /**
     * Structural parse of untrusted token bytes. Rejects oversize input, anything but exactly one '.', padding,
     * non-canonical or non-alphabet base64url, a signature that is not 64 bytes, and any body defect. Does
     * <em>not</em> verify the signature.
     */
    public static SignedLease parse(byte[] token) throws CodecException {
        if (token == null || token.length == 0) {
            throw new CodecException("empty token");
        }
        if (token.length > MAX_TOKEN_LENGTH) {
            throw new CodecException("token too long");
        }
        int dot = -1;
        for (int i = 0; i < token.length; i++) {
            if (token[i] == '.') {
                if (dot >= 0) {
                    throw new CodecException("malformed token");
                }
                dot = i;
            }
        }
        if (dot <= 0 || dot == token.length - 1) {
            throw new CodecException("malformed token");
        }
        byte[] body = decodeCanonical(Arrays.copyOfRange(token, 0, dot));
        byte[] sig = decodeCanonical(Arrays.copyOfRange(token, dot + 1, token.length));
        if (sig.length != Ed25519.SIGNATURE_LENGTH) {
            throw new CodecException("bad signature length");
        }
        return new SignedLease(decodeBody(body), Bytes.copyOf(body), Bytes.copyOf(sig));
    }

    public static SignedLease parse(String token) throws CodecException {
        if (token == null) {
            throw new CodecException("empty token");
        }
        return parse(token.getBytes(StandardCharsets.US_ASCII));
    }

    /** Decodes unpadded base64url and requires re-encoding to reproduce the input exactly. */
    private static byte[] decodeCanonical(byte[] part) throws CodecException {
        for (byte c : part) {
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_';
            if (!ok) {
                throw new CodecException("invalid base64url");
            }
        }
        byte[] out;
        try {
            out = B64D.decode(part);
        } catch (IllegalArgumentException e) {
            throw new CodecException("invalid base64url");
        }
        if (!Arrays.equals(B64.encode(out), part)) {
            throw new CodecException("non-canonical base64url");
        }
        return out;
    }
}
