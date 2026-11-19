package eastguard.test;

import eastguard.common.Bytes;
import eastguard.common.Ed25519;
import eastguard.common.IpAddress;
import eastguard.common.Lease;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;

/** Shared deterministic test values. Not a test class; not registered in {@link AllTests}. */
final class Fixtures {
    static final Instant NOW = Instant.parse("2026-11-19T10:00:00Z");
    static final long NOW_MS = NOW.toEpochMilli();
    static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    static final String CLUSTER = "eg-demo";
    static final String KEY_ID = "lease-k1";
    static final String CLIENT = "web-01";
    static final String SERVICE = "app-02";
    static final IpAddress CLIENT_IP = IpAddress.parse("10.0.1.10");
    static final Bytes LEAF = Bytes.fromHex("11".repeat(32));
    static final Bytes JTI = Bytes.fromHex("0123456789abcdef0123456789abcdef");

    /** Deterministic signing key (RFC 8032 TEST 1 seed) so encoded tokens are reproducible. */
    static final KeyPair LEASE_KEYS = new KeyPair(
            Ed25519.publicKeyFromRaw(HexFormat.of().parseHex(
                    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")),
            Ed25519.privateKeyFromSeed(HexFormat.of().parseHex(
                    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")));

    private Fixtures() {
    }

    /** A 60-second lease issued at NOW for web-01 -> app-02 at revision 5. */
    static Lease lease() {
        return lease(NOW_MS, NOW_MS + 60_000, 5);
    }

    static Lease lease(long iat, long exp, long revision) {
        return new Lease(CLUSTER, KEY_ID, CLIENT, SERVICE, CLIENT_IP, LEAF, iat, exp, JTI, revision);
    }

    static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }
}
