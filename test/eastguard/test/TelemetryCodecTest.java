package eastguard.test;

import static eastguard.test.Assert.*;
import static eastguard.test.Fixtures.*;

import eastguard.common.Bytes;
import eastguard.common.CodecException;
import eastguard.common.Hmac;
import eastguard.common.IpAddress;
import eastguard.common.ReasonCode;
import eastguard.common.Telemetry;
import eastguard.common.TelemetryCodec;
import eastguard.common.Verdict;
import java.util.Arrays;
import java.util.function.BiFunction;

public final class TelemetryCodecTest {
    private static final byte[] KEY = Bytes.fromHex("42".repeat(32)).toArray();
    private static final BiFunction<String, String, byte[]> KEYS =
            (producer, keyId) -> producer.equals("gw-1") && keyId.equals("mac-k1") ? KEY : null;
    private static final Bytes BOOT = Bytes.fromHex("00112233445566778899aabbccddeeff");

    private static Telemetry event(Verdict v, ReasonCode r, String identity, boolean outside) {
        return new Telemetry(CLUSTER, "gw-1", "mac-k1", BOOT, 7, NOW_MS, 5, identity, CLIENT_IP, SERVICE,
                IpAddress.parse("10.0.2.20"), 8443, v, r, outside);
    }

    private static Telemetry allow() {
        return event(Verdict.ALLOW, ReasonCode.OK, CLIENT, false);
    }

    /** Re-MACs a mutated body so the test reaches the check after the MAC. */
    private static byte[] remac(byte[] datagram) {
        int body = datagram.length - 32;
        byte[] mac = Hmac.sha256(KEY, datagram, 0, body);
        byte[] out = datagram.clone();
        System.arraycopy(mac, 0, out, body, 32);
        return out;
    }

    public void testRoundTrip() throws Exception {
        for (Telemetry t : new Telemetry[] {
                allow(),
                event(Verdict.ALLOW, ReasonCode.OK, CLIENT, true),           // pilot observation
                event(Verdict.DENY, ReasonCode.INVALID_TOKEN, null, false),  // no attributed identity
                event(Verdict.DECOY, ReasonCode.DECOY_TOUCH, CLIENT, false),
                new Telemetry(CLUSTER, "gw-1", "mac-k1", BOOT, 0, 0, 0, null, IpAddress.parse("2001:db8::5"),
                        SERVICE, IpAddress.parse("2001:db8::6"), 65535, Verdict.DENY, ReasonCode.THROTTLED, false)}) {
            assertEquals(t, TelemetryCodec.decode(TelemetryCodec.encode(t, KEY), CLUSTER, KEYS));
        }
    }

    public void testLayout() {
        byte[] d = TelemetryCodec.encode(event(Verdict.ALLOW, ReasonCode.OK, CLIENT, true), KEY);
        assertArrayEquals(new byte[] {'E', 'G', 'F', '1'}, Arrays.copyOf(d, 4));
        int flagsAt = d.length - 33;
        assertEquals(1, d[flagsAt]);              // flags
        assertEquals(0, d[flagsAt - 1]);          // reason OK
        assertEquals(0, d[flagsAt - 2]);          // verdict ALLOW
        assertEquals(8443, ((d[flagsAt - 4] & 0xFF) << 8) | (d[flagsAt - 3] & 0xFF));
    }

    public void testRejectsBadMacWrongKeyUnknownProducer() {
        byte[] d = TelemetryCodec.encode(allow(), KEY);
        byte[] flipped = d.clone();
        flipped[d.length - 1] ^= 1;
        assertThrows(CodecException.class, () -> TelemetryCodec.decode(flipped, CLUSTER, KEYS));
        byte[] body = d.clone();
        body[30] ^= 1; // inside bootId (offset 24..39): still parses, so only the MAC can catch it
        CodecException e = assertThrows(CodecException.class, () -> TelemetryCodec.decode(body, CLUSTER, KEYS));
        assertEquals("bad mac", e.getMessage());
        byte[] otherKey = Bytes.fromHex("43".repeat(32)).toArray();
        assertThrows(CodecException.class,
                () -> TelemetryCodec.decode(d, CLUSTER, (p, k) -> otherKey));
        assertThrows(CodecException.class, () -> TelemetryCodec.decode(d, CLUSTER, (p, k) -> null));
    }

    public void testRejectsWrongCluster() {
        byte[] d = TelemetryCodec.encode(allow(), KEY);
        assertThrows(CodecException.class, () -> TelemetryCodec.decode(d, "other", KEYS));
    }

    public void testRejectsUnknownVersion() {
        byte[] d = TelemetryCodec.encode(allow(), KEY);
        d[3] = '2';
        assertThrows(CodecException.class, () -> TelemetryCodec.decode(remac(d), CLUSTER, KEYS));
    }

    public void testRejectsTruncatedAndTrailing() {
        byte[] d = TelemetryCodec.encode(allow(), KEY);
        for (int cut : new int[] {0, 1, 31, 32, 33, d.length - 33, d.length - 1}) {
            byte[] shorter = Arrays.copyOf(d, cut);
            assertThrows(CodecException.class, () -> TelemetryCodec.decode(shorter, CLUSTER, KEYS));
        }
        // A trailing byte inside the MAC'd region, correctly MAC'd: still rejected.
        byte[] trailing = Arrays.copyOf(d, d.length + 1);
        System.arraycopy(d, d.length - 32, trailing, d.length - 31, 32);
        trailing[d.length - 32] = 0;
        assertThrows(CodecException.class, () -> TelemetryCodec.decode(remac(trailing), CLUSTER, KEYS));
    }

    public void testRejectsOversizeDatagram() {
        byte[] d = TelemetryCodec.encode(allow(), KEY);
        byte[] buf = Arrays.copyOf(d, TelemetryCodec.RECEIVE_BUFFER);
        // A receiver that got 1201 bytes knows the packet was at least that long.
        CodecException e = assertThrows(CodecException.class,
                () -> TelemetryCodec.decode(buf, 0, TelemetryCodec.RECEIVE_BUFFER, CLUSTER, KEYS));
        assertEquals("oversize datagram", e.getMessage());
    }

    public void testRejectsBadEnumsAndFlags() {
        byte[] d = TelemetryCodec.encode(allow(), KEY);
        int flagsAt = d.length - 33;
        byte[] reserved = d.clone();
        reserved[flagsAt] = 0x02;
        byte[] verdict = d.clone();
        verdict[flagsAt - 2] = 3;
        byte[] reason = d.clone();
        reason[flagsAt - 1] = (byte) 200;
        byte[] inconsistent = d.clone();
        inconsistent[flagsAt - 1] = (byte) ReasonCode.POLICY_DENY.code(); // ALLOW + POLICY_DENY
        byte[] port0 = d.clone();
        port0[flagsAt - 4] = 0;
        port0[flagsAt - 3] = 0;
        for (byte[] bad : new byte[][] {reserved, verdict, reason, inconsistent, port0}) {
            assertThrows(CodecException.class, () -> TelemetryCodec.decode(remac(bad), CLUSTER, KEYS));
        }
    }

    public void testDecodesAtOffset() throws Exception {
        byte[] d = TelemetryCodec.encode(allow(), KEY);
        byte[] buf = new byte[d.length + 10];
        System.arraycopy(d, 0, buf, 5, d.length);
        assertEquals(allow(), TelemetryCodec.decode(buf, 5, d.length, CLUSTER, KEYS));
    }

    public void testRecordRejectsInconsistentVerdicts() {
        assertThrows(IllegalArgumentException.class, () -> event(Verdict.ALLOW, ReasonCode.POLICY_DENY, null, false));
        assertThrows(IllegalArgumentException.class, () -> event(Verdict.DENY, ReasonCode.OK, null, false));
        assertThrows(IllegalArgumentException.class, () -> event(Verdict.DECOY, ReasonCode.POLICY_DENY, null, false));
    }
}
