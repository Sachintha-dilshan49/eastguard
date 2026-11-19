package eastguard.test;

import static eastguard.test.Assert.*;
import static eastguard.test.Fixtures.*;

import eastguard.common.Bytes;
import eastguard.common.CodecException;
import eastguard.common.Ed25519;
import eastguard.common.IpAddress;
import eastguard.common.Notice;
import eastguard.common.NoticeCodec;
import eastguard.common.NoticeOperation;
import eastguard.common.ReasonCode;
import eastguard.common.Selector;
import eastguard.common.TelemetryCodec;
import eastguard.common.WireWriter;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Clock;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

public final class NoticeCodecTest {
    private static final KeyPair CONTROL = Ed25519.generate();
    private static final Function<String, PublicKey> KEYS = id -> id.equals("ctl-k1") ? CONTROL.getPublic() : null;
    private static final Bytes NONCE = Bytes.fromHex("ab".repeat(16));

    private static Notice quarantine(List<Selector> selectors) {
        return new Notice(CLUSTER, "ctl-k1", 12, NOW_MS, NONCE, NoticeOperation.QUARANTINE, NOW_MS + 600_000,
                selectors, ReasonCode.DECOY_TOUCH);
    }

    private static Notice release() {
        return new Notice(CLUSTER, "ctl-k1", 13, NOW_MS, NONCE, NoticeOperation.RELEASE, 0,
                List.of(Selector.identity(CLIENT)), ReasonCode.OPERATOR_ACTION);
    }

    private static Notice decode(byte[] d) throws CodecException {
        return NoticeCodec.decode(d, CLUSTER, KEYS, CLOCK);
    }

    /** Hand-built body (lets tests produce shapes the record forbids), correctly signed. */
    private static byte[] signed(WireWriter body) {
        byte[] b = body.toByteArray();
        return Fixtures.concat(b, Ed25519.sign(CONTROL.getPrivate(), b));
    }

    private static WireWriter header(int op, long expiresAt) {
        return new WireWriter().ascii("EGC1").id(CLUSTER).id("ctl-k1").i64(12).i64(NOW_MS).raw(NONCE.toArray())
                .u8(op).i64(expiresAt);
    }

    public void testRoundTrip() throws Exception {
        Notice q = quarantine(List.of(Selector.identity(CLIENT), Selector.ip(CLIENT_IP),
                Selector.ip(IpAddress.parse("2001:db8::9"))));
        assertEquals(q, decode(NoticeCodec.encode(q, CONTROL.getPrivate())));
        assertEquals(release(), decode(NoticeCodec.encode(release(), CONTROL.getPrivate())));
    }

    public void testMaxSelectorsFitsDatagram() throws Exception {
        List<Selector> eight = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            eight.add(Selector.identity(("w" + i).repeat(32).substring(0, 64)));
        }
        byte[] d = NoticeCodec.encode(quarantine(eight), CONTROL.getPrivate());
        assertTrue(d.length <= NoticeCodec.MAX_DATAGRAM, "max notice fits: " + d.length);
        assertEquals(8, decode(d).selectors().size());
    }

    public void testRejectsSignatureProblems() {
        byte[] d = NoticeCodec.encode(release(), CONTROL.getPrivate());
        byte[] flipped = d.clone();
        flipped[30] ^= 1; // inside revision/sentAt: still parses
        assertEquals("bad signature",
                assertThrows(CodecException.class, () -> decode(flipped)).getMessage());
        assertThrows(CodecException.class,
                () -> NoticeCodec.decode(d, CLUSTER, id -> Ed25519.generate().getPublic(), CLOCK));
        assertEquals("untrusted control key", assertThrows(CodecException.class,
                () -> NoticeCodec.decode(d, CLUSTER, id -> null, CLOCK)).getMessage());
        assertEquals("wrong cluster", assertThrows(CodecException.class,
                () -> NoticeCodec.decode(d, "other", KEYS, CLOCK)).getMessage());
    }

    public void testTimestampWindow() throws Exception {
        byte[] d = NoticeCodec.encode(release(), CONTROL.getPrivate());
        for (long offset : new long[] {-30_000, 0, 30_000}) {
            decode(d, Clock.fixed(NOW.plusMillis(offset), ZoneOffset.UTC));
        }
        for (long offset : new long[] {-30_001, 30_001}) {
            assertThrows(CodecException.class, () -> decode(d, Clock.fixed(NOW.plusMillis(offset), ZoneOffset.UTC)));
        }
    }

    private static void decode(byte[] d, Clock c) throws CodecException {
        NoticeCodec.decode(d, CLUSTER, KEYS, c);
    }

    public void testRejectsUnknownVersionAndEnums() {
        byte[] d = NoticeCodec.encode(release(), CONTROL.getPrivate());
        byte[] v2 = d.clone();
        v2[3] = '2';
        assertThrows(CodecException.class, () -> decode(v2));
        assertThrows(CodecException.class, () -> decode(signed(header(3, 0).u8(1).u8(1).id(CLIENT).u8(15))));
        assertThrows(CodecException.class, () -> decode(signed(header(2, 0).u8(1).u8(3).id(CLIENT).u8(15))));
        assertThrows(CodecException.class, () -> decode(signed(header(2, 0).u8(1).u8(1).id(CLIENT).u8(99))));
    }

    public void testRejectsBadSelectorCounts() {
        assertThrows(CodecException.class, () -> decode(signed(header(2, 0).u8(0).u8(15))));
        WireWriter nine = header(2, 0).u8(9);
        for (int i = 0; i < 9; i++) {
            nine.u8(1).id("w" + i);
        }
        assertThrows(CodecException.class, () -> decode(signed(nine.u8(15))));
        assertThrows(CodecException.class,
                () -> decode(signed(header(2, 0).u8(2).u8(1).id(CLIENT).u8(1).id(CLIENT).u8(15))));
    }

    public void testRejectsBadExpiry() {
        // RELEASE with nonzero expiry, QUARANTINE with zero or past expiry.
        assertThrows(CodecException.class, () -> decode(signed(header(2, NOW_MS).u8(1).u8(1).id(CLIENT).u8(15))));
        assertThrows(CodecException.class, () -> decode(signed(header(1, 0).u8(1).u8(1).id(CLIENT).u8(11))));
        assertThrows(CodecException.class, () -> decode(signed(header(1, NOW_MS).u8(1).u8(1).id(CLIENT).u8(11))));
    }

    public void testRejectsTruncatedTrailingOversize() {
        byte[] d = NoticeCodec.encode(release(), CONTROL.getPrivate());
        for (int cut : new int[] {0, 63, 64, 65, d.length - 1}) {
            assertThrows(CodecException.class, () -> decode(Arrays.copyOf(d, cut)));
        }
        byte[] body = Arrays.copyOf(d, d.length - 64);
        assertThrows(CodecException.class, () -> decode(signed(new WireWriter().raw(body).u8(0))));
        byte[] big = Arrays.copyOf(d, TelemetryCodec.RECEIVE_BUFFER);
        assertEquals("oversize datagram", assertThrows(CodecException.class,
                () -> NoticeCodec.decode(big, 0, big.length, CLUSTER, KEYS, CLOCK)).getMessage());
    }

    public void testRecordValidation() {
        assertThrows(IllegalArgumentException.class, () -> quarantine(List.of()));
        assertThrows(IllegalArgumentException.class,
                () -> quarantine(List.of(Selector.identity(CLIENT), Selector.identity(CLIENT))));
        assertThrows(IllegalArgumentException.class, () -> new Notice(CLUSTER, "ctl-k1", 1, NOW_MS, NONCE,
                NoticeOperation.RELEASE, 5, List.of(Selector.identity(CLIENT)), ReasonCode.OPERATOR_ACTION));
    }
}
