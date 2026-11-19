package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Bytes;
import eastguard.common.CodecException;
import eastguard.common.IssuerReply;
import eastguard.common.IssuerRequest;
import eastguard.common.Preamble;
import eastguard.common.ReplyStatus;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class HandshakeCodecTest {
    private static final byte[] TOKEN = "aGVsbG8.c2ln".getBytes(StandardCharsets.US_ASCII);

    // ---- issuer request ----

    public void testIssuerRequestRoundTrip() throws Exception {
        byte[] b = new IssuerRequest("app-02").encode();
        assertArrayEquals(new byte[] {'E', 'G', 'I', '1', 6, 'a', 'p', 'p', '-', '0', '2'}, b);
        assertEquals(new IssuerRequest("app-02"), IssuerRequest.decode(b));
        assertEquals(new IssuerRequest("app-02"), IssuerRequest.read(new ByteArrayInputStream(b)));
    }

    public void testIssuerRequestStreamReadStopsAtFrame() throws Exception {
        byte[] b = Fixtures.concat(new IssuerRequest("app-02").encode(), new byte[] {9, 9});
        ByteArrayInputStream in = new ByteArrayInputStream(b);
        IssuerRequest.read(in);
        assertEquals(2, in.available());
    }

    public void testIssuerRequestRejects() {
        byte[] good = new IssuerRequest("app-02").encode();
        byte[] v2 = good.clone();
        v2[3] = '2';
        byte[] badId = good.clone();
        badId[5] = 'A';
        byte[] zeroLen = {'E', 'G', 'I', '1', 0};
        byte[] longLen = {'E', 'G', 'I', '1', 65};
        byte[][] badOnStreamToo = {v2, badId, zeroLen, longLen, Arrays.copyOf(good, good.length - 1), new byte[0],
                new byte[IssuerRequest.MAX_LENGTH + 1]};
        for (byte[] bad : badOnStreamToo) {
            assertThrows(CodecException.class, () -> IssuerRequest.decode(bad));
            assertThrows(CodecException.class, () -> IssuerRequest.read(new ByteArrayInputStream(bad)));
        }
        // Trailing bytes: a whole-frame decode rejects them; a stream read stops at the frame boundary instead.
        assertThrows(CodecException.class, () -> IssuerRequest.decode(Arrays.copyOf(good, good.length + 1)));
    }

    // ---- issuer reply ----

    public void testIssuerReplyRoundTrip() throws Exception {
        IssuerReply ok = IssuerReply.success(TOKEN);
        byte[] b = ok.encode();
        assertEquals(0, b[0]);
        assertEquals(TOKEN.length, ((b[1] & 0xFF) << 8) | (b[2] & 0xFF));
        assertEquals(ok, IssuerReply.decode(b));
        assertEquals(ok, IssuerReply.read(new ByteArrayInputStream(b)));
        for (ReplyStatus s : new ReplyStatus[] {ReplyStatus.DENY, ReplyStatus.QUARANTINED, ReplyStatus.UNAVAILABLE}) {
            IssuerReply f = IssuerReply.failure(s);
            assertArrayEquals(new byte[] {(byte) s.code(), 0, 0}, f.encode());
            assertEquals(f, IssuerReply.decode(f.encode()));
        }
    }

    public void testIssuerReplyRejects() {
        byte[][] bad = {
            {0, 0, 0},                 // success with no token
            {1, 0, 1, 'x'},            // deny with a token
            {4, 0, 0},                 // unknown status
            {0, 0x08, 0x01},           // 2049-byte token claimed
            {0, 0, 2, 'x'},            // truncated token
            {1, 0, 0, 0},              // trailing byte
            {0, 0},                    // truncated header
        };
        for (byte[] b : bad) {
            assertThrows(CodecException.class, () -> IssuerReply.decode(b));
        }
        assertThrows(IllegalArgumentException.class, () -> IssuerReply.success(new byte[2049]));
        assertThrows(IllegalArgumentException.class,
                () -> new IssuerReply(ReplyStatus.DENY, Bytes.copyOf(new byte[1])));
    }

    public void testIssuerReplyStreamRejectsOversizeBeforeReading() {
        // Header claims 0xFFFF bytes; the stream has none. Must fail on the length, not on EOF.
        CodecException e = assertThrows(CodecException.class,
                () -> IssuerReply.read(new ByteArrayInputStream(new byte[] {0, (byte) 0xFF, (byte) 0xFF})));
        assertEquals("invalid token length", e.getMessage());
    }

    // ---- gateway preamble ----

    public void testPreambleRoundTripAndLayout() throws Exception {
        byte[] b = Preamble.of(TOKEN).encode();
        assertArrayEquals(new byte[] {0x45, 0x5A, 1, 0, (byte) TOKEN.length}, Arrays.copyOf(b, 5));
        assertEquals(Preamble.of(TOKEN), Preamble.decode(b));
        assertArrayEquals(TOKEN, Preamble.decode(b).token().toArray());
    }

    public void testPreambleFragmentedArrival() throws Exception {
        byte[] frame = Preamble.of(TOKEN).encode();
        ByteBuffer buf = ByteBuffer.allocate(64);
        for (int i = 0; i < frame.length - 1; i++) {
            buf.put(frame[i]);
            buf.flip();
            assertNull(Preamble.tryDecode(buf));
            assertEquals(0, buf.position()); // nothing consumed while incomplete
            buf.compact();
        }
        buf.put(frame[frame.length - 1]).put((byte) 0x77); // last byte plus early payload
        buf.flip();
        Preamble p = Preamble.tryDecode(buf);
        assertEquals(Preamble.of(TOKEN), p);
        assertEquals(1, buf.remaining()); // early payload left for the gateway to reject
    }

    public void testPreambleRejectsEarly() {
        assertThrows(CodecException.class, () -> Preamble.tryDecode(ByteBuffer.wrap(new byte[] {0x46})));
        assertThrows(CodecException.class, () -> Preamble.tryDecode(ByteBuffer.wrap(new byte[] {0x45, 0x5B})));
        assertThrows(CodecException.class, () -> Preamble.tryDecode(ByteBuffer.wrap(new byte[] {0x45, 0x5A, 2})));
        assertThrows(CodecException.class, () -> Preamble.tryDecode(ByteBuffer.wrap(new byte[] {0x45, 0x5A, 0})));
        // Oversize and zero lengths rejected from the 5-byte header alone.
        assertThrows(CodecException.class,
                () -> Preamble.tryDecode(ByteBuffer.wrap(new byte[] {0x45, 0x5A, 1, 0x08, 0x01})));
        assertThrows(CodecException.class,
                () -> Preamble.tryDecode(ByteBuffer.wrap(new byte[] {0x45, 0x5A, 1, (byte) 0xFF, (byte) 0xFF})));
        assertThrows(CodecException.class,
                () -> Preamble.tryDecode(ByteBuffer.wrap(new byte[] {0x45, 0x5A, 1, 0, 0})));
    }

    public void testPreambleDecodeRejectsTruncationAndTrailing() {
        byte[] frame = Preamble.of(TOKEN).encode();
        assertThrows(CodecException.class, () -> Preamble.decode(Arrays.copyOf(frame, frame.length - 1)));
        assertThrows(CodecException.class, () -> Preamble.decode(Arrays.copyOf(frame, frame.length + 1)));
        assertThrows(CodecException.class, () -> Preamble.decode(new byte[0]));
    }

    public void testPreambleAcceptsMaxToken() throws Exception {
        byte[] max = new byte[2048];
        Arrays.fill(max, (byte) 'A');
        assertEquals(2048, Preamble.decode(Preamble.of(max).encode()).token().length());
        assertThrows(IllegalArgumentException.class, () -> Preamble.of(new byte[2049]));
        assertThrows(IllegalArgumentException.class, () -> Preamble.of(new byte[0]));
    }

    public void testGatewayReply() throws Exception {
        for (ReplyStatus s : ReplyStatus.values()) {
            assertEquals(s, Preamble.decodeReply(Preamble.encodeReply(s)[0]));
        }
        assertThrows(CodecException.class, () -> Preamble.decodeReply(4));
    }
}
