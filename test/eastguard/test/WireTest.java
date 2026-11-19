package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Bytes;
import eastguard.common.CodecException;
import eastguard.common.Ids;
import eastguard.common.IpAddress;
import eastguard.common.WireReader;
import eastguard.common.WireWriter;

public final class WireTest {

    public void testIdValidation() {
        assertTrue(Ids.isValid("web-01"), "simple id");
        assertTrue(Ids.isValid("a"), "single char");
        assertTrue(Ids.isValid("0.a_b-c"), "digits and punctuation");
        assertTrue(Ids.isValid("a".repeat(64)), "64 chars");
        assertFalse(Ids.isValid("a".repeat(65)), "65 chars");
        assertFalse(Ids.isValid(""), "empty");
        assertFalse(Ids.isValid(null), "null");
        assertFalse(Ids.isValid("-web"), "leading dash");
        assertFalse(Ids.isValid(".web"), "leading dot");
        assertFalse(Ids.isValid("Web"), "uppercase");
        assertFalse(Ids.isValid("web 01"), "space");
        assertFalse(Ids.isValid("wéb"), "non-ascii");
    }

    public void testPrimitivesRoundTrip() throws Exception {
        byte[] b = new WireWriter()
                .u8(255).u16(65535).i64(-2L).nonNegative(Long.MAX_VALUE, "x")
                .id("svc.app-02").optId(null).optId("web-01")
                .ip(IpAddress.parse("10.1.2.3")).ip(IpAddress.parse("2001:db8::1"))
                .toByteArray();
        WireReader r = new WireReader(b);
        assertEquals(255, r.u8());
        assertEquals(65535, r.u16());
        assertEquals(-2L, r.i64());
        assertEquals(Long.MAX_VALUE, r.nonNegative("x"));
        assertEquals("svc.app-02", r.id());
        assertNull(r.optId());
        assertEquals("web-01", r.optId());
        assertEquals(IpAddress.parse("10.1.2.3"), r.ip());
        assertEquals(IpAddress.parse("2001:db8::1"), r.ip());
        r.end();
    }

    public void testBigEndian() {
        byte[] b = new WireWriter().u16(0x455A).i64(0x0102030405060708L).toByteArray();
        assertArrayEquals(new byte[] {0x45, 0x5A, 1, 2, 3, 4, 5, 6, 7, 8}, b);
    }

    public void testReaderRejectsTruncation() {
        assertThrows(CodecException.class, () -> new WireReader(new byte[7]).i64());
        assertThrows(CodecException.class, () -> new WireReader(new byte[1]).u16());
        assertThrows(CodecException.class, () -> new WireReader(new byte[0]).u8());
        // id claims 5 bytes but only 2 follow
        assertThrows(CodecException.class, () -> new WireReader(new byte[] {5, 'a', 'b'}).id());
    }

    public void testReaderRejectsTrailingBytes() throws Exception {
        WireReader r = new WireReader(new byte[] {1, 2});
        r.u8();
        assertThrows(CodecException.class, r::end);
    }

    public void testReaderRejectsBadIds() {
        assertThrows(CodecException.class, () -> new WireReader(new byte[] {0}).id());
        assertThrows(CodecException.class, () -> new WireReader(new byte[] {1, 'A'}).id());
        assertThrows(CodecException.class, () -> new WireReader(new byte[] {1, '-'}).id());
        byte[] tooLong = new byte[66];
        tooLong[0] = 65;
        java.util.Arrays.fill(tooLong, 1, 66, (byte) 'a');
        assertThrows(CodecException.class, () -> new WireReader(tooLong).id());
    }

    public void testReaderRejectsNegativeRevision() {
        byte[] b = new WireWriter().i64(-1).toByteArray();
        assertThrows(CodecException.class, () -> new WireReader(b).nonNegative("revision"));
    }

    public void testReaderRejectsBadIpLengths() {
        for (int len : new int[] {0, 1, 3, 5, 15, 17, 255}) {
            byte[] b = new byte[1 + Math.max(len, 0)];
            b[0] = (byte) len;
            assertThrows(CodecException.class, () -> new WireReader(b).ip());
        }
    }

    public void testReaderRejectsIpv4MappedOnWire() {
        byte[] b = new byte[17];
        b[0] = 16;
        b[11] = (byte) 0xff;
        b[12] = (byte) 0xff;
        b[13] = 10;
        assertThrows(CodecException.class, () -> new WireReader(b).ip());
    }

    public void testWriterRejectsInvalidValues() {
        assertThrows(IllegalArgumentException.class, () -> new WireWriter().u8(256));
        assertThrows(IllegalArgumentException.class, () -> new WireWriter().u16(-1));
        assertThrows(IllegalArgumentException.class, () -> new WireWriter().id("Bad"));
        assertThrows(IllegalArgumentException.class, () -> new WireWriter().nonNegative(-1, "seq"));
    }

    public void testIpParsingAndNormalization() {
        IpAddress mapped = IpAddress.parse("::ffff:192.168.1.7");
        assertTrue(mapped.isIpv4(), "mapped address normalized to IPv4");
        assertEquals(IpAddress.parse("192.168.1.7"), mapped);
        byte[] raw16 = new byte[16];
        raw16[10] = (byte) 0xff;
        raw16[11] = (byte) 0xff;
        raw16[12] = 127;
        raw16[15] = 1;
        assertEquals(IpAddress.parse("127.0.0.1"), IpAddress.of(raw16));
        assertEquals(16, IpAddress.parse("::1").length());
        assertEquals("10.0.0.1", IpAddress.parse("10.0.0.1").toString());
        for (String bad : new String[] {"", "1.2.3", "1.2.3.4.5", "256.1.1.1", "01.2.3.4", "1..3.4",
                "localhost", "example.com", "fe80::1%eth0", "zz::1", "1::2::3", " 1.2.3.4",
                // Leading '.' would reach the system resolver inside InetAddress.getByName.
                ".:1", "..::"}) {
            assertThrows(IllegalArgumentException.class, () -> IpAddress.parse(bad));
        }
    }

    public void testBytesIsImmutableAndHidesContent() {
        byte[] src = {1, 2, 3};
        Bytes b = Bytes.copyOf(src);
        src[0] = 9;
        assertEquals(1, b.get(0));
        b.toArray()[1] = 9;
        assertEquals(2, b.get(1));
        assertEquals(Bytes.fromHex("010203"), b);
        assertEquals("Bytes[3]", b.toString());
        assertEquals("010203", b.hex());
    }
}
