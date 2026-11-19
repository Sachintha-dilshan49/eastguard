package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Cidr;
import eastguard.common.IpAddress;

public final class CidrTest {

    private static boolean in(String cidr, String ip) {
        return Cidr.parse(cidr).contains(IpAddress.parse(ip));
    }

    public void testIpv4Prefixes() {
        assertTrue(in("10.0.0.0/8", "10.255.1.2"), "inside /8");
        assertFalse(in("10.0.0.0/8", "11.0.0.0"), "outside /8");
        assertTrue(in("192.168.4.0/22", "192.168.7.255"), "top of /22");
        assertFalse(in("192.168.4.0/22", "192.168.8.0"), "just past /22");
        assertFalse(in("192.168.4.0/22", "192.168.3.255"), "just before /22");
    }

    public void testIpv4ZeroAndFullWidth() {
        assertTrue(in("0.0.0.0/0", "1.2.3.4"), "/0 matches any v4");
        assertTrue(in("0.0.0.0/0", "255.255.255.255"), "/0 matches broadcast");
        assertFalse(in("0.0.0.0/0", "::1"), "/0 v4 never matches v6");
        assertTrue(in("10.1.2.3/32", "10.1.2.3"), "/32 exact");
        assertFalse(in("10.1.2.3/32", "10.1.2.4"), "/32 neighbour");
        assertEquals(Cidr.parse("10.1.2.3/32"), Cidr.parse("10.1.2.3"));
    }

    public void testIpv6Prefixes() {
        assertTrue(in("2001:db8::/32", "2001:db8:ffff::1"), "inside /32");
        assertFalse(in("2001:db8::/32", "2001:db9::1"), "outside /32");
        assertTrue(in("fd00:1:2:2::/63", "fd00:1:2:2::1"), "odd prefix, low half");
        assertTrue(in("fd00:1:2:2::/63", "fd00:1:2:3::1"), "odd prefix, high half");
        assertFalse(in("fd00:1:2:2::/63", "fd00:1:2:4::1"), "odd prefix, outside");
    }

    public void testIpv6ZeroAndFullWidth() {
        assertTrue(in("::/0", "2001:db8::1"), "/0 matches any v6");
        assertFalse(in("::/0", "10.0.0.1"), "/0 v6 never matches v4");
        assertTrue(in("2001:db8::7/128", "2001:db8::7"), "/128 exact");
        assertFalse(in("2001:db8::7/128", "2001:db8::8"), "/128 neighbour");
    }

    public void testMappedAddressMatchesIpv4Prefix() {
        assertTrue(in("10.0.0.0/8", "::ffff:10.9.9.9"), "mapped v6 normalized to v4");
    }

    public void testRejectsInvalid() {
        for (String bad : new String[] {"10.0.0.1/8", "10.0.0.0/33", "::/129", "2001:db8::1/64", "10.0.0.0/",
                "10.0.0.0/08", "10.0.0.0/-1", "10.0.0.0/8/8", "10.0.0.0/ 8", "host/8", "/8", "::ffff:10.0.0.0/104", "fd00:1:2:3::/63"}) {
            assertThrows(IllegalArgumentException.class, () -> Cidr.parse(bad));
        }
        assertThrows(IllegalArgumentException.class, () -> Cidr.parse(null));
    }

    public void testToStringAndEquality() {
        assertEquals("10.0.0.0/8", Cidr.parse("10.0.0.0/8").toString());
        assertEquals(Cidr.parse("2001:db8::/32"), Cidr.parse("2001:0db8:0:0::/32"));
        assertFalse(Cidr.parse("10.0.0.0/8").equals(Cidr.parse("10.0.0.0/9")), "prefix length matters");
    }
}
