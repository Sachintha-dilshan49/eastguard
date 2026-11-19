package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Bytes;
import eastguard.common.Config;
import eastguard.common.IpAddress;
import eastguard.common.Selector;
import eastguard.gateway.GatewayLimits;
import eastguard.gateway.SessionIndex;
import java.time.Duration;
import java.util.List;
import java.util.Properties;
import java.util.Set;

/** Pure tests of the containment index and of gateway limit validation. */
public final class SessionIndexTest {
    private static final IpAddress IP_A = IpAddress.parse("10.0.1.10");
    private static final IpAddress IP_B = IpAddress.parse("10.0.1.11");
    private static final Bytes CERT_1 = Bytes.fromHex("11".repeat(32));
    private static final Bytes CERT_2 = Bytes.fromHex("22".repeat(32));

    /** Distinct handles that are equal by value, to prove the index compares sessions by identity. */
    private record Handle(String name) {
    }

    private final SessionIndex<Handle> index = new SessionIndex<>();
    private final Handle web1 = new Handle("s");
    private final Handle web2 = new Handle("s");
    private final Handle api = new Handle("s");

    private void fill() {
        index.add(new SessionIndex.Entry<>(web1, "web-01", IP_A, "lease-k1", CERT_1));
        index.add(new SessionIndex.Entry<>(web2, "web-01", IP_B, "lease-k2", CERT_1));
        index.add(new SessionIndex.Entry<>(api, "api-01", IP_A, "lease-k1", CERT_2));
    }

    private static boolean same(List<Handle> actual, Handle... expected) {
        if (actual.size() != expected.length) {
            return false;
        }
        for (Handle e : expected) {
            if (actual.stream().noneMatch(a -> a == e)) {
                return false;
            }
        }
        return true;
    }

    public void testIdentitySelectorMatchesEverySessionOfThatIdentity() {
        fill();
        assertEquals(3, index.size());
        assertTrue(same(index.matching(Set.of(Selector.identity("web-01"))), web1, web2), "both web-01 sessions");
        assertTrue(same(index.matching(Set.of(Selector.identity("db-01")))), "unknown identity matches nothing");
    }

    public void testIpSelectorIsIndependentOfIdentity() {
        fill();
        assertTrue(same(index.matching(Set.of(Selector.ip(IP_A))), web1, api), "both sessions from 10.0.1.10");
    }

    public void testSelectorsUnionWithoutDuplicates() {
        fill();
        List<Handle> hit = index.matching(Set.of(Selector.identity("web-01"), Selector.ip(IP_A)));
        assertTrue(same(hit, web1, web2, api), "union, each session once");
    }

    public void testKeyIdAndCertificateLookups() {
        fill();
        assertTrue(same(index.withKeyId("lease-k1"), web1, api), "key lease-k1");
        assertTrue(same(index.withKeyId("lease-k2"), web2), "key lease-k2");
        assertTrue(same(index.withCertificate(CERT_1), web1, web2), "certificate 1");
        assertTrue(same(index.withCertificate(Bytes.fromHex("33".repeat(32)))), "unknown certificate");
    }

    public void testRemoveCleansEveryIndex() {
        fill();
        assertTrue(index.remove(web1), "removed");
        assertFalse(index.remove(web1), "second remove is a no-op");
        assertTrue(same(index.matching(Set.of(Selector.identity("web-01"))), web2), "only web2 left");
        assertTrue(same(index.matching(Set.of(Selector.ip(IP_A))), api), "only api left on IP_A");
        assertTrue(same(index.withKeyId("lease-k1"), api), "key index updated");
        index.remove(web2);
        index.remove(api);
        assertEquals(0, index.size());
        assertTrue(index.all().isEmpty(), "empty");
    }

    public void testDoubleAddRejected() {
        fill();
        assertThrows(IllegalStateException.class,
                () -> index.add(new SessionIndex.Entry<>(web1, "web-01", IP_A, "lease-k1", CERT_1)));
    }

    // ---- GatewayLimits ----

    public void testLimitDefaultsMatchSpec() {
        GatewayLimits d = GatewayLimits.defaults();
        assertEquals(Duration.ofSeconds(5), d.handshakeTimeout());
        assertEquals(Duration.ofSeconds(2), d.preambleTimeout());
        assertEquals(Duration.ofSeconds(2), d.backendConnectTimeout());
        assertEquals(Duration.ofSeconds(60), d.idleTimeout());
        assertEquals(Duration.ofMinutes(5), d.maxSessionDuration());
    }

    public void testWaterMarksValidated() {
        Properties p = new Properties();
        p.setProperty("limits.highWaterBytes", "4096");
        p.setProperty("limits.lowWaterBytes", "4096");
        assertThrows(IllegalArgumentException.class, () -> GatewayLimits.from(Config.of(p, "test")));
        p.setProperty("limits.highWaterBytes", "65536"); // above the relay buffer
        p.setProperty("limits.lowWaterBytes", "1024");
        assertThrows(IllegalArgumentException.class, () -> GatewayLimits.from(Config.of(p, "test")));
    }
}
