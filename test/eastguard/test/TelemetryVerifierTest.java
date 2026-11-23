package eastguard.test;

import static eastguard.test.Assert.assertEquals;
import static eastguard.test.Assert.assertFalse;
import static eastguard.test.Assert.assertThrows;
import static eastguard.test.Assert.assertTrue;

import eastguard.common.Bytes;
import eastguard.common.Endpoint;
import eastguard.common.IpAddress;
import eastguard.common.ReasonCode;
import eastguard.common.Telemetry;
import eastguard.common.TelemetryCodec;
import eastguard.common.Verdict;
import eastguard.detector.FlowReceiver;
import eastguard.detector.ProducerInventory;
import eastguard.detector.ProducerInventory.Kind;
import eastguard.detector.ProducerInventory.Producer;
import eastguard.detector.TelemetryVerifier;
import eastguard.detector.TelemetryVerifier.Result;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/** Telemetry verification: MAC, producer scope, size, event-time window, dedup and reordering, input quality. */
public final class TelemetryVerifierTest {
    static final byte[] GW_KEY = TelemetryProducerTest.filled(32, 1);
    static final byte[] GW5_KEY = TelemetryProducerTest.filled(32, 5);
    static final byte[] ISS_KEY = TelemetryProducerTest.filled(32, 2);
    static final Endpoint GW = Endpoint.parse("127.0.0.1:9002");
    static final Endpoint DECOY = Endpoint.parse("127.0.0.1:9003");
    static final Endpoint GW5 = Endpoint.parse("127.0.0.1:9005");
    static final Endpoint ISSUER = Endpoint.parse("127.0.0.1:8443");
    static final Bytes BOOT = Bytes.fromHex("00112233445566778899aabbccddeeff");
    static final IpAddress IP = IpAddress.parse("10.0.1.10");

    static ProducerInventory inventory() {
        return ProducerInventory.of(List.of(
                new Producer("gw-app-02", Kind.GATEWAY, "tk1", Map.of(GW, "app-02"), Map.of(DECOY, "decoy-9003")),
                new Producer("gw-app-05", Kind.GATEWAY, "tk1", Map.of(GW5, "app-05"), Map.of()),
                new Producer("tokensvc", Kind.ISSUER, "tk1", Map.of(ISSUER, ProducerInventory.ANY_SERVICE), Map.of())),
                Map.of("gw-app-02", GW_KEY, "gw-app-05", GW5_KEY, "tokensvc", ISS_KEY));
    }

    static Telemetry event(String producer, Bytes boot, long seq, long at, String identity, IpAddress ip, String service,
            Endpoint dst, Verdict v, ReasonCode r, boolean outside) {
        return new Telemetry("eg-demo", producer, "tk1", boot, seq, at, 3, identity, ip, service, dst.ip(), dst.port(), v, r,
                outside);
    }

    static Telemetry gwDeny(long seq, ReasonCode r) {
        return event("gw-app-02", BOOT, seq, Fixtures.NOW_MS, "web-01", IP, "app-02", GW, Verdict.DENY, r, false);
    }

    static byte[] gw(Telemetry t) {
        return TelemetryCodec.encode(t, GW_KEY);
    }

    private final ControlFixtures.MutableClock clock = new ControlFixtures.MutableClock(Fixtures.NOW);
    private final TelemetryVerifier v = new TelemetryVerifier("eg-demo", inventory(), TelemetryVerifier.Settings.defaults(),
            clock);
    private long nanos = 1_000_000_000L;

    private Result verify(byte[] d) {
        return v.verify(d, d.length, nanos).result();
    }

    public void testValidEventAcceptedOnceDuplicateRejected() {
        byte[] d = gw(gwDeny(0, ReasonCode.POLICY_DENY));
        TelemetryVerifier.Outcome o = v.verify(d, d.length, nanos);
        assertEquals(Result.ACCEPTED, o.result());
        assertEquals("web-01", o.verified().event().sourceIdentity());
        assertEquals(Kind.GATEWAY, o.verified().producerKind());
        assertEquals("gw-app-02/00112233/0", o.verified().ref());
        assertEquals(Result.DUPLICATE, verify(d));
        assertEquals(1, v.stats().count(Result.DUPLICATE));
    }

    public void testWrongMacUnknownProducerAndWrongClusterAreUnauthenticated() {
        assertEquals(Result.UNAUTHENTICATED, verify(TelemetryCodec.encode(gwDeny(0, ReasonCode.POLICY_DENY), ISS_KEY)));
        Telemetry stranger = event("gw-x", BOOT, 0, Fixtures.NOW_MS, "web-01", IP, "app-02", GW, Verdict.DENY,
                ReasonCode.POLICY_DENY, false);
        assertEquals(Result.UNAUTHENTICATED, verify(TelemetryCodec.encode(stranger, GW_KEY)));
        Telemetry other = new Telemetry("eg-other", "gw-app-02", "tk1", BOOT, 0, Fixtures.NOW_MS, 3, "web-01", IP,
                "app-02", GW.ip(), GW.port(), Verdict.DENY, ReasonCode.POLICY_DENY, false);
        assertEquals(Result.UNAUTHENTICATED, verify(gw(other)));
        Telemetry wrongKeyId = new Telemetry("eg-demo", "gw-app-02", "tk2", BOOT, 0, Fixtures.NOW_MS, 3, "web-01", IP,
                "app-02", GW.ip(), GW.port(), Verdict.DENY, ReasonCode.POLICY_DENY, false);
        assertEquals(Result.UNAUTHENTICATED, verify(gw(wrongKeyId)));
        byte[] flipped = gw(gwDeny(0, ReasonCode.POLICY_DENY));
        flipped[20] ^= 1;
        assertEquals(Result.UNAUTHENTICATED, verify(flipped));
        assertEquals(Result.MALFORMED, verify(new byte[] {'E', 'G', 'F'}));
        assertEquals(0, v.stats().count(Result.ACCEPTED));
    }

    public void testProducerScope() {
        // gw-app-02's valid key, but another gateway's listener.
        assertEquals(Result.OUT_OF_SCOPE, verify(gw(event("gw-app-02", BOOT, 0, Fixtures.NOW_MS, "web-01", IP, "app-05",
                GW5, Verdict.DENY, ReasonCode.POLICY_DENY, false))));
        // Its own listener, but a service it does not front.
        assertEquals(Result.OUT_OF_SCOPE, verify(gw(event("gw-app-02", BOOT, 1, Fixtures.NOW_MS, "web-01", IP, "app-05",
                GW, Verdict.DENY, ReasonCode.POLICY_DENY, false))));
        // A DECOY verdict on the real listener, and an ALLOW on the decoy.
        assertEquals(Result.OUT_OF_SCOPE, verify(gw(event("gw-app-02", BOOT, 2, Fixtures.NOW_MS, null, IP, "app-02",
                GW, Verdict.DECOY, ReasonCode.DECOY_TOUCH, false))));
        assertEquals(Result.OUT_OF_SCOPE, verify(gw(event("gw-app-02", BOOT, 3, Fixtures.NOW_MS, "web-01", IP,
                "decoy-9003", DECOY, Verdict.ALLOW, ReasonCode.OK, false))));
        // The issuer only reports selected denials on its own listener.
        assertEquals(Result.OUT_OF_SCOPE, verify(TelemetryCodec.encode(event("tokensvc", BOOT, 0, Fixtures.NOW_MS,
                "web-01", IP, "app-02", ISSUER, Verdict.ALLOW, ReasonCode.OK, false), ISS_KEY)));
        assertEquals(Result.OUT_OF_SCOPE, verify(TelemetryCodec.encode(event("tokensvc", BOOT, 1, Fixtures.NOW_MS,
                "web-01", IP, "app-02", ISSUER, Verdict.DENY, ReasonCode.EXPIRED, false), ISS_KEY)));
        assertEquals(Result.ACCEPTED, verify(TelemetryCodec.encode(event("tokensvc", BOOT, 2, Fixtures.NOW_MS,
                "web-01", IP, "app-02", ISSUER, Verdict.DENY, ReasonCode.POLICY_DENY, true), ISS_KEY)));
        assertEquals(Result.ACCEPTED, verify(gw(event("gw-app-02", BOOT, 4, Fixtures.NOW_MS, null, IP, "decoy-9003",
                DECOY, Verdict.DECOY, ReasonCode.DECOY_TOUCH, false))));
    }

    public void testOversizeRejectedBeforeParsing() {
        byte[] big = new byte[TelemetryCodec.RECEIVE_BUFFER];
        byte[] valid = gw(gwDeny(0, ReasonCode.POLICY_DENY));
        System.arraycopy(valid, 0, big, 0, valid.length);
        assertEquals(Result.OVERSIZE, v.verify(big, big.length, nanos).result());
        assertEquals(Result.ACCEPTED, verify(valid));
    }

    public void testEventTimeOutsideAcceptanceWindowIsStale() {
        assertEquals(Result.STALE, verify(gw(event("gw-app-02", BOOT, 0, Fixtures.NOW_MS - 30_001, "web-01", IP,
                "app-02", GW, Verdict.DENY, ReasonCode.POLICY_DENY, false))));
        assertEquals(Result.STALE, verify(gw(event("gw-app-02", BOOT, 1, Fixtures.NOW_MS + 5_001, "web-01", IP,
                "app-02", GW, Verdict.DENY, ReasonCode.POLICY_DENY, false))));
        assertEquals(Result.ACCEPTED, verify(gw(event("gw-app-02", BOOT, 2, Fixtures.NOW_MS - 29_000, "web-01", IP,
                "app-02", GW, Verdict.DENY, ReasonCode.POLICY_DENY, false))));
    }

    public void testReorderingInsideWindowAcceptedOutsideRejected() {
        assertEquals(Result.ACCEPTED, verify(gw(gwDeny(0, ReasonCode.POLICY_DENY))));
        assertEquals(Result.ACCEPTED, verify(gw(gwDeny(5, ReasonCode.POLICY_DENY))));
        assertEquals(4, v.stats().missing());
        assertEquals(Result.ACCEPTED, verify(gw(gwDeny(3, ReasonCode.POLICY_DENY)))); // late, inside the window
        assertEquals(Result.DUPLICATE, verify(gw(gwDeny(3, ReasonCode.POLICY_DENY))));
        assertEquals(3, v.stats().missing());
        assertEquals(1, v.stats().reordered());
        assertEquals(Result.ACCEPTED, verify(gw(gwDeny(2_000, ReasonCode.POLICY_DENY))));
        assertEquals(Result.ACCEPTED, verify(gw(gwDeny(977, ReasonCode.POLICY_DENY)))); // 2000 - 1024 < 977
        assertEquals(Result.TOO_OLD, verify(gw(gwDeny(976, ReasonCode.POLICY_DENY)))); // fell out of the window
        assertEquals(Result.TOO_OLD, verify(gw(gwDeny(5, ReasonCode.POLICY_DENY)))); // a replay of an old one
    }

    public void testNewBootIsAFreshStreamButBootsAreBounded() {
        TelemetryVerifier small = new TelemetryVerifier("eg-demo", inventory(),
                new TelemetryVerifier.Settings(30_000, 5_000, 1_024, 2), clock);
        for (int i = 0; i < 2; i++) {
            Bytes boot = Bytes.fromHex(("0" + i).repeat(16));
            byte[] d = gw(event("gw-app-02", boot, 7, Fixtures.NOW_MS, "web-01", IP, "app-02", GW, Verdict.DENY,
                    ReasonCode.POLICY_DENY, false));
            assertEquals(Result.ACCEPTED, small.verify(d, d.length, nanos).result());
        }
        byte[] third = gw(event("gw-app-02", Bytes.fromHex("22".repeat(16)), 0, Fixtures.NOW_MS, "web-01", IP, "app-02",
                GW, Verdict.DENY, ReasonCode.POLICY_DENY, false));
        assertEquals(Result.BOOT_LIMIT, small.verify(third, third.length, nanos).result());
        // Once the oldest boot has been quiet for the acceptance window, its state can go.
        nanos += 30_001_000_000L;
        clock.advance(java.time.Duration.ofSeconds(31));
        third = gw(event("gw-app-02", Bytes.fromHex("22".repeat(16)), 0, clock.millis(), "web-01", IP, "app-02",
                GW, Verdict.DENY, ReasonCode.POLICY_DENY, false));
        assertEquals(Result.ACCEPTED, small.verify(third, third.length, nanos).result());
        assertThrows(IllegalArgumentException.class, () -> new TelemetryVerifier.Settings(30_000, 5_000, 1_000, 2));
    }

    public void testSequenceGapsDegradeInputButForgeriesDoNot() {
        for (int i = 0; i < 50; i++) {
            verify(TelemetryCodec.encode(gwDeny(i, ReasonCode.POLICY_DENY), ISS_KEY)); // forged: wrong key
        }
        assertFalse(v.degraded(nanos), "junk does not switch automation off");
        verify(gw(gwDeny(0, ReasonCode.POLICY_DENY)));
        verify(gw(gwDeny(10, ReasonCode.POLICY_DENY))); // 9 lost
        assertTrue(v.degraded(nanos), "9 of 11 expected events missing");
        nanos += 11_000_000_000L;
        assertFalse(v.degraded(nanos), "the loss aged out");
    }

    public void testInventoryRejectsSharedEndpointsAndShortKeys() {
        assertThrows(IllegalArgumentException.class, () -> ProducerInventory.of(List.of(
                new Producer("a", Kind.GATEWAY, "tk1", Map.of(GW, "app-02"), Map.of()),
                new Producer("b", Kind.GATEWAY, "tk1", Map.of(GW, "app-02"), Map.of())),
                Map.of("a", GW_KEY, "b", GW5_KEY)));
        assertThrows(IllegalArgumentException.class, () -> ProducerInventory.of(List.of(
                new Producer("a", Kind.GATEWAY, "tk1", Map.of(GW, "app-02"), Map.of())), Map.of("a", new byte[16])));
        assertThrows(IllegalArgumentException.class, () -> new Producer("a", Kind.GATEWAY, "tk1",
                Map.of(GW, ProducerInventory.ANY_SERVICE), Map.of()));
    }

    /** Real UDP: forged, duplicate and oversized datagrams never reach the sink. */
    public void testReceiverDeliversOnlyVerifiedEvents() throws Exception {
        List<TelemetryVerifier.Verified> got = Collections.synchronizedList(new ArrayList<>());
        TelemetryVerifier verifier = new TelemetryVerifier("eg-demo", inventory(), TelemetryVerifier.Settings.defaults(),
                java.time.Clock.systemUTC());
        try (FlowReceiver r = new FlowReceiver(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), verifier,
                got::add, () -> { }, System::nanoTime);
                DatagramSocket out = new DatagramSocket()) {
            r.start();
            InetSocketAddress to = new InetSocketAddress(InetAddress.getLoopbackAddress(), r.port());
            long now = System.currentTimeMillis();
            byte[] good = gw(event("gw-app-02", BOOT, 0, now, "web-01", IP, "app-02", GW, Verdict.DENY,
                    ReasonCode.POLICY_DENY, false));
            byte[] forged = TelemetryCodec.encode(event("gw-app-02", BOOT, 1, now, "web-01", IP, "app-02", GW,
                    Verdict.DENY, ReasonCode.POLICY_DENY, false), ISS_KEY);
            byte[] oversized = new byte[1_300];
            System.arraycopy(good, 0, oversized, 0, good.length);
            byte[] last = gw(event("gw-app-02", BOOT, 2, now, "web-01", IP, "app-02", GW, Verdict.DENY,
                    ReasonCode.POLICY_DENY, false));
            for (byte[] d : List.of(good, forged, good, oversized, last)) {
                out.send(new DatagramPacket(d, d.length, to));
            }
            long deadline = System.nanoTime() + 5_000_000_000L;
            while (got.size() < 2 && System.nanoTime() < deadline) {
                Thread.sleep(10);
            }
            Thread.sleep(100);
            r.close();
            assertEquals(2, got.size());
            assertEquals(0, got.get(0).event().seq());
            assertEquals(2, got.get(1).event().seq());
            TelemetryVerifier.Stats s = verifier.stats();
            assertEquals(1, s.count(Result.UNAUTHENTICATED));
            assertEquals(1, s.count(Result.DUPLICATE));
            assertEquals(1, s.count(Result.OVERSIZE));
        }
    }

    public void testHitlessTelemetryKeyRotation() {
        byte[] newKey = new byte[32];
        java.util.Arrays.fill(newKey, (byte) 0x77);
        ProducerInventory rotated = inventory().withKey("gw-app-02", "tk2", newKey);
        TelemetryVerifier tv = new TelemetryVerifier("eg-demo", rotated, TelemetryVerifier.Settings.defaults(), clock);

        // Event signed with old key (tk1) is accepted
        byte[] oldEvent = TelemetryCodec.encode(event("gw-app-02", BOOT, 0, Fixtures.NOW_MS, "web-01", IP, "app-02",
                GW, Verdict.DENY, ReasonCode.POLICY_DENY, false), GW_KEY);
        assertEquals(Result.ACCEPTED, tv.verify(oldEvent, oldEvent.length, nanos).result());

        // Event signed with new rotated key (tk2) is also accepted without dropping old events
        Telemetry tNew = new Telemetry("eg-demo", "gw-app-02", "tk2", BOOT, 1, Fixtures.NOW_MS, 3, "web-01", IP,
                "app-02", GW.ip(), GW.port(), Verdict.DENY, ReasonCode.POLICY_DENY, false);
        byte[] newEvent = TelemetryCodec.encode(tNew, newKey);
        assertEquals(Result.ACCEPTED, tv.verify(newEvent, newEvent.length, nanos).result());

        // Event signed with unknown key (tk3) is rejected
        Telemetry tBad = new Telemetry("eg-demo", "gw-app-02", "tk3", BOOT, 2, Fixtures.NOW_MS, 3, "web-01", IP,
                "app-02", GW.ip(), GW.port(), Verdict.DENY, ReasonCode.POLICY_DENY, false);
        byte[] badEvent = TelemetryCodec.encode(tBad, newKey);
        assertEquals(Result.UNAUTHENTICATED, tv.verify(badEvent, badEvent.length, nanos).result());
    }
}
