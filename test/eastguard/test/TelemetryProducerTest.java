package eastguard.test;

import static eastguard.test.Assert.assertEquals;
import static eastguard.test.Assert.assertFalse;
import static eastguard.test.Assert.assertNull;
import static eastguard.test.Assert.assertThrows;
import static eastguard.test.Assert.assertTrue;

import eastguard.common.Bytes;
import eastguard.common.Config;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementView;
import eastguard.common.IpAddress;
import eastguard.common.IssuerReply;
import eastguard.common.Peer;
import eastguard.common.ReasonCode;
import eastguard.common.ReplyStatus;
import eastguard.common.Telemetry;
import eastguard.common.TelemetryCodec;
import eastguard.common.TelemetrySender;
import eastguard.common.Verdict;
import eastguard.gateway.DecisionSink;
import eastguard.gateway.GatewayDecision;
import eastguard.tokensvc.LeaseIssuer;
import eastguard.tokensvc.TokenServer;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Properties;

/** UDP telemetry producer: wire output, sequence/boot ID, bounded non-blocking queue, issuer selection. */
public final class TelemetryProducerTest {
    static final byte[] KEY = filled(32, 7);
    static final Endpoint LISTENER = Endpoint.parse("127.0.0.1:9002");

    static byte[] filled(int n, int v) {
        byte[] b = new byte[n];
        Arrays.fill(b, (byte) v);
        return b;
    }

    private static Telemetry receive(DatagramSocket s) throws Exception {
        byte[] buf = new byte[TelemetryCodec.RECEIVE_BUFFER];
        DatagramPacket p = new DatagramPacket(buf, buf.length);
        s.receive(p);
        return TelemetryCodec.decode(buf, 0, p.getLength(), "eg-demo",
                (producer, keyId) -> producer.equals("gw-app-02") && keyId.equals("tk1") ? KEY : null);
    }

    public void testSendsAuthenticatedDatagramsWithIncreasingSequence() throws Exception {
        try (DatagramSocket collector = new DatagramSocket(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))) {
            collector.setSoTimeout(5_000);
            TelemetrySender s = new TelemetrySender("eg-demo", "gw-app-02", "tk1", KEY,
                    (InetSocketAddress) collector.getLocalSocketAddress(), 16, new SecureRandom());
            s.start();
            try {
                DecisionSink sink = DecisionSink.udp(s);
                IpAddress ip = IpAddress.parse("10.0.1.10");
                sink.record(new GatewayDecision(1_000, "web-01", ip, "app-02", LISTENER, Verdict.ALLOW, ReasonCode.OK,
                        true, 4));
                sink.record(new GatewayDecision(1_001, null, ip, "app-02", LISTENER, Verdict.DENY,
                        ReasonCode.INVALID_TOKEN, false, 4));
                Telemetry a = receive(collector);
                Telemetry b = receive(collector);
                assertEquals(0, a.seq());
                assertEquals(1, b.seq());
                assertEquals(s.bootId(), a.bootId());
                assertEquals(a.bootId(), b.bootId());
                assertEquals("web-01", a.sourceIdentity());
                assertTrue(a.outsideApprovedGraph(), "flag bit 0 carried");
                assertEquals(9002, a.dstPort());
                assertNull(b.sourceIdentity());
                assertEquals(ReasonCode.INVALID_TOKEN, b.reason());
                assertEquals(2, s.stats().sent());
            } finally {
                s.close();
            }
        }
    }

    public void testEachStartHasItsOwnBootId() {
        TelemetrySender a = new TelemetrySender("eg-demo", "gw-app-02", "tk1", KEY, new InetSocketAddress(
                InetAddress.getLoopbackAddress(), 5514), 4, new SecureRandom());
        TelemetrySender b = new TelemetrySender("eg-demo", "gw-app-02", "tk1", KEY, new InetSocketAddress(
                InetAddress.getLoopbackAddress(), 5514), 4, new SecureRandom());
        assertEquals(16, a.bootId().length());
        assertFalse(a.bootId().equals(b.bootId()), "random boot IDs differ");
    }

    public void testFullQueueDropsWithoutBlockingAndLeavesASequenceGap() throws Exception {
        try (DatagramSocket collector = new DatagramSocket(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))) {
            collector.setSoTimeout(5_000);
            TelemetrySender s = new TelemetrySender("eg-demo", "gw-app-02", "tk1", KEY,
                    (InetSocketAddress) collector.getLocalSocketAddress(), 2, new SecureRandom());
            IpAddress ip = IpAddress.parse("10.0.1.10");
            long t0 = System.nanoTime();
            int accepted = 0;
            for (int i = 0; i < 5; i++) { // not started yet: nothing drains the queue
                if (s.offer(1_000, "web-01", ip, "app-02", LISTENER, Verdict.ALLOW, ReasonCode.OK, false, 1)) {
                    accepted++;
                }
            }
            assertTrue(System.nanoTime() - t0 < 1_000_000_000L, "offer never blocks");
            assertEquals(2, accepted);
            assertEquals(3, s.stats().dropped());
            s.start();
            try {
                assertEquals(0, receive(collector).seq());
                assertEquals(1, receive(collector).seq());
                assertTrue(s.offer(1_000, "web-01", ip, "app-02", LISTENER, Verdict.ALLOW, ReasonCode.OK, false, 1),
                        "space again");
                assertEquals(5, receive(collector).seq()); // seq 2..4 were dropped: a visible gap
            } finally {
                s.close();
            }
        }
    }

    public void testInvalidEventIsCountedNotThrown() {
        TelemetrySender s = new TelemetrySender("eg-demo", "gw-app-02", "tk1", KEY, new InetSocketAddress(
                InetAddress.getLoopbackAddress(), 5514), 4, new SecureRandom());
        assertFalse(s.offer(1_000, "web-01", IpAddress.parse("10.0.1.10"), "app-02", LISTENER, Verdict.ALLOW,
                ReasonCode.POLICY_DENY, false, 1), "verdict/reason mismatch rejected");
        assertEquals(1, s.stats().invalid());
    }

    public void testShortKeyRejected() {
        assertThrows(IllegalArgumentException.class, () -> new TelemetrySender("eg-demo", "gw", "tk1", new byte[16],
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 5514), 4, new SecureRandom()));
    }

    public void testSettingsOptionalAndValidated() {
        Properties p = new Properties();
        assertNull(TelemetrySender.Settings.from(Config.of(p, "t")));
        p.setProperty("telemetry.keyFile", "keys/telemetry/x.key");
        assertThrows(IllegalArgumentException.class, () -> TelemetrySender.Settings.from(Config.of(p, "t")));
        p.setProperty("telemetry.collector", "127.0.0.1:5514");
        p.setProperty("telemetry.producerId", "gw-app-02");
        p.setProperty("telemetry.keyId", "tk1");
        TelemetrySender.Settings s = TelemetrySender.Settings.from(Config.of(p, "t"));
        assertEquals(4_096, s.queueCapacity());
        p.setProperty("telemetry.collector", "localhost:5514");
        assertThrows(IllegalArgumentException.class, () -> TelemetrySender.Settings.from(Config.of(p, "t")));
    }

    public void testIssuerReportsOnlySelectedAuthenticatedDenials() {
        EnforcementView view = EnforcementView.fresh(ControlFixtures.initial(Fixtures.LEASE_KEYS.getPublic()));
        Peer peer = new Peer("web-01", Bytes.fromHex("11".repeat(32)), IpAddress.parse("10.0.1.10"));
        assertTrue(TokenServer.reportable(deny(ReasonCode.POLICY_DENY, peer), view, "app-02"), "known service");
        assertFalse(TokenServer.reportable(deny(ReasonCode.POLICY_DENY, peer), view, "no-such"), "unknown service");
        assertTrue(TokenServer.reportable(deny(ReasonCode.QUARANTINED, peer), view, "app-02"), "quarantine");
        assertFalse(TokenServer.reportable(deny(ReasonCode.QUARANTINED, null), view, "app-02"), "no TLS identity");
        assertFalse(TokenServer.reportable(deny(ReasonCode.THROTTLED, peer), view, "app-02"), "throttling");
        assertFalse(TokenServer.reportable(deny(ReasonCode.NOT_READY, peer), view, "app-02"), "infrastructure");
        assertFalse(TokenServer.reportable(deny(ReasonCode.BAD_IDENTITY, null), view, "app-02"), "bad certificate");
    }

    private static LeaseIssuer.Outcome deny(ReasonCode r, Peer peer) {
        return new LeaseIssuer.Outcome(r, IssuerReply.failure(ReplyStatus.forReason(r)), peer, null);
    }
}
