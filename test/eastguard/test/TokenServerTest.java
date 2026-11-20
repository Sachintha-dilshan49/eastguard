package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.client.EastGuardClient;
import eastguard.common.Edge;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.EnforcementView;
import eastguard.common.IpAddress;
import eastguard.common.IssuerReply;
import eastguard.common.Lease;
import eastguard.common.LeaseCodec;
import eastguard.common.PilotScope;
import eastguard.common.Policy;
import eastguard.common.PolicyMode;
import eastguard.common.ReasonCode;
import eastguard.common.ReplyStatus;
import eastguard.common.Restriction;
import eastguard.common.Selector;
import eastguard.common.Service;
import eastguard.common.SignedLease;
import eastguard.common.Workload;
import eastguard.common.PolicyEvaluator;
import eastguard.common.Peer;
import eastguard.tokensvc.IssueLimiter;
import eastguard.tokensvc.LeaseIssuer;
import eastguard.tokensvc.TlsContextFactory;
import eastguard.tokensvc.TokenServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/** Token service end to end over mTLS on an ephemeral loopback port, with the generated test PKI. */
public final class TokenServerTest {
    private static final IpAddress LOOPBACK = IpAddress.parse("127.0.0.1");
    private static final Duration CLIENT_TIMEOUT = Duration.ofSeconds(5);
    private static final long REVISION = 4;

    private final Clock clock = Clock.systemUTC(); // certificate validity is real time
    private final AtomicReference<EnforcementView> state = new AtomicReference<>(EnforcementView.fresh(snapshot(List.of())));

    private static EnforcementSnapshot snapshot(List<Restriction> restrictions) {
        Service app = new Service("app-02", "app-02", Endpoint.parse("127.0.0.1:9002"), "127.0.0.1",
                Endpoint.parse("127.0.0.1:7002"));
        Policy policy = new Policy(PolicyMode.ENFORCE, Set.of(new Edge("web-01", "app-02")), PilotScope.NONE, 2,
                Duration.ofSeconds(60));
        return new EnforcementSnapshot("eg-test", REVISION, policy,
                Map.of("web-01", Workload.enabled("web-01"), "api-01", Workload.enabled("api-01")),
                Map.of("app-02", app), restrictions, List.of(), Map.of(),
                Map.of("lease-k1", TestPki.leaseVerifyKey()), Set.of());
    }

    private TokenServer start(int maxConcurrent, Duration deadline) throws IOException {
        LeaseIssuer issuer = new LeaseIssuer(new PolicyEvaluator(clock), "lease-k1", TestPki.leaseSigningKey(), TestPki.leaseVerifyKey(),
                new IssueLimiter(1_000, System::nanoTime), clock, new SecureRandom());
        TokenServer server = new TokenServer(TestPki.context("tokensvc"),
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), state::get, issuer,
                new TokenServer.Limits(maxConcurrent, deadline, 16));
        server.start();
        return server;
    }

    private TokenServer start() throws IOException {
        return start(8, Duration.ofSeconds(5));
    }

    private static Endpoint ep(TokenServer s) {
        return new Endpoint(LOOPBACK, s.port());
    }

    private static EastGuardClient client(String store, TokenServer s) {
        return new EastGuardClient(TestPki.context(store), ep(s), "127.0.0.1", CLIENT_TIMEOUT);
    }

    private static void await(BooleanSupplier condition, String what) throws InterruptedException {
        long end = System.nanoTime() + 5_000_000_000L;
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > end) {
                fail("timed out waiting for " + what);
            }
            Thread.sleep(10);
        }
    }

    /** True if the server closed the connection without sending anything. */
    private static boolean closedWithoutReply(InputStream in) {
        try {
            return in.read() == -1;
        } catch (IOException e) {
            return true; // reset or TLS close also count: no application reply
        }
    }

    // ---- issuance ----

    public void testTrustedWorkloadGetsBoundLease() throws Exception {
        try (TokenServer server = start()) {
            long before = Instant.now().toEpochMilli();
            IssuerReply reply = client("workload-web-01", server).requestLease("app-02");
            assertEquals(ReplyStatus.SUCCESS, reply.status());
            SignedLease signed = LeaseCodec.parse(reply.token().toArray());
            assertTrue(signed.verify(TestPki.leaseVerifyKey()), "signed by lease-k1");
            Lease l = signed.lease();
            assertEquals("eg-test", l.cluster());
            assertEquals("web-01", l.subject());
            assertEquals("app-02", l.audience());
            assertEquals(LOOPBACK, l.sourceIp()); // read from the accepted socket
            assertEquals(TestPki.fingerprint("workload-web-01"), l.leafSha256());
            assertEquals(60_000, l.expiresAtMs() - l.issuedAtMs());
            assertTrue(l.issuedAtMs() >= before - 1_000, "issued now");
            assertEquals(REVISION, l.issuedAtRevision());

            // The same evaluator the gateway uses admits it for the same certificate and IP...
            PolicyEvaluator gateway = new PolicyEvaluator(clock);
            Peer peer = new Peer("web-01", TestPki.fingerprint("workload-web-01"), LOOPBACK);
            assertEquals(ReasonCode.OK, gateway.admit(state.get(), peer, "app-02", reply.token().toArray()).reason());
            // ...but not for another certificate or address.
            Peer otherCert = new Peer("web-01", TestPki.fingerprint("workload-api-01"), LOOPBACK);
            assertEquals(ReasonCode.IDENTITY_MISMATCH,
                    gateway.admit(state.get(), otherCert, "app-02", reply.token().toArray()).reason());
            Peer otherIp = new Peer("web-01", peer.leafSha256(), IpAddress.parse("10.0.0.9"));
            assertEquals(ReasonCode.IP_MISMATCH,
                    gateway.admit(state.get(), otherIp, "app-02", reply.token().toArray()).reason());
            assertEquals(1, server.stats().issued());
        }
    }

    public void testDefaultDeny() throws Exception {
        try (TokenServer server = start()) {
            IssuerReply noEdge = client("workload-api-01", server).requestLease("app-02");
            assertEquals(ReplyStatus.DENY, noEdge.status());
            assertEquals(0, noEdge.token().length());
            assertEquals(ReplyStatus.DENY, client("workload-web-01", server).requestLease("db-09").status());
            assertEquals(2, server.stats().denied());
        }
    }

    /** Spec §1 "selected token-service denials": policy deny for a known service and quarantine, nothing else. */
    public void testSelectedDenialsReportedOverUdp() throws Exception {
        try (java.net.DatagramSocket collector = new java.net.DatagramSocket(new InetSocketAddress(
                InetAddress.getLoopbackAddress(), 0))) {
            collector.setSoTimeout(300);
            LeaseIssuer issuer = new LeaseIssuer(new PolicyEvaluator(clock), "lease-k1", TestPki.leaseSigningKey(),
                    TestPki.leaseVerifyKey(), new IssueLimiter(1_000, System::nanoTime), clock, new SecureRandom());
            TokenServer server = new TokenServer(TestPki.context("tokensvc"),
                    new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), state::get, issuer,
                    new TokenServer.Limits(8, Duration.ofSeconds(5), 16));
            server.reportTo(new eastguard.common.TelemetrySender("eg-test", "tokensvc", "tk1", TelemetryProducerTest.KEY,
                    (InetSocketAddress) collector.getLocalSocketAddress(), 16, new SecureRandom()), clock);
            server.start();
            try (server) {
                client("workload-web-01", server).requestLease("app-02");   // issued: not reported
                client("workload-api-01", server).requestLease("app-02");   // policy deny, known service
                client("workload-web-01", server).requestLease("db-09");    // unknown service: not reported
                Restriction q = new Restriction(Selector.identity("web-01"), ReasonCode.OPERATOR_ACTION, "operator",
                        Instant.now(), Instant.now().plusSeconds(300), REVISION);
                state.set(EnforcementView.fresh(snapshot(List.of(q))));
                client("workload-web-01", server).requestLease("app-02");   // quarantined
                state.set(EnforcementView.NOT_READY);
                client("workload-web-01", server).requestLease("app-02");   // infrastructure: not reported
                List<eastguard.common.Telemetry> got = new java.util.ArrayList<>();
                byte[] buf = new byte[eastguard.common.TelemetryCodec.RECEIVE_BUFFER];
                while (true) {
                    java.net.DatagramPacket p = new java.net.DatagramPacket(buf, buf.length);
                    try {
                        collector.receive(p);
                    } catch (java.net.SocketTimeoutException e) {
                        break;
                    }
                    got.add(eastguard.common.TelemetryCodec.decode(buf, 0, p.getLength(), "eg-test",
                            (producer, keyId) -> TelemetryProducerTest.KEY));
                }
                assertEquals(2, got.size());
                assertEquals("api-01", got.get(0).sourceIdentity());
                assertEquals(ReasonCode.POLICY_DENY, got.get(0).reason());
                assertTrue(got.get(0).outsideApprovedGraph(), "policy deny carries flag bit 0");
                assertEquals(server.port(), got.get(0).dstPort());
                assertEquals("web-01", got.get(1).sourceIdentity());
                assertEquals(ReasonCode.QUARANTINED, got.get(1).reason());
                assertEquals(got.get(0).seq() + 1, got.get(1).seq());
            }
        }
    }

    public void testQuarantinedAndStaleState() throws Exception {
        try (TokenServer server = start()) {
            Restriction q = new Restriction(Selector.identity("web-01"), ReasonCode.OPERATOR_ACTION, "operator",
                    Instant.now(), Instant.now().plusSeconds(300), REVISION);
            state.set(EnforcementView.fresh(snapshot(List.of(q))));
            assertEquals(ReplyStatus.QUARANTINED, client("workload-web-01", server).requestLease("app-02").status());
            state.set(EnforcementView.NOT_READY);
            assertEquals(ReplyStatus.UNAVAILABLE, client("workload-web-01", server).requestLease("app-02").status());
        }
    }

    public void testIdentityChecksRunOnEveryConnection() throws Exception {
        try (TokenServer server = start()) {
            EastGuardClient web = client("workload-web-01", server);
            assertEquals(ReplyStatus.SUCCESS, web.requestLease("app-02").status());
            // Revoke the certificate in the installed state; the same client context (and any cached TLS
            // session) must now be refused.
            var s = state.get().snapshot();
            Workload revoked = new Workload("web-01", true, Set.of(TestPki.fingerprint("workload-web-01")), null);
            state.set(EnforcementView.fresh(new EnforcementSnapshot(s.clusterId(), s.revision(), s.policy(),
                    Map.of("web-01", revoked, "api-01", Workload.enabled("api-01")), s.services(), s.restrictions(),
                    s.leaseReductions(), s.releaseWatermarks(), s.tokenKeys(), s.revokedKeyIds())));
            assertEquals(ReplyStatus.DENY, web.requestLease("app-02").status());
        }
    }

    public void testNonWorkloadCertificatesDenied() throws Exception {
        try (TokenServer server = start()) {
            for (String store : new String[] {"workload-nosan", "workload-twosan", "gateway-app-02"}) {
                IssuerReply r = client(store, server).requestLease("app-02");
                assertEquals(ReplyStatus.DENY, r.status());
            }
        }
    }

    // ---- TLS and framing failures ----

    public void testUntrustedCertificateFailsHandshake() throws Exception {
        try (TokenServer server = start()) {
            EastGuardClient rogue = client("untrusted-web-01", server);
            // TLS 1.3 reports the rejection after the client's side of the handshake: as the server's alert
            // (SSLException) or, when a TCP reset discards the alert, a SocketException. The server is authoritative.
            assertThrows(IOException.class, () -> rogue.requestLease("app-02"));
            await(() -> server.stats().handshakeFailures() == 1, "server-side handshake failure");
            assertEquals(0, server.stats().issued() + server.stats().denied());
        }
    }

    public void testMalformedRequestsClosedWithoutReply() throws Exception {
        byte[][] frames = {
                {'E', 'G', 'I', '2', 6, 'a', 'p', 'p', '-', '0', '2'}, // unknown version
                {'E', 'G', 'I', '1', 65},                              // id length over 64
                {'E', 'G', 'I', '1', 0},                               // empty id
                {'E', 'G', 'I', '1', 3, 'A', 'P', 'P'},                // invalid id characters
        };
        try (TokenServer server = start()) {
            SSLContext web = TestPki.context("workload-web-01");
            for (byte[] frame : frames) {
                try (SSLSocket s = TlsContextFactory.connect(web, ep(server), "127.0.0.1", CLIENT_TIMEOUT)) {
                    s.getOutputStream().write(frame);
                    s.getOutputStream().flush();
                    assertTrue(closedWithoutReply(s.getInputStream()), "no reply to a malformed frame");
                }
            }
            await(() -> server.stats().malformed() == frames.length, "malformed count");
        }
    }

    public void testTruncatedRequestClosedWithoutReply() throws Exception {
        try (TokenServer server = start()) {
            try (SSLSocket s = TlsContextFactory.connect(TestPki.context("workload-web-01"), ep(server), "127.0.0.1",
                    CLIENT_TIMEOUT)) {
                s.getOutputStream().write(new byte[] {'E', 'G', 'I', '1', 6, 'a', 'p'});
                s.getOutputStream().flush();
                s.shutdownOutput();
                assertTrue(closedWithoutReply(s.getInputStream()), "no reply to a truncated frame");
            }
        }
    }

    /**
     * True if a raw (non-TLS) client sees the connection end with nothing but, at most, TLS alert records
     * (content type 21) that {@code SSLSocket.close()} sends while aborting a handshake.
     */
    private static boolean closedWithOnlyTlsAlerts(InputStream in) {
        try {
            byte[] all = in.readNBytes(4_096);
            for (int i = 0; i < all.length; ) {
                if (all[i] != 21 || i + 5 > all.length) {
                    return false;
                }
                i += 5 + (((all[i + 3] & 0xFF) << 8) | (all[i + 4] & 0xFF));
            }
            return all.length < 4_096;
        } catch (IOException e) {
            return true;
        }
    }

    // ---- deadlines and limits ----

    public void testSilentTcpClientClosedAtDeadline() throws Exception {
        try (TokenServer server = start(4, Duration.ofMillis(300))) {
            try (Socket raw = new Socket()) {
                raw.connect(ep(server).toSocketAddress(), 2_000);
                raw.setSoTimeout(5_000);
                long t0 = System.nanoTime();
                assertTrue(closedWithOnlyTlsAlerts(raw.getInputStream()), "closed without an application reply");
                long ms = (System.nanoTime() - t0) / 1_000_000;
                assertTrue(ms < 3_000, "closed near the 300 ms deadline, took " + ms + " ms");
            }
            await(() -> server.stats().timedOut() == 1 && server.active() == 0, "deadline accounted, permit released");
        }
    }

    public void testSilentTlsClientClosedAtDeadline() throws Exception {
        try (TokenServer server = start(4, Duration.ofMillis(500))) {
            try (SSLSocket s = TlsContextFactory.connect(TestPki.context("workload-web-01"), ep(server), "127.0.0.1",
                    CLIENT_TIMEOUT)) {
                assertTrue(closedWithoutReply(s.getInputStream()), "closed after handshake with no request");
            }
            await(() -> server.stats().timedOut() == 1, "deadline accounted");
        }
    }

    public void testExcessConnectionsRejected() throws Exception {
        try (TokenServer server = start(1, Duration.ofSeconds(2))) {
            try (Socket hog = new Socket()) {
                hog.connect(ep(server).toSocketAddress(), 2_000);
                await(() -> server.active() == 1, "first connection holds the only permit");
                assertThrows(IOException.class, () -> client("workload-web-01", server).requestLease("app-02"));
                assertEquals(1, server.stats().rejectedBusy());
            }
            await(() -> server.active() == 0, "permit released after the hog closes");
            assertEquals(ReplyStatus.SUCCESS, client("workload-web-01", server).requestLease("app-02").status());
        }
    }

    public void testClientDeadlineBoundsSlowServer() throws Exception {
        // A plain TCP listener that accepts and never speaks TLS.
        try (var silent = new java.net.ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            EastGuardClient c = new EastGuardClient(TestPki.context("workload-web-01"),
                    new Endpoint(LOOPBACK, silent.getLocalPort()), "127.0.0.1", Duration.ofMillis(300));
            long t0 = System.nanoTime();
            assertThrows(IOException.class, () -> c.requestLease("app-02"));
            long ms = (System.nanoTime() - t0) / 1_000_000;
            assertTrue(ms < 3_000, "client gave up near its deadline, took " + ms + " ms");
        }
    }

    public void testCloseStopsAccepting() throws Exception {
        TokenServer server = start();
        Endpoint ep = ep(server);
        server.close();
        EastGuardClient c = new EastGuardClient(TestPki.context("workload-web-01"), ep, "127.0.0.1", CLIENT_TIMEOUT);
        assertThrows(IOException.class, () -> c.requestLease("app-02"));
    }

    public void testInvalidServiceIdRejectedBeforeConnecting() throws Exception {
        try (TokenServer server = start()) {
            assertThrows(IllegalArgumentException.class, () -> client("workload-web-01", server).requestLease("App 02"));
        }
    }
}
