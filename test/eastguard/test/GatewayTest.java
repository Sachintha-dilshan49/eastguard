package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.client.EastGuardClient;
import eastguard.client.GatewaySession;
import eastguard.common.Bytes;
import eastguard.common.Config;
import eastguard.common.Edge;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.EnforcementView;
import eastguard.common.IpAddress;
import eastguard.common.Lease;
import eastguard.common.LeaseCodec;
import eastguard.common.PilotScope;
import eastguard.common.Policy;
import eastguard.common.PolicyMode;
import eastguard.common.Preamble;
import eastguard.common.ReasonCode;
import eastguard.common.ReplyStatus;
import eastguard.common.Selector;
import eastguard.common.Service;
import eastguard.common.Verdict;
import eastguard.common.Workload;
import eastguard.demos.EchoBackend;
import eastguard.gateway.BackendConnector;
import eastguard.gateway.CountingDecisionSink;
import eastguard.gateway.GatewayLimits;
import eastguard.gateway.NioGateway;
import eastguard.tokensvc.TlsContextFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * NIO gateway end to end over mTLS on ephemeral loopback ports, with the generated test PKI and leases signed by
 * the test lease key. Covers spec §10 rows for the gateway data path.
 */
public final class GatewayTest {
    private static final IpAddress LOOPBACK = IpAddress.parse("127.0.0.1");
    private static final InetAddress LOOPBACK_ADDR = InetAddress.getLoopbackAddress();
    private static final Duration CLIENT_TIMEOUT = Duration.ofSeconds(5);
    private static final long REVISION = 4;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Clock clock = Clock.systemUTC(); // certificate validity is real time
    private final CountingDecisionSink sink = new CountingDecisionSink();
    private final AtomicReference<EnforcementView> state =
            new AtomicReference<>(EnforcementView.fresh(snapshot(Set.of(new Edge("web-01", "app-02")))));

    private static EnforcementSnapshot snapshot(Set<Edge> edges) {
        Service app = new Service("app-02", "app-02", Endpoint.parse("127.0.0.1:9002"), "127.0.0.1",
                Endpoint.parse("127.0.0.1:7002"));
        Policy policy = new Policy(PolicyMode.ENFORCE, edges, PilotScope.NONE, 2, Duration.ofSeconds(60));
        return new EnforcementSnapshot("eg-test", REVISION, policy,
                Map.of("web-01", Workload.enabled("web-01"), "api-01", Workload.enabled("api-01")),
                Map.of("app-02", app), List.of(), List.of(), Map.of(),
                Map.of("lease-k1", TestPki.leaseVerifyKey()), Set.of());
    }

    // ---- fixtures ----

    private static Properties limits(String... kv) {
        Properties p = new Properties();
        for (int i = 0; i < kv.length; i += 2) {
            p.setProperty(kv[i], kv[i + 1]);
        }
        return p;
    }

    private NioGateway gateway(Properties limits, InetSocketAddress backend, BackendConnector connector)
            throws IOException {
        NioGateway g = new NioGateway("app-02", TestPki.context("gateway-app-02"), new InetSocketAddress(LOOPBACK_ADDR, 0),
                backend, state::get, clock, GatewayLimits.from(Config.of(limits, "test")), sink, connector);
        g.start();
        return g;
    }

    private NioGateway gateway(Properties limits, EchoBackend echo) throws IOException {
        return gateway(limits, new InetSocketAddress(LOOPBACK_ADDR, echo.port()), BackendConnector.DIRECT);
    }

    private static EchoBackend echo() throws IOException {
        return new EchoBackend(new InetSocketAddress(LOOPBACK_ADDR, 0), 64).start();
    }

    private static Endpoint ep(NioGateway g) {
        return new Endpoint(LOOPBACK, g.port());
    }

    private static EastGuardClient client(String store) {
        // The issuer endpoint is unused: these tests mint leases directly with the test lease key.
        return new EastGuardClient(TestPki.context(store), new Endpoint(LOOPBACK, 1), "127.0.0.1", CLIENT_TIMEOUT);
    }

    /** A lease signed by the trusted test key. */
    private static Bytes lease(String sub, String aud, IpAddress ip, Bytes leaf) {
        long now = System.currentTimeMillis();
        byte[] jti = new byte[Lease.JTI_LENGTH];
        RANDOM.nextBytes(jti);
        Lease l = new Lease("eg-test", "lease-k1", sub, aud, ip, leaf, now, now + 60_000, Bytes.copyOf(jti), REVISION);
        return Bytes.copyOf(LeaseCodec.issue(l, TestPki.leaseSigningKey()));
    }

    private static Bytes webLease() {
        return lease("web-01", "app-02", LOOPBACK, TestPki.fingerprint("workload-web-01"));
    }

    private static Bytes apiLease() {
        return lease("api-01", "app-02", LOOPBACK, TestPki.fingerprint("workload-api-01"));
    }

    private static SSLSocket rawTls(NioGateway g, String store) throws IOException {
        return TlsContextFactory.connect(TestPki.context(store), ep(g), "127.0.0.1", CLIENT_TIMEOUT);
    }

    private static void await(BooleanSupplier condition, String what) throws InterruptedException {
        long end = System.nanoTime() + 5_000_000_000L;
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > end) {
                fail("timed out waiting for " + what);
            }
            Thread.sleep(5);
        }
    }

    /** True if the peer closed the connection without sending a single application byte. */
    private static boolean closedWithoutReply(InputStream in) {
        try {
            return in.read() == -1;
        } catch (IOException e) {
            return true; // reset or TLS close also count: no application reply
        }
    }

    private static void roundTrip(GatewaySession s, String text) throws IOException {
        byte[] msg = text.getBytes(StandardCharsets.UTF_8);
        s.output().write(msg);
        s.output().flush();
        s.setReadTimeout(CLIENT_TIMEOUT);
        assertArrayEquals(msg, s.input().readNBytes(msg.length));
    }

    // ---- admission and relay ----

    public void testAllowedSessionRelaysAndClosesCleanly() throws Exception {
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits(), echo)) {
            GatewaySession s = client("workload-web-01").connect(ep(g), "127.0.0.1", webLease());
            assertEquals(ReplyStatus.SUCCESS, s.status());
            roundTrip(s, "hello through the gateway");
            await(() -> g.stats().sessions() == 1, "one live session");
            // Clean half-close: client close_notify -> backend FIN -> echo FIN -> gateway close_notify -> EOF.
            s.shutdownOutput();
            assertEquals(-1, s.input().read());
            s.close();
            await(() -> g.stats().completed() == 1 && g.stats().connections() == 0, "clean completion");
            assertEquals(1, sink.count(Verdict.ALLOW));
            assertEquals(0, sink.count(Verdict.DENY));
            assertEquals(0, g.stats().truncated());
            await(() -> g.stats().reservedBufferBytes() == 0, "buffers released");
        }
    }

    public void testClientFullCloseIsCleanNotATlsFailure() throws Exception {
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits(), echo)) {
            for (int i = 0; i < 3; i++) {
                GatewaySession s = client("workload-web-01").connect(ep(g), "127.0.0.1", webLease());
                roundTrip(s, "bye " + i);
                s.close(); // JDK TLS 1.3 duplex close: user_canceled + close_notify, no half-close first
            }
            await(() -> g.stats().completed() == 3 && g.stats().connections() == 0, "three clean completions");
            assertEquals(0, g.stats().tlsFailures());
            assertEquals(0, g.stats().truncated());
            assertEquals(0, g.stats().ioErrors());
        }
    }

    public void testDeniedFlowGetsStatusAndNoBackendConnection() throws Exception {
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits(), echo)) {
            // api-01 has no approved edge to app-02: a validly signed lease (e.g. issued under an older policy)
            // is still denied, because admission re-evaluates the current policy.
            GatewaySession s = client("workload-api-01").connect(ep(g), "127.0.0.1", apiLease());
            assertEquals(ReplyStatus.DENY, s.status());
            assertThrows(IllegalStateException.class, s::input);
            assertEquals(1, sink.count(ReasonCode.POLICY_DENY));
            assertEquals(0, echo.accepted());
            await(() -> g.stats().connections() == 0, "denied connection closed");
        }
    }

    public void testFragmentedPreambleIsReassembled() throws Exception {
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits(), echo); SSLSocket s = rawTls(g, "workload-web-01")) {
            byte[] frame = new Preamble(webLease()).encode();
            OutputStream out = s.getOutputStream();
            for (int i = 0; i < frame.length; i += 97) { // many separate TLS records, some splitting the header
                out.write(frame, i, Math.min(97, frame.length - i));
                out.flush();
                if (i < 400) {
                    Thread.sleep(2);
                }
            }
            assertEquals(ReplyStatus.SUCCESS.code(), s.getInputStream().read());
            out.write("ping".getBytes(StandardCharsets.US_ASCII));
            out.flush();
            assertEquals("ping", new String(s.getInputStream().readNBytes(4), StandardCharsets.US_ASCII));
        }
    }

    public void testSingleByteFragmentsAreReassembled() throws Exception {
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits(), echo); SSLSocket s = rawTls(g, "workload-web-01")) {
            byte[] frame = new Preamble(webLease()).encode();
            OutputStream out = s.getOutputStream();
            for (int i = 0; i < 8; i++) { // header split byte by byte, then the rest
                out.write(frame[i]);
                out.flush();
            }
            out.write(frame, 8, frame.length - 8);
            out.flush();
            assertEquals(ReplyStatus.SUCCESS.code(), s.getInputStream().read());
        }
    }

    public void testOversizeAndMalformedPreamblesClosedWithoutReply() throws Exception {
        byte[][] frames = {
                {0x45, 0x5A, 1, 0x08, 0x01},    // token length 2049: rejected from the header alone
                {0x45, 0x5A, 1, 0x00, 0x00},    // token length 0
                {0x45, 0x5B, 1, 0x00, 0x05},    // bad magic
                {0x45, 0x5A, 2, 0x00, 0x05},    // unsupported version
        };
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits(), echo)) {
            for (byte[] frame : frames) {
                try (SSLSocket s = rawTls(g, "workload-web-01")) {
                    s.getOutputStream().write(frame);
                    s.getOutputStream().flush();
                    assertTrue(closedWithoutReply(s.getInputStream()), "no reply to " + Arrays.toString(frame));
                }
            }
            await(() -> g.stats().malformed() == frames.length && g.stats().connections() == 0, "all rejected");
            assertEquals(0, echo.accepted());
            assertEquals(0, sink.count(Verdict.ALLOW));
            assertEquals(0, g.stats().reservedBufferBytes());
        }
    }

    public void testPayloadBeforeReplyIsRejected() throws Exception {
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits(), echo); SSLSocket s = rawTls(g, "workload-web-01")) {
            byte[] early = Fixtures.concat(new Preamble(webLease()).encode(), "GET /".getBytes(StandardCharsets.US_ASCII));
            s.getOutputStream().write(early); // one TLS record: preamble plus early payload
            s.getOutputStream().flush();
            assertTrue(closedWithoutReply(s.getInputStream()), "early payload is a protocol violation");
            await(() -> g.stats().malformed() == 1, "counted as malformed");
            assertEquals(0, echo.accepted()); // nothing reached the backend
        }
    }

    // ---- deadlines ----

    public void testPreambleTimeout() throws Exception {
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits("limits.preambleMillis", "300"), echo);
                SSLSocket s = rawTls(g, "workload-web-01")) {
            s.getOutputStream().write(new byte[] {0x45, 0x5A, 1}); // a plausible start, then silence
            s.getOutputStream().flush();
            long t0 = System.nanoTime();
            assertTrue(closedWithoutReply(s.getInputStream()), "closed without reply");
            long ms = (System.nanoTime() - t0) / 1_000_000;
            assertTrue(ms >= 200 && ms < 3_000, "closed near the 300 ms preamble deadline, took " + ms + " ms");
            await(() -> g.stats().preambleTimeouts() == 1 && g.stats().connections() == 0, "timeout accounted");
            assertEquals(0, echo.accepted());
        }
    }

    public void testHandshakeTimeout() throws Exception {
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits("limits.handshakeMillis", "300"), echo);
                Socket raw = new Socket()) {
            raw.connect(ep(g).toSocketAddress(), 2_000);
            raw.setSoTimeout(5_000);
            long t0 = System.nanoTime();
            assertTrue(closedWithoutReply(raw.getInputStream()), "silent TCP client is closed");
            long ms = (System.nanoTime() - t0) / 1_000_000;
            assertTrue(ms < 3_000, "closed near the 300 ms handshake deadline, took " + ms + " ms");
            await(() -> g.stats().handshakeTimeouts() == 1, "timeout accounted");
        }
    }

    public void testIdleTimeoutClosesRelay() throws Exception {
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits("limits.idleMillis", "300"), echo)) {
            GatewaySession s = client("workload-web-01").connect(ep(g), "127.0.0.1", webLease());
            roundTrip(s, "x");
            s.setReadTimeout(CLIENT_TIMEOUT);
            assertTrue(closedWithoutReply(s.input()), "idle session closed");
            await(() -> g.stats().idleTimeouts() == 1, "idle timeout accounted");
        }
    }

    // ---- lease binding (validator permutations through the real data path) ----

    public void testWrongAudienceDenied() throws Exception {
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits(), echo)) {
            Bytes other = lease("web-01", "db-09", LOOPBACK, TestPki.fingerprint("workload-web-01"));
            assertEquals(ReplyStatus.DENY, client("workload-web-01").connect(ep(g), "127.0.0.1", other).status());
            assertEquals(1, sink.count(ReasonCode.WRONG_AUDIENCE));
            assertEquals(0, echo.accepted());
        }
    }

    public void testLeaseIpMismatchDenied() throws Exception {
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits(), echo)) {
            Bytes elsewhere = lease("web-01", "app-02", IpAddress.parse("10.0.0.9"), TestPki.fingerprint("workload-web-01"));
            assertEquals(ReplyStatus.DENY, client("workload-web-01").connect(ep(g), "127.0.0.1", elsewhere).status());
            assertEquals(1, sink.count(ReasonCode.IP_MISMATCH));
            assertEquals(0, echo.accepted());
        }
    }

    public void testCertificateFingerprintMismatchDenied() throws Exception {
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits(), echo)) {
            // Right identity, wrong certificate: a lease bound to another leaf.
            Bytes otherLeaf = lease("web-01", "app-02", LOOPBACK, TestPki.fingerprint("workload-api-01"));
            assertEquals(ReplyStatus.DENY, client("workload-web-01").connect(ep(g), "127.0.0.1", otherLeaf).status());
            // Another workload replaying web-01's genuine lease.
            assertEquals(ReplyStatus.DENY, client("workload-api-01").connect(ep(g), "127.0.0.1", webLease()).status());
            assertEquals(2, sink.count(ReasonCode.IDENTITY_MISMATCH));
            assertEquals(0, echo.accepted());
        }
    }

    public void testForgedAndGarbageTokensDenied() throws Exception {
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits(), echo)) {
            byte[] genuine = webLease().toArray();
            byte[] tampered = genuine.clone();
            tampered[tampered.length - 2] ^= 0x01; // inside the base64url signature
            EastGuardClient web = client("workload-web-01");
            assertEquals(ReplyStatus.DENY, web.connect(ep(g), "127.0.0.1", Bytes.copyOf(tampered)).status());
            assertEquals(ReplyStatus.DENY, web.connect(ep(g), "127.0.0.1",
                    Bytes.copyOf("not.a-lease".getBytes(StandardCharsets.US_ASCII))).status());
            assertEquals(2, sink.count(ReasonCode.INVALID_TOKEN));
            assertEquals(0, echo.accepted());
        }
    }

    public void testUntrustedCertificateFailsHandshake() throws Exception {
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits(), echo)) {
            assertThrows(IOException.class, () -> client("untrusted-web-01").connect(ep(g), "127.0.0.1", webLease()));
            await(() -> g.stats().tlsFailures() == 1, "server-side handshake failure");
            assertEquals(0, sink.total()); // no application decision, no reply
            assertEquals(0, echo.accepted());
        }
    }

    public void testUnusableStateIsUnavailable() throws Exception {
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits(), echo)) {
            state.set(EnforcementView.NOT_READY);
            assertEquals(ReplyStatus.UNAVAILABLE, client("workload-web-01").connect(ep(g), "127.0.0.1", webLease()).status());
            assertEquals(1, sink.count(ReasonCode.NOT_READY));
            assertEquals(0, echo.accepted());
        }
    }

    // ---- backend failures ----

    public void testBackendRefusedIsUnavailable() throws Exception {
        int closedPort;
        try (ServerSocket tmp = new ServerSocket(0, 1, LOOPBACK_ADDR)) {
            closedPort = tmp.getLocalPort();
        }
        try (NioGateway g = gateway(limits(), new InetSocketAddress(LOOPBACK_ADDR, closedPort), BackendConnector.DIRECT)) {
            assertEquals(ReplyStatus.UNAVAILABLE, client("workload-web-01").connect(ep(g), "127.0.0.1", webLease()).status());
            assertEquals(1, sink.count(ReasonCode.BACKEND_UNAVAILABLE));
            assertEquals(0, sink.count(Verdict.ALLOW));
            await(() -> g.stats().connections() == 0, "closed");
        }
    }

    /** A backend whose TCP connect only starts after {@code delayMs} (never if negative): a slow network. */
    private static BackendConnector slowConnect(long delayMs) {
        return backend -> {
            SocketChannel ch = SocketChannel.open();
            ch.configureBlocking(false);
            if (delayMs >= 0) {
                CompletableFuture.delayedExecutor(delayMs, TimeUnit.MILLISECONDS).execute(() -> {
                    try {
                        ch.connect(backend);
                    } catch (IOException | RuntimeException ignored) {
                        // the gateway already gave up and closed the channel
                    }
                });
            }
            return ch;
        };
    }

    public void testSlowBackendConnectNeverGetsFalseAllow() throws Exception {
        try (EchoBackend echo = echo();
                NioGateway g = gateway(limits("limits.backendConnectMillis", "300"),
                        new InetSocketAddress(LOOPBACK_ADDR, echo.port()), slowConnect(-1))) {
            long t0 = System.nanoTime();
            GatewaySession s = client("workload-web-01").connect(ep(g), "127.0.0.1", webLease());
            long ms = (System.nanoTime() - t0) / 1_000_000;
            assertEquals(ReplyStatus.UNAVAILABLE, s.status());
            assertTrue(ms >= 250, "reply only after the connect deadline, took " + ms + " ms");
            assertEquals(1, g.stats().connectTimeouts());
            assertEquals(0, sink.count(Verdict.ALLOW));
            assertEquals(0, echo.accepted());
        }
    }

    public void testAllowWaitsForBackendConnect() throws Exception {
        try (EchoBackend echo = echo();
                NioGateway g = gateway(limits("limits.backendConnectMillis", "3000"),
                        new InetSocketAddress(LOOPBACK_ADDR, echo.port()), slowConnect(400))) {
            long t0 = System.nanoTime();
            GatewaySession s = client("workload-web-01").connect(ep(g), "127.0.0.1", webLease());
            long ms = (System.nanoTime() - t0) / 1_000_000;
            assertEquals(ReplyStatus.SUCCESS, s.status());
            assertTrue(ms >= 350, "ALLOW only after the backend connected, took " + ms + " ms");
            roundTrip(s, "late but fine");
            s.close();
        }
    }

    // ---- containment via the session index ----

    public void testQuarantineClosesMatchingLiveSessionOnly() throws Exception {
        state.set(EnforcementView.fresh(snapshot(Set.of(new Edge("web-01", "app-02"), new Edge("api-01", "app-02")))));
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits(), echo)) {
            GatewaySession web = client("workload-web-01").connect(ep(g), "127.0.0.1", webLease());
            GatewaySession api = client("workload-api-01").connect(ep(g), "127.0.0.1", apiLease());
            roundTrip(web, "web before");
            roundTrip(api, "api before");
            await(() -> g.stats().sessions() == 2, "two live sessions");

            // The state still allows web-01: only the index lookup can close it.
            assertTrue(g.closeMatching(Set.of(Selector.identity("web-01")), ReasonCode.QUARANTINED), "command accepted");
            assertTrue(closedWithoutReply(web.input()), "quarantined session cancelled");
            await(() -> g.stats().sessions() == 1 && g.stats().closedByCommand() == 1, "one session left");
            roundTrip(api, "api after"); // unrelated session untouched

            // An IP selector matches every session from that address.
            assertTrue(g.closeMatching(Set.of(Selector.ip(LOOPBACK)), ReasonCode.QUARANTINED), "command accepted");
            assertTrue(closedWithoutReply(api.input()), "ip-quarantined session cancelled");
            await(() -> g.stats().sessions() == 0, "no sessions left");
            web.close();
            api.close();
        }
    }

    public void testQuarantineDuringPendingBackendConnect() throws Exception {
        try (EchoBackend echo = echo();
                NioGateway g = gateway(limits("limits.backendConnectMillis", "5000"),
                        new InetSocketAddress(LOOPBACK_ADDR, echo.port()), slowConnect(1_500))) {
            EastGuardClient web = client("workload-web-01");
            Bytes token = webLease();
            CompletableFuture<GatewaySession> result = CompletableFuture.supplyAsync(() -> {
                try {
                    return web.connect(ep(g), "127.0.0.1", token);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
            await(() -> g.stats().pending() == 1, "admission pending on the backend connect");
            assertTrue(g.closeMatching(Set.of(Selector.identity("web-01")), ReasonCode.QUARANTINED), "command accepted");
            GatewaySession s = result.get(5, TimeUnit.SECONDS);
            assertEquals(ReplyStatus.QUARANTINED, s.status());
            assertEquals(0, sink.count(Verdict.ALLOW));
            assertEquals(1, sink.count(ReasonCode.QUARANTINED));
            await(() -> g.stats().pending() == 0 && g.stats().connections() == 0, "pending admission gone");
            Thread.sleep(1_700); // let the delayed connect fire into the closed channel
            assertEquals(0, echo.accepted());
        }
    }

    public void testRevocationCommandsUseKeyIdAndCertificate() throws Exception {
        state.set(EnforcementView.fresh(snapshot(Set.of(new Edge("web-01", "app-02"), new Edge("api-01", "app-02")))));
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits(), echo)) {
            GatewaySession web = client("workload-web-01").connect(ep(g), "127.0.0.1", webLease());
            GatewaySession api = client("workload-api-01").connect(ep(g), "127.0.0.1", apiLease());
            g.closeCertificate(TestPki.fingerprint("workload-api-01"));
            assertTrue(closedWithoutReply(api.input()), "revoked certificate's session closed");
            roundTrip(web, "still here");
            g.closeSigningKey("lease-k1");
            assertTrue(closedWithoutReply(web.input()), "sessions under a revoked signing key closed");
            await(() -> g.stats().sessions() == 0, "all closed");
        }
    }

    public void testStaleStateClosesLiveSessions() throws Exception {
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits(), echo)) {
            GatewaySession s = client("workload-web-01").connect(ep(g), "127.0.0.1", webLease());
            roundTrip(s, "fresh");
            state.set(EnforcementView.NOT_READY); // freshness deadline passed (Task 6 drives this for real)
            s.setReadTimeout(CLIENT_TIMEOUT);
            assertTrue(closedWithoutReply(s.input()), "fail closed");
            await(() -> g.stats().sessions() == 0, "closed by the sweep");
        }
    }

    // ---- TLS closure ----

    public void testTruncationIsAnError() throws Exception {
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits(), echo)) {
            SSLContext ctx = TestPki.context("workload-web-01");
            Socket plain = new Socket();
            plain.connect(ep(g).toSocketAddress(), 2_000);
            plain.setSoTimeout(5_000);
            SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(plain, "127.0.0.1", g.port(), false);
            s.setUseClientMode(true);
            s.setSSLParameters(TlsContextFactory.clientParameters(ctx, "127.0.0.1"));
            s.startHandshake();
            s.getOutputStream().write(new Preamble(webLease()).encode());
            s.getOutputStream().flush();
            assertEquals(ReplyStatus.SUCCESS.code(), s.getInputStream().read());
            plain.close(); // TCP FIN without close_notify
            await(() -> g.stats().truncated() == 1 && g.stats().connections() == 0, "truncation counted");
            assertEquals(0, g.stats().completed());
        }
    }

    // ---- limits and backpressure ----

    public void testPerPeerConnectionLimit() throws Exception {
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits("limits.maxConnectionsPerPeer", "1"), echo)) {
            GatewaySession first = client("workload-web-01").connect(ep(g), "127.0.0.1", webLease());
            assertEquals(ReplyStatus.SUCCESS, first.status());
            assertThrows(IOException.class, () -> client("workload-web-01").connect(ep(g), "127.0.0.1", webLease()));
            assertEquals(1, g.stats().rejectedLimit());
            first.close();
            await(() -> g.stats().connections() == 0, "slot released");
            assertEquals(ReplyStatus.SUCCESS, client("workload-web-01").connect(ep(g), "127.0.0.1", webLease()).status());
        }
    }

    public void testSlowReaderIsBackpressuredAndLosesNothing() throws Exception {
        final int total = 16 << 20;
        try (EchoBackend echo = echo(); NioGateway g = gateway(limits(), echo)) {
            GatewaySession s = client("workload-web-01").connect(ep(g), "127.0.0.1", webLease());
            AtomicLong written = new AtomicLong();
            Thread writer = Thread.ofPlatform().start(() -> {
                byte[] chunk = new byte[8 * 1024];
                try {
                    OutputStream out = s.output();
                    for (int off = 0; off < total; off += chunk.length) {
                        for (int i = 0; i < chunk.length; i++) {
                            chunk[i] = (byte) (off + i);
                        }
                        out.write(chunk);
                        written.addAndGet(chunk.length);
                    }
                    out.flush();
                } catch (IOException ignored) {
                    // reported by the reader's checks
                }
            });
            // Do not read for a while: the client -> gateway -> echo -> gateway -> client loop fills up.
            Thread.sleep(700);
            long stalledAt = written.get();
            Thread.sleep(300);
            assertTrue(written.get() == stalledAt && stalledAt < total, "writer blocked by backpressure at " + stalledAt);
            NioGateway.Stats st = g.stats();
            assertTrue(st.readPauses() > 0, "gateway paused reads");
            assertTrue(st.peakQueuedBytes() <= g.connectionCost(), "queued " + st.peakQueuedBytes()
                    + " bytes, bounded by one connection's buffers (" + g.connectionCost() + ")");

            s.setReadTimeout(CLIENT_TIMEOUT);
            InputStream in = s.input();
            byte[] buf = new byte[64 * 1024];
            int got = 0;
            while (got < total) {
                int n = in.read(buf, 0, Math.min(buf.length, total - got));
                assertTrue(n > 0, "stream ended early at " + got);
                for (int i = 0; i < n; i++) {
                    if (buf[i] != (byte) (got + i)) {
                        fail("corrupted byte at " + (got + i));
                    }
                }
                got += n;
            }
            writer.join(5_000);
            assertEquals(total, written.get());
            s.close();
        }
    }

    public void testStalledBackendBoundsMemory() throws Exception {
        List<Socket> held = new ArrayList<>();
        try (ServerSocket stalled = new ServerSocket(0, 8, LOOPBACK_ADDR);
                NioGateway g = gateway(limits(), new InetSocketAddress(LOOPBACK_ADDR, stalled.getLocalPort()),
                        BackendConnector.DIRECT)) {
            Thread acceptor = Thread.ofPlatform().daemon().start(() -> {
                try {
                    while (true) {
                        held.add(stalled.accept()); // accept, never read
                    }
                } catch (IOException ignored) {
                    // closed at the end of the test
                }
            });
            GatewaySession s = client("workload-web-01").connect(ep(g), "127.0.0.1", webLease());
            AtomicLong written = new AtomicLong();
            Thread writer = Thread.ofPlatform().daemon().start(() -> {
                byte[] chunk = new byte[16 * 1024];
                try {
                    while (true) {
                        s.output().write(chunk);
                        written.addAndGet(chunk.length);
                    }
                } catch (IOException ignored) {
                    // closed at the end of the test
                }
            });
            Thread.sleep(800);
            long stalledAt = written.get();
            Thread.sleep(300);
            assertEquals(stalledAt, written.get());
            assertTrue(g.stats().peakQueuedBytes() <= g.connectionCost(), "gateway memory bounded");
            assertTrue(g.stats().readPauses() > 0, "client reads paused");
            s.close();
            writer.join(2_000);
            acceptor.interrupt();
        } finally {
            for (Socket h : held) {
                h.close();
            }
        }
    }

    // ---- decoy ----

    public void testDecoyAcceptsAndClosesWithOneEvent() throws Exception {
        try (EchoBackend echo = echo()) {
            NioGateway g = new NioGateway("app-02", TestPki.context("gateway-app-02"), new InetSocketAddress(LOOPBACK_ADDR, 0),
                    new InetSocketAddress(LOOPBACK_ADDR, echo.port()), state::get, clock, GatewayLimits.defaults(), sink,
                    BackendConnector.DIRECT);
            g.enableDecoy("decoy-test", new InetSocketAddress(LOOPBACK_ADDR, 0));
            g.start();
            try (g; Socket probe = new Socket()) {
                probe.connect(new InetSocketAddress(LOOPBACK_ADDR, g.decoyPort()), 2_000);
                probe.setSoTimeout(5_000);
                probe.getOutputStream().write("USER admin\r\n".getBytes(StandardCharsets.US_ASCII));
                assertTrue(closedWithoutReply(probe.getInputStream()), "decoy closes at once, says nothing");
                await(() -> sink.count(Verdict.DECOY) == 1, "one DECOY event");
                assertEquals(1, sink.count(ReasonCode.DECOY_TOUCH));
                assertEquals(1, g.decoyHits());
                assertEquals(0, echo.accepted());
                assertEquals(0, g.stats().accepted()); // the real listener never saw it
            }
        }
    }
}
