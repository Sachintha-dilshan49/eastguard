package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.client.EastGuardClient;
import eastguard.client.GatewaySession;
import eastguard.common.Bytes;
import eastguard.common.Cidr;
import eastguard.common.Edge;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.EnforcementView;
import eastguard.common.IpAddress;
import eastguard.common.IssuerReply;
import eastguard.common.PilotScope;
import eastguard.common.Policy;
import eastguard.common.PolicyEvaluator;
import eastguard.common.PolicyMode;
import eastguard.common.ReplyStatus;
import eastguard.common.Service;
import eastguard.common.Workload;
import eastguard.demos.EchoBackend;
import eastguard.gateway.BackendConnector;
import eastguard.gateway.CountingDecisionSink;
import eastguard.gateway.GatewayLimits;
import eastguard.gateway.NioGateway;
import eastguard.tokensvc.IssueLimiter;
import eastguard.tokensvc.LeaseIssuer;
import eastguard.tokensvc.TokenServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.SSLContext;

/**
 * Tests for {@link EastGuardClient} and {@link GatewaySession}:
 * parameter validations, end-to-end mTLS lease acquisition and gateway relay,
 * composite connection helper, denied session invariant checks, and deadline timeouts.
 */
public final class ClientTest {
    private static final IpAddress LOOPBACK = IpAddress.parse("127.0.0.1");
    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private static EnforcementSnapshot snapshot(int backendPort) {
        Workload web = new Workload("web-01", true, Set.of(), Cidr.of(LOOPBACK, 32));
        Workload untrusted = new Workload("untrusted-web-01", false, Set.of(), Cidr.of(LOOPBACK, 32));
        Service app02 = new Service("app-02", "gw-app-02", new Endpoint(LOOPBACK, 9002), "127.0.0.1",
                new Endpoint(LOOPBACK, backendPort));
        Policy policy = new Policy(PolicyMode.ENFORCE, Set.of(new Edge("web-01", "app-02")),
                new PilotScope(Set.of(), Set.of()), 1, Duration.ofSeconds(60));
        return new EnforcementSnapshot("eg-demo", 1, policy, Map.of("web-01", web, "untrusted-web-01", untrusted),
                Map.of("app-02", app02), List.of(), List.of(), Map.of(),
                Map.of("lease-k1", TestPki.leaseVerifyKey()), Set.of());
    }

    public void testConstructorValidation() {
        SSLContext ctx = TestPki.context("workload-web-01");
        Endpoint ep = new Endpoint(LOOPBACK, 9000);

        assertThrows(NullPointerException.class, () -> new EastGuardClient(null, ep, "tokensvc", TIMEOUT));
        assertThrows(NullPointerException.class, () -> new EastGuardClient(ctx, null, "tokensvc", TIMEOUT));
        assertThrows(NullPointerException.class, () -> new EastGuardClient(ctx, ep, null, TIMEOUT));
        assertThrows(NullPointerException.class, () -> new EastGuardClient(ctx, ep, "tokensvc", null));
        assertThrows(IllegalArgumentException.class, () -> new EastGuardClient(ctx, ep, "tokensvc", Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new EastGuardClient(ctx, ep, "tokensvc", Duration.ofMillis(-10)));
    }

    public void testRequestLeaseValidation() {
        EastGuardClient client = new EastGuardClient(TestPki.context("workload-web-01"),
                new Endpoint(LOOPBACK, 9000), "tokensvc", TIMEOUT);
        assertThrows(IllegalArgumentException.class, () -> client.requestLease(null));
        assertThrows(IllegalArgumentException.class, () -> client.requestLease(""));
        assertThrows(IllegalArgumentException.class, () -> client.requestLease("Invalid_Service!"));
    }

    public void testConnectNullChecks() {
        EastGuardClient client = new EastGuardClient(TestPki.context("workload-web-01"),
                new Endpoint(LOOPBACK, 9000), "tokensvc", TIMEOUT);
        assertThrows(NullPointerException.class, () -> client.connect(null, "gateway-app-02", Bytes.copyOf(new byte[] {1, 2, 3})));
        assertThrows(NullPointerException.class, () -> client.connect(new Endpoint(LOOPBACK, 9001), "gateway-app-02", null));
    }

    public void testLeaseAndGatewayAdmitEndToEnd() throws Exception {
        try (EchoBackend backend = new EchoBackend(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 10).start()) {
            int backendPort = backend.port();
            EnforcementSnapshot snap = snapshot(backendPort);
            EnforcementView view = EnforcementView.fresh(snap);

            Clock clock = Clock.systemUTC();
            LeaseIssuer issuer = new LeaseIssuer(new PolicyEvaluator(clock), "lease-k1", TestPki.leaseSigningKey(),
                    TestPki.leaseVerifyKey(), new IssueLimiter(1_000, System::nanoTime), clock, new SecureRandom());

            TokenServer tokenServer = new TokenServer(TestPki.context("tokensvc"),
                    new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), () -> view, issuer,
                    new TokenServer.Limits(10, Duration.ofSeconds(2), 16));
            tokenServer.start();
            try (tokenServer) {
                Endpoint tokenEp = new Endpoint(LOOPBACK, tokenServer.port());

                CountingDecisionSink sink = new CountingDecisionSink();
                NioGateway gateway = new NioGateway("app-02", TestPki.context("gateway-app-02"),
                        new InetSocketAddress(InetAddress.getLoopbackAddress(), 0),
                        new InetSocketAddress(InetAddress.getLoopbackAddress(), backendPort),
                        () -> view, clock, GatewayLimits.defaults(), sink, BackendConnector.DIRECT);
                gateway.start();
                try (gateway) {
                    Endpoint gwEp = new Endpoint(LOOPBACK, gateway.port());

                    EastGuardClient client = new EastGuardClient(TestPki.context("workload-web-01"), tokenEp,
                            "127.0.0.1", TIMEOUT);

                    // 1. Request lease
                    IssuerReply reply = client.requestLease("app-02");
                    assertEquals(ReplyStatus.SUCCESS, reply.status());
                    assertTrue(reply.token() != null, "token present");

                    // 2. Connect to gateway
                    try (GatewaySession session = client.connect(gwEp, "127.0.0.1", reply.token())) {
                        assertTrue(session.allowed(), "session allowed");
                        assertEquals(ReplyStatus.SUCCESS, session.status());

                        byte[] payload = "Hello EastGuard!".getBytes();
                        session.output().write(payload);
                        session.output().flush();

                        byte[] echo = session.input().readNBytes(payload.length);
                        assertArrayEquals(payload, echo);

                        session.shutdownOutput();
                    }
                }
            }
        }
    }

    public void testCompositeConnectAndDeniedSessionBehavior() throws Exception {
        try (EchoBackend backend = new EchoBackend(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 10).start()) {
            int backendPort = backend.port();
            EnforcementSnapshot snap = snapshot(backendPort);
            EnforcementView view = EnforcementView.fresh(snap);

            Clock clock = Clock.systemUTC();
            LeaseIssuer issuer = new LeaseIssuer(new PolicyEvaluator(clock), "lease-k1", TestPki.leaseSigningKey(),
                    TestPki.leaseVerifyKey(), new IssueLimiter(1_000, System::nanoTime), clock, new SecureRandom());

            TokenServer tokenServer = new TokenServer(TestPki.context("tokensvc"),
                    new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), () -> view, issuer,
                    new TokenServer.Limits(10, Duration.ofSeconds(2), 16));
            tokenServer.start();
            try (tokenServer) {
                Endpoint tokenEp = new Endpoint(LOOPBACK, tokenServer.port());

                CountingDecisionSink sink = new CountingDecisionSink();
                NioGateway gateway = new NioGateway("app-02", TestPki.context("gateway-app-02"),
                        new InetSocketAddress(InetAddress.getLoopbackAddress(), 0),
                        new InetSocketAddress(InetAddress.getLoopbackAddress(), backendPort),
                        () -> view, clock, GatewayLimits.defaults(), sink, BackendConnector.DIRECT);
                gateway.start();
                try (gateway) {
                    Endpoint gwEp = new Endpoint(LOOPBACK, gateway.port());

                    EastGuardClient client = new EastGuardClient(TestPki.context("workload-web-01"), tokenEp,
                            "127.0.0.1", TIMEOUT);

                    // Composite connect success
                    try (GatewaySession session = client.connect("app-02", gwEp, "127.0.0.1")) {
                        assertTrue(session.allowed(), "session allowed");
                        assertEquals(ReplyStatus.SUCCESS, session.status());
                        session.setReadTimeout(Duration.ofSeconds(2));
                    }

                    // Composite connect for unknown/denied service
                    try (GatewaySession denied = client.connect("unknown-service", gwEp, "127.0.0.1")) {
                        assertFalse(denied.allowed(), "denied session not allowed");
                        assertEquals(ReplyStatus.DENY, denied.status());
                        assertThrows(IllegalStateException.class, denied::input);
                        assertThrows(IllegalStateException.class, denied::output);
                        assertThrows(IllegalStateException.class, denied::shutdownOutput);
                        assertThrows(IllegalStateException.class, () -> denied.setReadTimeout(Duration.ofSeconds(1)));
                    }
                }
            }
        }
    }

    public void testClientTimeoutFailsWithIOException() throws Exception {
        try (ServerSocket hangingServer = new ServerSocket(0)) {
            int port = hangingServer.getLocalPort();
            EastGuardClient client = new EastGuardClient(TestPki.context("workload-web-01"),
                    new Endpoint(LOOPBACK, port), "127.0.0.1", Duration.ofMillis(300));
            assertThrows(IOException.class, () -> client.requestLease("app-02"));
        }
    }
}
