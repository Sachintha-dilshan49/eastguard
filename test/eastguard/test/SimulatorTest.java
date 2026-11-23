package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.BootstrapState;
import eastguard.common.Config;
import eastguard.common.Edge;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.EnforcementView;
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
import eastguard.simulator.LegitClient;
import eastguard.simulator.PortScanner;
import eastguard.simulator.TokenReplayAttack;
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
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;

public final class SimulatorTest {
    private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
    private static final eastguard.common.IpAddress LOOPBACK_IP = eastguard.common.IpAddress.parse("127.0.0.1");
    private final Clock clock = Clock.systemUTC();
    private final AtomicReference<EnforcementView> state = new AtomicReference<>();
    private final CountingDecisionSink sink = new CountingDecisionSink();

    public SimulatorTest() {
        EnforcementSnapshot snap = snapshot(Set.of(new Edge("web-01", "app-02")));
        state.set(EnforcementView.fresh(snap));
    }

    private static EnforcementSnapshot snapshot(Set<Edge> edges) {
        Service app = new Service("app-02", "app-02", Endpoint.parse("127.0.0.1:9002"), "localhost",
                Endpoint.parse("127.0.0.1:7002"));
        eastguard.common.Policy policy = new eastguard.common.Policy(PolicyMode.ENFORCE, edges,
                eastguard.common.PilotScope.NONE, 1, Duration.ofSeconds(60));
        return new EnforcementSnapshot("eg-test", 1L, policy,
                java.util.Map.of("web-01", Workload.enabled("web-01"), "api-01", Workload.enabled("api-01")),
                java.util.Map.of("app-02", app), List.of(), List.of(), java.util.Map.of(),
                java.util.Map.of("lease-k1", TestPki.leaseVerifyKey()), Set.of());
    }

    private TokenServer tokenServer() throws IOException {
        LeaseIssuer issuer = new LeaseIssuer(new PolicyEvaluator(clock), "lease-k1", TestPki.leaseSigningKey(),
                TestPki.leaseVerifyKey(), new IssueLimiter(1_000, System::nanoTime), clock, new SecureRandom());
        TokenServer server = new TokenServer(TestPki.context("tokensvc"),
                new InetSocketAddress(LOOPBACK, 0), state::get, issuer,
                new TokenServer.Limits(8, Duration.ofSeconds(5), 16));
        server.start();
        return server;
    }

    private NioGateway gateway(EchoBackend echo, int decoyPort) throws IOException {
        Properties p = new Properties();
        NioGateway g = new NioGateway("app-02", TestPki.context("gateway-app-02"),
                new InetSocketAddress(LOOPBACK, 0), new InetSocketAddress(LOOPBACK, echo.port()),
                state::get, clock, GatewayLimits.from(Config.of(p, "test")), sink, BackendConnector.DIRECT);
        if (decoyPort > 0) {
            g.enableDecoy("decoy", new InetSocketAddress(LOOPBACK, decoyPort));
        }
        g.start();
        return g;
    }

    public void testPortScannerDetectsOpenAndClosedPorts() throws Exception {
        int openPort;
        try (EchoBackend echo = new EchoBackend(new InetSocketAddress(LOOPBACK, 0), 16).start()) {
            openPort = echo.port();
            PortScanner scanner = new PortScanner(LOOPBACK, Duration.ofMillis(200));
            PortScanner.PortResult rOpen = scanner.probe(openPort);
            assertEquals(PortScanner.PortState.OPEN, rOpen.state());

            int closedPort;
            try (ServerSocket tmp = new ServerSocket(0, 1, LOOPBACK)) {
                closedPort = tmp.getLocalPort();
            }
            PortScanner.PortResult rClosed = scanner.probe(closedPort);
            assertEquals(PortScanner.PortState.CLOSED, rClosed.state());
        }
    }

    public void testPortScannerDetectsDecoy() throws Exception {
        int decoyPort;
        try (ServerSocket tmp = new ServerSocket(0, 1, LOOPBACK)) {
            decoyPort = tmp.getLocalPort();
        }
        try (EchoBackend echo = new EchoBackend(new InetSocketAddress(LOOPBACK, 0), 16).start();
                NioGateway g = gateway(echo, decoyPort)) {
            PortScanner scanner = new PortScanner(LOOPBACK, Duration.ofMillis(300));
            PortScanner.PortResult r = scanner.probe(decoyPort);
            assertEquals(PortScanner.PortState.DECOY_HIT, r.state());
        }
    }

    public void testTokenReplayAttackIsBlocked() throws Exception {
        try (EchoBackend echo = new EchoBackend(new InetSocketAddress(LOOPBACK, 0), 16).start();
                NioGateway g = gateway(echo, 0);
                TokenServer ts = tokenServer()) {

            SSLContext victimCtx = TestPki.context("workload-web-01");
            SSLContext attackerCtx = TestPki.context("workload-api-01");
            Endpoint issuerEp = new Endpoint(LOOPBACK_IP, ts.port());
            Endpoint gwEp = new Endpoint(LOOPBACK_IP, g.port());

            TokenReplayAttack attack = new TokenReplayAttack(victimCtx, attackerCtx,
                    issuerEp, "localhost", gwEp, "localhost", "app-02", Duration.ofSeconds(5));

            TokenReplayAttack.AttackResult res = attack.execute();
            assertTrue(res.attackBlocked(), "replay attack must be blocked");
            assertEquals(ReplyStatus.DENY, res.gatewayReply());
            assertEquals(0L, echo.accepted());
        }
    }

    public void testLegitClientExchange() throws Exception {
        try (EchoBackend echo = new EchoBackend(new InetSocketAddress(LOOPBACK, 0), 16).start();
                NioGateway g = gateway(echo, 0);
                TokenServer ts = tokenServer()) {

            LegitClient.Options opts = new LegitClient.Options(
                    TestPki.p12("workload-web-01"),
                    TestPki.trustStore(),
                    TestPki.storePass(),
                    new Endpoint(LOOPBACK_IP, ts.port()),
                    "localhost",
                    new Endpoint(LOOPBACK_IP, g.port()),
                    "localhost",
                    "app-02",
                    Duration.ofSeconds(5));

            LegitClient client = new LegitClient(opts);
            LegitClient.Result res = client.exchange("ping legit payload");
            assertTrue(res.success(), "legitimate client exchange should succeed");
            assertEquals(ReplyStatus.SUCCESS, res.status());
            assertEquals("ping legit payload", res.response());
        }
    }
}
