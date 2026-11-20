package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.client.EastGuardClient;
import eastguard.client.GatewaySession;
import eastguard.common.Bytes;
import eastguard.common.Config;
import eastguard.common.Edge;
import eastguard.common.Endpoint;
import eastguard.common.IpAddress;
import eastguard.common.Lease;
import eastguard.common.LeaseCodec;
import eastguard.common.ReasonCode;
import eastguard.common.ReplyStatus;
import eastguard.common.Selector;
import eastguard.common.Verdict;
import eastguard.control.ControlClient;
import eastguard.control.ControlPlaneImpl;
import eastguard.control.ControlServer;
import eastguard.control.Dto;
import eastguard.control.Journal;
import eastguard.control.StateSync;
import eastguard.demos.EchoBackend;
import eastguard.gateway.BackendConnector;
import eastguard.gateway.CountingDecisionSink;
import eastguard.gateway.GatewayLimits;
import eastguard.gateway.NioGateway;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Properties;
import java.util.function.BooleanSupplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Control plane, RMI, state sync and gateway together (spec §6.2, §6.3, §10): a committed quarantine closes the
 * matching live session through the sync path, release makes old leases fail on the watermark, and losing the
 * control plane denies and closes sessions once freshness expires.
 */
public final class ControlE2ETest {
    private static final Logger QUIET = Logger.getLogger("eastguard");
    private static final IpAddress LOOPBACK = IpAddress.parse("127.0.0.1");
    private static final InetAddress LO = InetAddress.getLoopbackAddress();
    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final Selector WEB = Selector.identity("web-01");

    private final ControlFixtures fx = new ControlFixtures();
    private final CountingDecisionSink sink = new CountingDecisionSink();
    private final SecureRandom random = new SecureRandom();
    private Journal journal;
    private ControlServer server;
    private StateSync sync;
    private EchoBackend echo;
    private NioGateway gateway;
    private int registryPort;
    private int objectPort;

    public ControlE2ETest() {
        QUIET.setLevel(Level.SEVERE); // quarantine closes, sync failures and denials log on purpose
    }

    private void stop() throws IOException {
        if (gateway != null) {
            gateway.close();
        }
        if (sync != null) {
            sync.close();
        }
        if (echo != null) {
            echo.close();
        }
        if (server != null) {
            server.close();
        }
        if (journal != null) {
            journal.close();
        }
    }

    private ControlClient admin(String principal) {
        return new ControlClient(new Endpoint(LOOPBACK, registryPort), objectPort, fx.cred(principal),
                TestPki.context("tokensvc"));
    }

    private Bytes lease(String sub, String store, long revision) {
        long now = System.currentTimeMillis();
        byte[] jti = new byte[Lease.JTI_LENGTH];
        random.nextBytes(jti);
        Lease l = new Lease("eg-test", "lease-k1", sub, "app-02", LOOPBACK, TestPki.fingerprint(store), now,
                now + 60_000, Bytes.copyOf(jti), revision);
        return Bytes.copyOf(LeaseCodec.issue(l, TestPki.leaseSigningKey()));
    }

    private GatewaySession connect(String store, Bytes token) throws IOException {
        return new EastGuardClient(TestPki.context(store), new Endpoint(LOOPBACK, 1), "127.0.0.1", TIMEOUT)
                .connect(new Endpoint(LOOPBACK, gateway.port()), "127.0.0.1", token);
    }

    private static void roundTrip(GatewaySession s, String text) throws IOException {
        byte[] msg = text.getBytes(StandardCharsets.UTF_8);
        s.output().write(msg);
        s.output().flush();
        s.setReadTimeout(TIMEOUT);
        assertArrayEquals(msg, s.input().readNBytes(msg.length));
    }

    private static boolean closedWithoutReply(InputStream in) {
        try {
            return in.read() == -1;
        } catch (IOException e) {
            return true;
        }
    }

    private static void await(BooleanSupplier c, String what) throws InterruptedException {
        long end = System.nanoTime() + 10_000_000_000L;
        while (!c.getAsBoolean()) {
            if (System.nanoTime() > end) {
                fail("timed out waiting for " + what);
            }
            Thread.sleep(10);
        }
    }

    private long revision() {
        return sync.get().snapshot().revision();
    }

    public void testQuarantineAndReleaseReachTheGatewayThroughSync() throws Exception {
        try {
            start(Duration.ofMillis(200));
            ControlClient admin = admin("admin");
            ControlClient operator = admin("operator");
            assertTrue(admin.replacePolicy("edit-1", 1, List.of(new Edge("web-01", "app-02"),
                    new Edge("api-01", "app-02")), "allow api-01").ok(), "policy edit");
            await(() -> revision() == 2, "gateway installs revision 2");

            Bytes oldWebLease = lease("web-01", "workload-web-01", 2);
            GatewaySession web = connect("workload-web-01", oldWebLease);
            GatewaySession api = connect("workload-api-01", lease("api-01", "workload-api-01", 2));
            roundTrip(web, "web");
            roundTrip(api, "api");

            long t0 = System.nanoTime();
            Dto.MutationResult q = operator.quarantine("q-1", List.of(WEB), Duration.ofMinutes(5), "decoy touch");
            assertTrue(q.ok(), "quarantine committed: " + q);
            web.setReadTimeout(Duration.ofSeconds(8));
            assertTrue(closedWithoutReply(web.input()), "quarantined session closed via sync + reevaluate");
            long ms = (System.nanoTime() - t0) / 1_000_000;
            assertTrue(ms < 3_000, "closed " + ms + " ms after commit (poll 200 ms)");
            roundTrip(api, "api still fine"); // unrelated session untouched
            assertEquals(ReplyStatus.QUARANTINED, connect("workload-web-01", oldWebLease).status());

            Dto.MutationResult r = operator.release("r-1", List.of(WEB), "remediated");
            assertTrue(r.ok(), "released");
            await(() -> revision() == r.revision(), "gateway installs the release");
            long supersededBefore = sink.count(ReasonCode.LEASE_SUPERSEDED);
            assertEquals(ReplyStatus.DENY, connect("workload-web-01", oldWebLease).status());
            assertEquals(supersededBefore + 1, sink.count(ReasonCode.LEASE_SUPERSEDED)); // watermark
            GatewaySession fresh = connect("workload-web-01", lease("web-01", "workload-web-01", r.revision()));
            assertEquals(ReplyStatus.SUCCESS, fresh.status());
            roundTrip(fresh, "back");
            fresh.close();
            api.close();
        } finally {
            stop();
        }
    }

    public void testControlPlaneLossDeniesAndClosesAfterFreshnessExpires() throws Exception {
        try {
            start(Duration.ofMillis(200));
            GatewaySession s = connect("workload-web-01", lease("web-01", "workload-web-01", 1));
            roundTrip(s, "before");
            server.close(); // the control plane disappears
            long t0 = System.nanoTime();
            s.setReadTimeout(Duration.ofSeconds(15));
            assertTrue(closedWithoutReply(s.input()), "live session closed when state went stale");
            long ms = (System.nanoTime() - t0) / 1_000_000;
            assertTrue(ms >= 4_000 && ms <= 6_500, "closed " + ms + " ms after the loss (freshness 5 s)");
            assertEquals(ReplyStatus.UNAVAILABLE, connect("workload-web-01", lease("web-01", "workload-web-01", 1)).status());
            assertTrue(sink.count(ReasonCode.NOT_READY) >= 1, "denied NOT_READY");
            assertEquals(1, sink.count(Verdict.ALLOW));
        } finally {
            stop();
        }
    }

    /** Control plane on fresh RMI ports, a gateway whose state comes from it over RMI, an echo backend. */
    private void start(Duration poll) throws Exception {
        registryPort = RmiTest.freePort();
        objectPort = RmiTest.freePort();
        journal = Journal.open(ControlFixtures.freshJournal());
        ControlPlaneImpl impl = ControlPlaneImpl.open(journal, Clock.systemUTC(), fx.credentials,
                ControlPlaneImpl.Settings.defaults());
        assertTrue(impl.bootstrap(ControlFixtures.initial(TestPki.leaseVerifyKey()), "admin", "test state").ok(), "bootstrap");
        server = ControlServer.start(impl, TestPki.context("control"), "127.0.0.1", registryPort, objectPort, null);
        ControlClient gw = admin("gw-app-02");
        sync = new StateSync("e2e", gw::sync, new StateSync.Settings("eg-test", poll, Duration.ofSeconds(5)),
                System::nanoTime);
        echo = new EchoBackend(new InetSocketAddress(LO, 0), 16).start();
        gateway = new NioGateway("app-02", TestPki.context("gateway-app-02"), new InetSocketAddress(LO, 0),
                new InetSocketAddress(LO, echo.port()), sync, Clock.systemUTC(),
                GatewayLimits.from(Config.of(new Properties(), "test")), sink, BackendConnector.DIRECT);
        sync.addListener(gateway::reevaluate);
        gateway.start();
        sync.start();
        await(() -> sync.get().usable(), "first sync");
    }
}
