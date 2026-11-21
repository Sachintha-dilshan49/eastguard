package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Endpoint;
import eastguard.common.IpAddress;
import eastguard.common.Selector;
import eastguard.common.SnapshotCodec;
import eastguard.control.ControlClient;
import eastguard.control.ControlPlane;
import eastguard.control.ControlPlaneImpl;
import eastguard.control.ControlServer;
import eastguard.control.Dto;
import eastguard.control.Dto.ErrorCode;
import eastguard.control.Journal;
import eastguard.control.RmiFilter;
import eastguard.control.TlsRmiClientSocketFactory;
import eastguard.tokensvc.TlsContextFactory;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputFilter;
import java.lang.invoke.MethodType;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.ServerSocket;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.RemoteObject;
import java.rmi.server.RemoteRef;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLSocket;

/** The control plane over real RMI: TLS on registry and object, credentials, deserialization filter, endpoints. */
public final class RmiTest {
    private static final Logger QUIET = Logger.getLogger("eastguard.control");
    private static final IpAddress LOOPBACK = IpAddress.parse("127.0.0.1");

    private final ControlFixtures fx = new ControlFixtures();
    private final int registryPort;
    private final int objectPort;

    public RmiTest() throws IOException {
        QUIET.setLevel(Level.OFF); // unauthorized calls and filter rejections log on purpose
        registryPort = freePort();
        objectPort = freePort();
    }

    static int freePort() throws IOException {
        try (ServerSocket s = new ServerSocket(0)) {
            return s.getLocalPort();
        }
    }

    private interface Body {
        void run(ControlServer server) throws Exception;
    }

    private void withServer(Body body) throws Exception {
        try (Journal j = Journal.open(ControlFixtures.freshJournal())) {
            ControlPlaneImpl impl = fx.bootstrapped(j);
            ControlServer server = ControlServer.start(impl, TestPki.context("control"), "127.0.0.1", registryPort,
                    objectPort, null);
            try {
                body.run(server);
            } finally {
                server.close();
            }
        }
    }

    private ControlClient client(String principal) {
        return new ControlClient(new Endpoint(LOOPBACK, registryPort), objectPort, fx.cred(principal),
                TestPki.context("tokensvc"));
    }

    public void testSyncAndMutationsOverTls() throws Exception {
        withServer(server -> {
            ControlClient gw = client("gw-app-02");
            Dto.SyncResponse full = gw.sync(0);
            assertTrue(full.ok() && !full.unchanged(), "full snapshot over RMI: " + full);
            assertEquals(1, SnapshotCodec.decode(full.snapshot().toArray()).revision());
            assertTrue(gw.sync(1).unchanged(), "exact acknowledgement");

            ControlClient op = client("operator");
            Dto.MutationResult q = op.quarantine("q-1", List.of(Selector.identity("web-01")), Duration.ofMinutes(5),
                    "scan from web-01");
            assertTrue(q.ok(), "quarantine committed: " + q);
            Dto.SyncResponse after = gw.sync(1);
            assertEquals(1, SnapshotCodec.decode(after.snapshot().toArray()).restrictions().size());

            Dto.DashboardView d = client("viewer").getDashboard(0, 10);
            assertEquals("QUARANTINE", d.audit().get(0).operation());
            assertEquals(1, d.restrictions().size());
            assertTrue(ObjectInputFilter.Config.getSerialFilter() instanceof RmiFilter, "client filter installed");
        });
    }

    /** Detector DTOs (proposal, observation batch) and the alert view pass the real deserialization filters. */
    public void testDetectorCallsOverRmi() throws Exception {
        try (Journal j = Journal.open(ControlFixtures.freshJournal())) {
            ControlPlaneImpl impl = ControlPlaneImpl.open(j, fx.clock, fx.credentials,
                    ControlPlaneImpl.Settings.defaults().withAutomation(DetectorControlTest.automation(20)));
            assertTrue(impl.bootstrap(ControlFixtures.initial(Fixtures.LEASE_KEYS.getPublic()), "admin", "x").ok(), "boot");
            ControlServer server = ControlServer.start(impl, TestPki.context("control"), "127.0.0.1", registryPort,
                    objectPort, null);
            try {
                ControlClient det = client("detector");
                Dto.MutationResult p = det.proposeAction("det-rmi-1", Dto.ActionType.QUARANTINE,
                        List.of(Selector.identity("web-01")), Duration.ofMinutes(5), 130, List.of("DECOY", "SCAN"),
                        List.of("gw-app-02/0a0b0c0d/17"));
                assertTrue(p.ok(), "proposal committed over RMI: " + p);
                Dto.MutationResult o = det.recordObservations("obs-rmi-1", List.of(new Dto.Observation(
                        new eastguard.common.Edge("api-01", "app-02"), fx.clock.millis(), fx.clock.millis(), 2)));
                assertTrue(o.ok(), "observations accepted over RMI: " + o);
                assertEquals("merged=0 outOfScope=1", o.message()); // ENFORCE mode: not a pilot edge
                Dto.DashboardView d = client("viewer").getDashboard(0, 10);
                assertEquals(1, d.alerts().size());
                assertEquals("det-rmi-1", d.alerts().get(0).id());
                assertEquals(Dto.ActionType.QUARANTINE, d.alerts().get(0).action());
                assertEquals(0, client("viewer").getPolicy(null).candidates().size());
            } finally {
                server.close();
            }
        }
    }

    /** Task 9 DTOs (draft view, freeze, role and refused alerts in the dashboard) pass the real filters. */
    public void testLearningDraftAndFreezeOverRmi() throws Exception {
        try (Journal j = Journal.open(ControlFixtures.freshJournal())) {
            ControlPlaneImpl impl = ControlPlaneImpl.open(j, fx.clock, fx.credentials, ControlPlaneImpl.Settings.defaults());
            assertTrue(impl.bootstrap(LearningFreezeTest.learning(), "admin", "x").ok(), "boot");
            ControlServer server = ControlServer.start(impl, TestPki.context("control"), "127.0.0.1", registryPort,
                    objectPort, null);
            try {
                long t = fx.clock.millis();
                assertTrue(client("detector").recordObservations("obs-1", List.of(new Dto.Observation(
                        LearningFreezeTest.API_APP02, t, t, 4))).ok(), "observation");
                assertEquals(ErrorCode.UNAVAILABLE, client("detector").proposeAction("p-1", Dto.ActionType.QUARANTINE,
                        List.of(Selector.identity("web-01")), Duration.ofMinutes(1), 130, List.of("DECOY"),
                        List.of("gw-app-02/0a/1")).error()); // alert-only
                ControlClient admin = client("admin");
                Dto.LearningDraftView v = admin.getLearningDraft();
                assertTrue(v.ok(), "draft over RMI: " + v);
                assertEquals(1, v.candidates().size());
                Dto.DashboardView d = client("viewer").getDashboard(0, 10);
                assertEquals(eastguard.control.Role.VIEWER, d.role());
                assertEquals(List.of("api-01", "web-01"), d.workloads());
                assertFalse(d.alerts().get(0).committed(), "refused proposal over RMI");
                assertEquals(ErrorCode.CONFLICT, admin.freezeBaseline("f-0", v.policyRevision(), v.draftVersion() + 1,
                        v.proposedBaseline(), "stale draft").error());
                Dto.MutationResult f = admin.freezeBaseline("f-1", v.policyRevision(), v.draftVersion(),
                        v.proposedBaseline(), "reviewed baseline");
                assertTrue(f.ok(), "freeze over RMI: " + f);
                assertEquals(eastguard.common.PolicyMode.ENFORCE, admin.getPolicy(null).mode());
            } finally {
                server.close();
            }
        }
    }

    public void testRoleAndCredentialCheckedOverRmi() throws Exception {
        withServer(server -> {
            assertEquals(ErrorCode.UNAUTHORIZED, client("viewer").sync(0).error());
            assertEquals(ErrorCode.UNAUTHORIZED, client("gw-app-02").quarantine("q-1",
                    List.of(Selector.identity("web-01")), Duration.ofMinutes(1), "x").error());
            ControlClient forged = new ControlClient(new Endpoint(LOOPBACK, registryPort), objectPort,
                    new Dto.Credential("admin", ControlFixtures.secret()), TestPki.context("tokensvc"));
            assertEquals(ErrorCode.UNAUTHORIZED, forged.getPolicy(null).error());
            assertEquals(3, server.impl().unauthorizedCalls());
        });
    }

    /** sun.rmi.server.Util.computeMethodHash: SHA-1 of writeUTF(name + descriptor), first 8 bytes little-endian. */
    private static long methodHash(Method m) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA");
        DataOutputStream out = new DataOutputStream(new DigestOutputStream(new ByteArrayOutputStream(), md));
        out.writeUTF(m.getName() + MethodType.methodType(m.getReturnType(), m.getParameterTypes()).toMethodDescriptorString());
        out.flush();
        byte[] h = md.digest();
        long hash = 0;
        for (int i = 0; i < 8; i++) {
            hash += ((long) (h[i] & 0xFF)) << (i * 8);
        }
        return hash;
    }

    public void testDeserializationFilterRejectsUnexpectedArguments() throws Exception {
        withServer(server -> {
            client("gw-app-02"); // installs the client TLS context and endpoint allowlist
            ControlPlane stub = (ControlPlane) LocateRegistry.getRegistry("127.0.0.1", registryPort,
                    new TlsRmiClientSocketFactory()).lookup(ControlPlane.NAME);
            RemoteRef ref = ((RemoteObject) Proxy.getInvocationHandler(stub)).getRef();
            Method sync = ControlPlane.class.getMethod("sync", Dto.SyncRequest.class);
            long hash = methodHash(sync);
            // Sanity: the raw path works with a legitimate argument.
            Object ok = ref.invoke(stub, sync, new Object[] {new Dto.SyncRequest(fx.cred("gw-app-02"), 0)}, hash);
            assertTrue(((Dto.SyncResponse) ok).ok(), "raw invocation reaches the server");

            Object deep = new Object[0];
            for (int i = 0; i < 40; i++) {
                deep = new Object[] {deep};
            }
            Object[] hostile = {
                    new HashMap<>(java.util.Map.of("not", "allowed")), // a class outside the allowlist
                    deep,                                               // graph depth
                    new byte[200_000],                                  // array length
            };
            for (Object h : hostile) {
                long before = RmiFilter.rejected();
                assertThrows(RemoteException.class, () -> ref.invoke(stub, sync, new Object[] {h}, hash));
                assertTrue(RmiFilter.rejected() > before, "rejected by the filter: " + h.getClass().getSimpleName());
            }
            assertEquals(0, server.impl().unauthorizedCalls()); // never reached the implementation
        });
    }

    public void testUnexpectedStubEndpointsAreRefused() throws Exception {
        withServer(server -> {
            client("gw-app-02");
            TlsRmiClientSocketFactory csf = new TlsRmiClientSocketFactory();
            IOException wrongPort = assertThrows(IOException.class, () -> csf.createSocket("127.0.0.1", freePort()));
            assertTrue(wrongPort.getMessage().contains("unexpected RMI endpoint"), wrongPort.getMessage());
            IOException name = assertThrows(IOException.class, () -> csf.createSocket("localhost", registryPort));
            assertTrue(name.getMessage().contains("non-numeric"), name.getMessage());
            csf.createSocket("127.0.0.1", registryPort).close(); // the configured endpoint is fine
        });
    }

    public void testRegistryRequiresATrustedClientCertificate() throws Exception {
        withServer(server -> {
            try (SSLSocket s = TlsContextFactory.connect(TestPki.context("untrusted-web-01"),
                    new Endpoint(LOOPBACK, registryPort), "127.0.0.1", Duration.ofSeconds(3))) {
                // TLS 1.3: the server rejects the certificate after the client's side of the handshake.
                s.getOutputStream().write(new byte[] {0x4a, 0x52, 0x4d, 0x49, 0, 2, 0x4b}); // JRMP header
                s.getOutputStream().flush();
                try {
                    assertEquals(-1, s.getInputStream().read());
                } catch (IOException expected) {
                    // alert or reset: no RMI service either way
                }
            } catch (IOException expected) {
                // handshake failure surfaced on connect
            }
        });
    }
}
