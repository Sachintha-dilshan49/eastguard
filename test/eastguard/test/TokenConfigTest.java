package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.BootstrapState;
import eastguard.common.Config;
import eastguard.common.Edge;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.EnforcementView;
import eastguard.common.PolicyMode;
import eastguard.tokensvc.TokenConfig;
import eastguard.tokensvc.TokenServer;
import java.io.Reader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.Properties;
import java.util.Set;

/**
 * The shipped token-service and bootstrap example configs parse, wire a server, and the validators reject bad
 * input. Since Task 6 the token service gets its state from the control plane; the bootstrap file only seeds
 * the control-plane journal (and the standalone demos).
 */
public final class TokenConfigTest {
    private static final Path EXAMPLE = Path.of("config", "token.properties.example");
    private static final Path BOOTSTRAP = Path.of("config", "bootstrap.properties.example");

    private static Properties load(Path file) throws Exception {
        Properties p = new Properties();
        try (Reader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            p.load(r);
        }
        return p;
    }

    /** The token example with key paths redirected to the test PKI. */
    private static Properties example() throws Exception {
        Properties p = load(EXAMPLE);
        Path dir = TestPki.dir();
        p.setProperty("tls.keyStore", dir.resolve("tokensvc.p12").toString());
        p.setProperty("tls.trustStore", dir.resolve("truststore.p12").toString());
        p.setProperty("tls.passwordEnv", "EASTGUARD_TEST_PKI_STORE_PASS");
        p.setProperty("tls.passwordFile", dir.resolve("store.pass").toString());
        p.setProperty("lease.keyStore", dir.resolve("lease-signer.p12").toString());
        p.setProperty("lease.passwordEnv", "EASTGUARD_TEST_PKI_SIGNER_PASS");
        p.setProperty("lease.passwordFile", dir.resolve("signer.pass").toString());
        return p;
    }

    /** The bootstrap example with the lease certificate redirected to the test PKI. */
    private static Properties bootstrap() throws Exception {
        Properties p = load(BOOTSTRAP);
        p.setProperty("bootstrap.tokenKey.lease-k1.cert", TestPki.dir().resolve("lease-k1.cer").toString());
        return p;
    }

    private static TokenConfig parse(Properties p) {
        return TokenConfig.from(Config.of(p, "test"));
    }

    private static EnforcementSnapshot boot(Properties p) {
        return BootstrapState.snapshot(Config.of(p, "test"));
    }

    // ---- token service ----

    public void testExampleConfigParses() throws Exception {
        TokenConfig c = parse(example());
        assertEquals(Endpoint.parse("127.0.0.1:8443"), c.listen());
        assertEquals("lease-k1", c.keyId());
        assertEquals(new TokenServer.Limits(64, Duration.ofSeconds(5), 128), c.limits());
        assertEquals(Endpoint.parse("127.0.0.1:1099"), c.control().registry());
        assertEquals("tokensvc", c.control().principal());
        assertEquals("eg-demo", c.sync().clusterId());
        assertEquals(Duration.ofSeconds(5), c.sync().maxAge());
    }

    public void testServerWiresFromConfig() throws Exception {
        TokenServer server = TokenServer.create(parse(example()), Clock.systemUTC(),
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), () -> EnforcementView.NOT_READY);
        server.close(); // never started; close must still be safe
    }

    public void testRejectsUnknownMissingOutOfRangeAndStaleKeys() throws Exception {
        Properties typo = example();
        typo.setProperty("limits.maxConcurent", "5");
        assertTrue(assertThrows(IllegalArgumentException.class, () -> parse(typo)).getMessage()
                .contains("limits.maxConcurent"), "names the unknown key");

        for (String key : new String[] {"listen", "control.registry", "control.principal", "cluster.id"}) {
            Properties missing = example();
            missing.remove(key);
            assertThrows(IllegalArgumentException.class, () -> parse(missing));
        }
        for (String[] kv : new String[][] {
                {"limits.deadlineMillis", "5"}, {"listen", "localhost:8443"}, {"cluster.id", "EG Demo"},
                {"control.objectPort", "0"}, {"state.pollMillis", "1"},
                {"bootstrap.edges", "web-01>app-02"}, {"lease.defaultSeconds", "60"}}) { // policy lives in the control plane now
            Properties bad = example();
            bad.setProperty(kv[0], kv[1]);
            assertThrows(IllegalArgumentException.class, () -> parse(bad));
        }
    }

    // ---- bootstrap state (seeds the control-plane journal) ----

    public void testBootstrapExampleIsMinimalDenyByDefault() throws Exception {
        EnforcementSnapshot s = boot(bootstrap());
        assertEquals("eg-demo", s.clusterId());
        assertEquals(1, s.revision());
        assertEquals(PolicyMode.ENFORCE, s.policy().mode());
        assertEquals(Duration.ofSeconds(60), s.policy().defaultLeaseLength());
        assertEquals(Set.of(new Edge("web-01", "app-02")), s.policy().approvedEdges());
        assertTrue(s.workloads().get("api-01").enabled(), "api-01 registered");
        assertEquals(Endpoint.parse("127.0.0.1:7002"), s.services().get("app-02").backend());
        assertEquals(TestPki.leaseVerifyKey(), s.tokenKeys().get("lease-k1"));
    }

    public void testBootstrapTokenKeyMustBeEd25519() throws Exception {
        Properties p = bootstrap();
        p.setProperty("bootstrap.tokenKey.lease-k1.cert", TestPki.dir().resolve("ca.cer").toString());
        assertThrows(IllegalArgumentException.class, () -> boot(p));
    }

    public void testBootstrapRejectsBadValues() throws Exception {
        for (String[] kv : new String[][] {
                {"lease.defaultSeconds", "61"}, {"bootstrap.mode", "PERMISSIVE"}, {"cluster.id", "EG Demo"},
                {"bootstrap.revision", "-1"}}) {
            Properties bad = bootstrap();
            bad.setProperty(kv[0], kv[1]);
            assertThrows(IllegalArgumentException.class, () -> boot(bad));
        }
    }

    public void testBootstrapEdgesMustReferenceKnownEntities() throws Exception {
        for (String edges : new String[] {"web-01>db-09", "ghost>app-02", "web-01", "web-01>app-02,web-01>app-02"}) {
            Properties p = bootstrap();
            p.setProperty("bootstrap.edges", edges);
            assertThrows(IllegalArgumentException.class, () -> boot(p));
        }
        Properties none = bootstrap();
        none.setProperty("bootstrap.edges", "");
        assertEquals(0, boot(none).policy().approvedEdges().size());
    }

    // ---- files ----

    public void testDuplicateKeysInFileRejected() throws Exception {
        Path f = Files.createTempFile("eg-dup", ".properties");
        try {
            Files.writeString(f, "cluster.id=a\ncluster.id=b\n");
            assertThrows(IllegalArgumentException.class, () -> Config.load(f));
        } finally {
            Files.delete(f);
        }
    }

    public void testExampleFilesHoldNoSecrets() throws Exception {
        for (String name : new String[] {"token.properties.example", "bootstrap.properties.example",
                "control.properties.example", "gateway-app-02.properties.example"}) {
            String text = Files.readString(Path.of("config", name)).toLowerCase();
            assertFalse(text.matches("(?s).*\\n(\\w+\\.)*(password|pass|secret)\\s*=.*"), "no secret values in " + name);
        }
    }
}
