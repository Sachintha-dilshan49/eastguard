package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Config;
import eastguard.common.Edge;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.PolicyMode;
import eastguard.tokensvc.TokenConfig;
import eastguard.tokensvc.TokenServer;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.Properties;

/** The shipped example config parses, wires a server, and the validator rejects bad input. */
public final class TokenConfigTest {
    private static final Path EXAMPLE = Path.of("config", "token.properties.example");

    /** The example file with key paths redirected to the test PKI. */
    private static Properties example() throws Exception {
        Properties p = new Properties();
        try (Reader r = Files.newBufferedReader(EXAMPLE, StandardCharsets.UTF_8)) {
            p.load(r);
        }
        Path dir = TestPki.dir();
        p.setProperty("tls.keyStore", dir.resolve("tokensvc.p12").toString());
        p.setProperty("tls.trustStore", dir.resolve("truststore.p12").toString());
        p.setProperty("tls.passwordEnv", "EASTGUARD_TEST_PKI_STORE_PASS");
        p.setProperty("tls.passwordFile", dir.resolve("store.pass").toString());
        p.setProperty("lease.keyStore", dir.resolve("lease-signer.p12").toString());
        p.setProperty("lease.passwordEnv", "EASTGUARD_TEST_PKI_SIGNER_PASS");
        p.setProperty("lease.passwordFile", dir.resolve("signer.pass").toString());
        p.setProperty("bootstrap.tokenKey.lease-k1.cert", dir.resolve("lease-k1.cer").toString());
        return p;
    }

    private static TokenConfig parse(Properties p) {
        return TokenConfig.from(Config.of(p, "test"));
    }

    public void testExampleConfigParses() throws Exception {
        TokenConfig c = parse(example());
        assertEquals(Endpoint.parse("127.0.0.1:8443"), c.listen());
        assertEquals("lease-k1", c.keyId());
        assertEquals(new TokenServer.Limits(64, Duration.ofSeconds(5), 128), c.limits());
        EnforcementSnapshot s = c.bootstrap();
        assertEquals("eg-demo", s.clusterId());
        assertEquals(1, s.revision());
        assertEquals(PolicyMode.ENFORCE, s.policy().mode());
        assertEquals(Duration.ofSeconds(60), s.policy().defaultLeaseLength());
        assertEquals(java.util.Set.of(new Edge("web-01", "app-02")), s.policy().approvedEdges());
        assertTrue(s.workloads().get("api-01").enabled(), "api-01 registered");
        assertEquals(Endpoint.parse("127.0.0.1:7002"), s.services().get("app-02").backend());
        assertEquals(TestPki.leaseVerifyKey(), s.tokenKeys().get("lease-k1"));
    }

    public void testServerWiresFromConfig() throws Exception {
        TokenServer server = TokenServer.create(parse(example()), Clock.systemUTC());
        server.close(); // never started; close must still be safe
    }

    public void testSigningKeyMustMatchPublishedKey() throws Exception {
        Properties p = example();
        p.setProperty("lease.keyId", "lease-k9"); // not in bootstrap.tokenKeys
        assertThrows(IllegalStateException.class, () -> TokenServer.create(parse(p), Clock.systemUTC()));
    }

    public void testTokenKeyMustBeEd25519() throws Exception {
        Properties p = example();
        p.setProperty("bootstrap.tokenKey.lease-k1.cert", TestPki.dir().resolve("ca.cer").toString());
        assertThrows(IllegalArgumentException.class, () -> parse(p));
    }

    public void testRejectsUnknownMissingAndOutOfRange() throws Exception {
        Properties typo = example();
        typo.setProperty("limits.maxConcurent", "5");
        assertTrue(assertThrows(IllegalArgumentException.class, () -> parse(typo)).getMessage()
                .contains("limits.maxConcurent"), "names the unknown key");

        Properties missing = example();
        missing.remove("listen");
        assertThrows(IllegalArgumentException.class, () -> parse(missing));

        for (String[] kv : new String[][] {
                {"lease.defaultSeconds", "61"}, {"limits.deadlineMillis", "5"}, {"listen", "localhost:8443"},
                {"bootstrap.mode", "PERMISSIVE"}, {"cluster.id", "EG Demo"}, {"bootstrap.revision", "-1"}}) {
            Properties bad = example();
            bad.setProperty(kv[0], kv[1]);
            assertThrows(IllegalArgumentException.class, () -> parse(bad));
        }
    }

    public void testEdgesMustReferenceKnownEntities() throws Exception {
        for (String edges : new String[] {"web-01>db-09", "ghost>app-02", "web-01", "web-01>app-02,web-01>app-02"}) {
            Properties p = example();
            p.setProperty("bootstrap.edges", edges);
            assertThrows(IllegalArgumentException.class, () -> parse(p));
        }
        Properties none = example();
        none.setProperty("bootstrap.edges", "");
        assertEquals(0, parse(none).bootstrap().policy().approvedEdges().size());
    }

    public void testDuplicateKeysInFileRejected() throws Exception {
        Path f = Files.createTempFile("eg-dup", ".properties");
        try {
            Files.writeString(f, "cluster.id=a\ncluster.id=b\n");
            assertThrows(IllegalArgumentException.class, () -> Config.load(f));
        } finally {
            Files.delete(f);
        }
    }

    public void testExampleFileHoldsNoSecrets() throws Exception {
        String text = Files.readString(EXAMPLE).toLowerCase();
        assertFalse(text.matches("(?s).*(password|pass|secret)\\s*=.*"), "no password values in the example");
    }
}
