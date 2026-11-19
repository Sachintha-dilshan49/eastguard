package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Config;
import eastguard.common.Endpoint;
import eastguard.gateway.GatewayConfig;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Properties;

/** Gateway configuration loading against a bootstrap file that uses the test PKI's lease key. */
public final class GatewayConfigTest {
    private static Path bootstrapFile() throws IOException {
        Path f = Path.of("out", "test-gateway-bootstrap.properties");
        String cert = TestPki.dir().resolve("lease-k1.cer").toString().replace('\\', '/');
        Files.writeString(f, String.join("\n",
                "cluster.id=eg-test",
                "lease.defaultSeconds=60",
                "bootstrap.workloads=web-01",
                "bootstrap.services=app-02",
                "bootstrap.service.app-02.gateway=app-02",
                "bootstrap.service.app-02.listener=127.0.0.1:9002",
                "bootstrap.service.app-02.serverName=127.0.0.1",
                "bootstrap.service.app-02.backend=127.0.0.1:7002",
                "bootstrap.edges=web-01>app-02",
                "bootstrap.tokenKeys=lease-k1",
                "bootstrap.tokenKey.lease-k1.cert=" + cert,
                ""), StandardCharsets.UTF_8);
        return f;
    }

    private static Properties base() throws IOException {
        Properties p = new Properties();
        p.setProperty("gateway.service", "app-02");
        p.setProperty("listen", "127.0.0.1:9002");
        p.setProperty("backend", "127.0.0.1:7002");
        p.setProperty("tls.keyStore", "keys/gateway-app-02.p12");
        p.setProperty("tls.trustStore", "keys/truststore.p12");
        p.setProperty("bootstrap.file", bootstrapFile().toString());
        return p;
    }

    public void testLoadsWithDefaultsAndNoDecoy() throws Exception {
        GatewayConfig c = GatewayConfig.from(Config.of(base(), "test"));
        assertEquals("app-02", c.serviceId());
        assertEquals(Endpoint.parse("127.0.0.1:7002"), c.backend());
        assertNull(c.decoyListen());
        assertEquals("decoy", c.decoyId());
        assertEquals(Duration.ofSeconds(2), c.limits().preambleTimeout());
        assertEquals("eg-test", c.bootstrap().clusterId());
        assertTrue(c.bootstrap().policy().isApproved(new eastguard.common.Edge("web-01", "app-02")), "edge loaded");
    }

    public void testDecoyAndLimitsRead() throws Exception {
        Properties p = base();
        p.setProperty("decoy.listen", "127.0.0.1:9003");
        p.setProperty("decoy.id", "decoy-9003");
        p.setProperty("limits.idleMillis", "1234");
        GatewayConfig c = GatewayConfig.from(Config.of(p, "test"));
        assertEquals(Endpoint.parse("127.0.0.1:9003"), c.decoyListen());
        assertEquals("decoy-9003", c.decoyId());
        assertEquals(Duration.ofMillis(1234), c.limits().idleTimeout());
    }

    public void testServiceMustExistInBootstrap() throws Exception {
        Properties p = base();
        p.setProperty("gateway.service", "db-09");
        assertThrows(IllegalArgumentException.class, () -> GatewayConfig.from(Config.of(p, "test")));
    }

    public void testUnknownKeyAndHostNameRejected() throws Exception {
        Properties typo = base();
        typo.setProperty("limits.idleMilis", "1000");
        assertThrows(IllegalArgumentException.class, () -> GatewayConfig.from(Config.of(typo, "test")));
        Properties host = base();
        host.setProperty("backend", "localhost:7002"); // never resolved: must be numeric
        assertThrows(IllegalArgumentException.class, () -> GatewayConfig.from(Config.of(host, "test")));
    }
}
