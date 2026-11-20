package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Config;
import eastguard.common.Endpoint;
import eastguard.gateway.GatewayConfig;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Properties;

/** Gateway configuration: the shipped example parses, and bad input is rejected. */
public final class GatewayConfigTest {
    private static final Path EXAMPLE = Path.of("config", "gateway-app-02.properties.example");

    private static Properties example() throws Exception {
        Properties p = new Properties();
        try (Reader r = Files.newBufferedReader(EXAMPLE, StandardCharsets.UTF_8)) {
            p.load(r);
        }
        return p;
    }

    private static GatewayConfig parse(Properties p) {
        return GatewayConfig.from(Config.of(p, "test"));
    }

    public void testExampleConfigParses() throws Exception {
        GatewayConfig c = parse(example());
        assertEquals("app-02", c.serviceId());
        assertEquals(Endpoint.parse("127.0.0.1:7002"), c.backend());
        assertEquals(Endpoint.parse("127.0.0.1:9003"), c.decoyListen());
        assertEquals("decoy-9003", c.decoyId());
        assertEquals(Duration.ofSeconds(2), c.limits().preambleTimeout());
        assertEquals(Endpoint.parse("127.0.0.1:1099"), c.control().registry());
        assertEquals(1100, c.control().objectPort());
        assertEquals("gw-app-02", c.control().principal());
        assertEquals("eg-demo", c.sync().clusterId());
        assertEquals(Duration.ofSeconds(1), c.sync().poll());
        assertEquals(Duration.ofSeconds(5), c.sync().maxAge());
    }

    public void testDecoyIsOptional() throws Exception {
        Properties p = example();
        p.remove("decoy.listen");
        p.remove("decoy.id");
        GatewayConfig c = parse(p);
        assertNull(c.decoyListen());
        assertEquals("decoy", c.decoyId());
    }

    public void testUnknownKeyHostNameAndStaleBootstrapKeyRejected() throws Exception {
        for (String[] kv : new String[][] {
                {"limits.idleMilis", "1000"},              // typo
                {"backend", "localhost:7002"},              // never resolved: must be numeric
                {"control.registry", "control:1099"},       // same for the control plane
                {"state.maxAgeMillis", "120000"},           // freshness above 60 s is refused
                {"bootstrap.file", "config/x.properties"},  // static state is gone (Task 6)
        }) {
            Properties bad = example();
            bad.setProperty(kv[0], kv[1]);
            assertThrows(IllegalArgumentException.class, () -> parse(bad));
        }
    }

    public void testExampleFileHoldsNoSecrets() throws Exception {
        String text = Files.readString(EXAMPLE).toLowerCase();
        assertFalse(text.matches("(?s).*\\n(\\w+\\.)*(password|pass|secret)\\s*=.*"), "no secret values");
    }
}
