package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Endpoint;
import eastguard.control.ControlConfig;
import eastguard.detector.DetectorConfig;
import eastguard.detector.ProducerInventory;
import eastguard.gateway.GatewayConfig;
import eastguard.tokensvc.TokenConfig;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * The configuration set {@code scripts\run-demo.ps1} starts (spec Â§11 final demo): it parses, its pieces agree with
 * each other (bootstrap services, gateway listeners and backends, the detector's producer inventory), automation
 * is limited to what the demo needs, and no example file holds a secret.
 */
public final class DemoConfigTest {
    private static final List<String> GATEWAYS = List.of("gateway-app-02.properties.example",
            "gateway-app-03.properties.example");

    static Properties raw(String name) throws Exception {
        Properties p = new Properties();
        try (Reader r = Files.newBufferedReader(Path.of("config", name), StandardCharsets.UTF_8)) {
            p.load(r);
        }
        return p;
    }

    public void testDemoConfigsParseAndEnableOnlyQuarantineAutomation() {
        ControlConfig demo = ControlConfig.load(Path.of("config", "demo-control.properties.example"));
        ControlConfig shipped = ControlConfig.load(Path.of("config", "control.properties.example"));
        assertTrue(demo.settings().automation().quarantine(), "demo control plane commits detector quarantines");
        assertFalse(demo.settings().automation().leaseReduction(), "lease-reduction automation stays off");
        assertFalse(shipped.settings().automation().quarantine(), "the shipped control config stays alert-only");
        assertFalse(demo.journalFile().equals(shipped.journalFile()), "the demo has its own journal");
        assertEquals(Path.of("journal", "demo-control.journal"), demo.journalFile());

        DetectorConfig det = DetectorConfig.load(Path.of("config", "demo-detector.properties.example"));
        assertTrue(det.risk().proposeQuarantine() && !det.risk().proposeLeaseReduction(), "demo detector proposes quarantine only");
        assertEquals(10_000, det.risk().warmupMillis());
        assertEquals(3, det.producers().size());

        GatewayConfig g3 = GatewayConfig.load(Path.of("config", "gateway-app-03.properties.example"));
        assertEquals("app-03", g3.serviceId());
        assertNull(g3.decoyListen());
    }

    /** Every gateway's listener and decoy belong to its own producer in the detector inventory, and vice versa. */
    public void testDetectorInventoryMatchesTheGatewayAndTokenConfigs() throws Exception {
        DetectorConfig det = DetectorConfig.load(Path.of("config", "demo-detector.properties.example"));
        Map<String, ProducerInventory.Producer> byId = new java.util.HashMap<>();
        det.producers().forEach(s -> byId.put(s.producer().id(), s.producer()));
        for (String name : GATEWAYS) {
            Properties g = raw(name);
            ProducerInventory.Producer p = byId.get(g.getProperty("telemetry.producerId"));
            assertTrue(p != null, name + ": producer " + g.getProperty("telemetry.producerId") + " in the demo inventory");
            assertEquals(ProducerInventory.Kind.GATEWAY, p.kind());
            assertEquals(Map.of(Endpoint.parse(g.getProperty("listen")), g.getProperty("gateway.service")), p.listeners());
            String decoy = g.getProperty("decoy.listen");
            assertEquals(decoy == null ? Map.of() : Map.of(Endpoint.parse(decoy), g.getProperty("decoy.id")), p.decoys());
            assertEquals(g.getProperty("telemetry.keyFile"), raw("demo-detector.properties.example")
                    .getProperty("producer." + p.id() + ".keyFile"));
            assertEquals(det.listen(), Endpoint.parse(g.getProperty("telemetry.collector")));
        }
        TokenConfig t = TokenConfig.load(Path.of("config", "token.properties.example"));
        ProducerInventory.Producer issuer = byId.get("tokensvc");
        assertEquals(ProducerInventory.Kind.ISSUER, issuer.kind());
        assertEquals(Set.of(t.listen()), issuer.listeners().keySet());
    }

    /** The bootstrap's services are exactly the two gateways: same listener, same fixed backend. */
    public void testDemoBootstrapMatchesTheGateways() throws Exception {
        Properties b = raw("demo-bootstrap.properties.example");
        assertEquals("app-02,app-03", b.getProperty("bootstrap.services"));
        assertEquals("ENFORCE", b.getProperty("bootstrap.mode"));
        assertEquals("web-01>app-02,web-01>app-03", b.getProperty("bootstrap.edges")); // deny by default: api-01 has no edge
        assertEquals("", b.getProperty("bootstrap.pilot.sources"));
        for (String name : GATEWAYS) {
            GatewayConfig g = GatewayConfig.load(Path.of("config", name));
            String pre = "bootstrap.service." + g.serviceId() + ".";
            assertEquals(Endpoint.parse(b.getProperty(pre + "listener")), g.listen());
            assertEquals(Endpoint.parse(b.getProperty(pre + "backend")), g.backend());
            assertEquals(g.serviceId(), b.getProperty(pre + "gateway"));
        }
        assertEquals(raw("bootstrap.properties.example").getProperty("bootstrap.tokenKeys"), b.getProperty("bootstrap.tokenKeys"));
        assertEquals(raw("bootstrap.properties.example").getProperty("bootstrap.controlKeys"),
                b.getProperty("bootstrap.controlKeys"));
    }

    public void testNewExampleFilesHoldNoSecrets() throws Exception {
        for (String name : new String[] {"demo-bootstrap.properties.example", "demo-control.properties.example",
                "demo-detector.properties.example", "gateway-app-03.properties.example", "detector.properties.example",
                "dashboard.properties.example"}) {
            String text = Files.readString(Path.of("config", name)).toLowerCase();
            assertFalse(text.matches("(?s).*\\n(\\w+\\.)*(password|pass|secret|key)\\s*=.*"), "no secret values in " + name);
        }
    }
}
