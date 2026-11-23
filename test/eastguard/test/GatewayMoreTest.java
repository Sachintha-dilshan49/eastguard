package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Config;
import eastguard.common.Endpoint;
import eastguard.common.IpAddress;
import eastguard.common.ReasonCode;
import eastguard.common.Verdict;
import eastguard.gateway.CountingDecisionSink;
import eastguard.gateway.GatewayDecision;
import eastguard.gateway.GatewayLimits;
import java.time.Duration;
import java.util.Properties;

/**
 * Tests for {@link CountingDecisionSink} and {@link GatewayLimits}:
 * counting sink aggregations, string representations, and limit parameter validations.
 */
public final class GatewayMoreTest {

    public void testCountingDecisionSink() {
        CountingDecisionSink sink = new CountingDecisionSink();
        assertEquals(0L, sink.total());
        assertEquals("none", sink.toString());

        Endpoint ep = new Endpoint(IpAddress.parse("127.0.0.1"), 9002);
        sink.record(new GatewayDecision(1000, "web-01", IpAddress.parse("10.0.1.10"), "app-02", ep,
                Verdict.ALLOW, ReasonCode.OK, false, 1));
        sink.record(new GatewayDecision(1001, null, IpAddress.parse("10.0.1.11"), "app-02", ep,
                Verdict.DENY, ReasonCode.POLICY_DENY, false, 1));
        sink.record(new GatewayDecision(1002, null, IpAddress.parse("10.0.1.12"), "app-02", ep,
                Verdict.DENY, ReasonCode.POLICY_DENY, false, 1));
        sink.record(new GatewayDecision(1003, null, IpAddress.parse("10.0.1.13"), "app-02", ep,
                Verdict.DECOY, ReasonCode.DECOY_TOUCH, false, 1));

        assertEquals(4L, sink.total());
        assertEquals(1L, sink.count(Verdict.ALLOW));
        assertEquals(2L, sink.count(Verdict.DENY));
        assertEquals(1L, sink.count(Verdict.DECOY));

        assertEquals(1L, sink.count(ReasonCode.OK));
        assertEquals(2L, sink.count(ReasonCode.POLICY_DENY));
        assertEquals(1L, sink.count(ReasonCode.DECOY_TOUCH));
        assertEquals(0L, sink.count(ReasonCode.INVALID_TOKEN));

        String str = sink.toString();
        assertTrue(str.contains("OK=1"), str);
        assertTrue(str.contains("POLICY_DENY=2"), str);
        assertTrue(str.contains("DECOY_TOUCH=1"), str);
    }

    public void testGatewayLimitsValidation() {
        GatewayLimits def = GatewayLimits.defaults();
        assertTrue(def != null, "defaults created");
        assertEquals(5000, def.handshakeTimeout().toMillis());
        assertEquals(2000, def.preambleTimeout().toMillis());

        // Zero / negative timeout
        assertThrows(IllegalArgumentException.class, () -> new GatewayLimits(Duration.ZERO, def.preambleTimeout(),
                def.backendConnectTimeout(), def.idleTimeout(), def.maxSessionDuration(), def.maxConnections(),
                def.maxConnectionsPerPeer(), def.maxHandshakes(), def.bufferBudgetBytes(), def.relayBufferBytes(),
                def.highWaterBytes(), def.lowWaterBytes(), def.tlsTaskThreads(), def.commandQueue(), def.backlog(),
                def.maxAcceptsPerEvent()));

        // Invalid maxConnections
        assertThrows(IllegalArgumentException.class, () -> new GatewayLimits(def.handshakeTimeout(), def.preambleTimeout(),
                def.backendConnectTimeout(), def.idleTimeout(), def.maxSessionDuration(), 0,
                def.maxConnectionsPerPeer(), def.maxHandshakes(), def.bufferBudgetBytes(), def.relayBufferBytes(),
                def.highWaterBytes(), def.lowWaterBytes(), def.tlsTaskThreads(), def.commandQueue(), def.backlog(),
                def.maxAcceptsPerEvent()));

        // Buffer budget smaller than relay buffer
        assertThrows(IllegalArgumentException.class, () -> new GatewayLimits(def.handshakeTimeout(), def.preambleTimeout(),
                def.backendConnectTimeout(), def.idleTimeout(), def.maxSessionDuration(), def.maxConnections(),
                def.maxConnectionsPerPeer(), def.maxHandshakes(), 1024, 2048,
                def.highWaterBytes(), def.lowWaterBytes(), def.tlsTaskThreads(), def.commandQueue(), def.backlog(),
                def.maxAcceptsPerEvent()));

        // lowWaterBytes >= highWaterBytes
        assertThrows(IllegalArgumentException.class, () -> new GatewayLimits(def.handshakeTimeout(), def.preambleTimeout(),
                def.backendConnectTimeout(), def.idleTimeout(), def.maxSessionDuration(), def.maxConnections(),
                def.maxConnectionsPerPeer(), def.maxHandshakes(), def.bufferBudgetBytes(), def.relayBufferBytes(),
                1000, 1000, def.tlsTaskThreads(), def.commandQueue(), def.backlog(),
                def.maxAcceptsPerEvent()));

        // highWaterBytes > relayBufferBytes
        assertThrows(IllegalArgumentException.class, () -> new GatewayLimits(def.handshakeTimeout(), def.preambleTimeout(),
                def.backendConnectTimeout(), def.idleTimeout(), def.maxSessionDuration(), def.maxConnections(),
                def.maxConnectionsPerPeer(), def.maxHandshakes(), def.bufferBudgetBytes(), 10000,
                12000, 5000, def.tlsTaskThreads(), def.commandQueue(), def.backlog(),
                def.maxAcceptsPerEvent()));

        // Load custom config
        Properties props = new Properties();
        props.setProperty("limits.maxConnections", "500");
        props.setProperty("limits.highWaterBytes", "16384");
        props.setProperty("limits.lowWaterBytes", "4096");
        GatewayLimits custom = GatewayLimits.from(Config.of(props, "custom"));
        assertEquals(500, custom.maxConnections());
        assertEquals(16384, custom.highWaterBytes());
        assertEquals(4096, custom.lowWaterBytes());
    }
}
