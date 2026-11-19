package eastguard.gateway;

import eastguard.common.Config;
import java.time.Duration;
import java.util.Properties;

/**
 * Gateway deadlines and resource limits (spec §4.3, §9.1). Every limit rejects excess rather than queueing it.
 *
 * <pre>
 * limits.handshakeMillis=5000          TLS handshake, from accept
 * limits.preambleMillis=2000           complete preamble, from handshake completion
 * limits.backendConnectMillis=2000     non-blocking backend connect
 * limits.idleMillis=60000              relay with no bytes moving in either direction
 * limits.maxSessionMillis=300000       absolute relay lifetime
 * limits.maxConnections=2048           client connections in any state; excess accepted and closed
 * limits.maxConnectionsPerPeer=1024    per source IP
 * limits.maxHandshakes=256             connections in TLS handshake or preamble; accepting pauses at the limit
 * limits.bufferBudgetBytes=268435456   total relay + TLS buffer memory reserved across connections
 * limits.relayBufferBytes=32768        plaintext buffer per direction (raised to one TLS record if smaller)
 * limits.highWaterBytes=24576          per direction: pause reading the source at or above this many queued bytes
 * limits.lowWaterBytes=8192            ... and resume at or below this
 * limits.tlsTaskThreads=2              delegated TLS task executor threads
 * limits.commandQueue=1024             cross-thread commands waiting for the selector
 * limits.backlog=512
 * limits.maxAcceptsPerEvent=64         accepts handled per selector wake-up (limits work per selected key)
 * </pre>
 */
public record GatewayLimits(
        Duration handshakeTimeout,
        Duration preambleTimeout,
        Duration backendConnectTimeout,
        Duration idleTimeout,
        Duration maxSessionDuration,
        int maxConnections,
        int maxConnectionsPerPeer,
        int maxHandshakes,
        long bufferBudgetBytes,
        int relayBufferBytes,
        int highWaterBytes,
        int lowWaterBytes,
        int tlsTaskThreads,
        int commandQueue,
        int backlog,
        int maxAcceptsPerEvent) {

    public GatewayLimits {
        for (Duration d : new Duration[] {handshakeTimeout, preambleTimeout, backendConnectTimeout, idleTimeout,
                maxSessionDuration}) {
            if (d == null || d.isNegative() || d.isZero()) {
                throw new IllegalArgumentException("timeouts must be positive");
            }
        }
        if (maxConnections < 1 || maxConnectionsPerPeer < 1 || maxHandshakes < 1 || tlsTaskThreads < 1
                || commandQueue < 1 || backlog < 1 || maxAcceptsPerEvent < 1) {
            throw new IllegalArgumentException("limits must be positive");
        }
        if (relayBufferBytes < 1_024 || bufferBudgetBytes < relayBufferBytes) {
            throw new IllegalArgumentException("buffer sizes out of range");
        }
        if (lowWaterBytes < 0 || lowWaterBytes >= highWaterBytes || highWaterBytes > relayBufferBytes) {
            throw new IllegalArgumentException("require 0 <= lowWaterBytes < highWaterBytes <= relayBufferBytes");
        }
    }

    public static GatewayLimits defaults() {
        return from(Config.of(new Properties(), "defaults"));
    }

    /** Reads the {@code limits.*} keys; absent keys take the §9.1 starting values. */
    public static GatewayLimits from(Config c) {
        return new GatewayLimits(
                c.millis("limits.handshakeMillis", 5_000, 10, 60_000),
                c.millis("limits.preambleMillis", 2_000, 10, 60_000),
                c.millis("limits.backendConnectMillis", 2_000, 10, 60_000),
                c.millis("limits.idleMillis", 60_000, 10, 86_400_000),
                c.millis("limits.maxSessionMillis", 300_000, 10, 86_400_000),
                c.intIn("limits.maxConnections", 2_048, 1, 100_000),
                c.intIn("limits.maxConnectionsPerPeer", 1_024, 1, 100_000),
                c.intIn("limits.maxHandshakes", 256, 1, 100_000),
                c.longIn("limits.bufferBudgetBytes", 256L << 20, 64 << 10, 64L << 30),
                c.intIn("limits.relayBufferBytes", 32 << 10, 1_024, 16 << 20),
                c.intIn("limits.highWaterBytes", 24 << 10, 1, 16 << 20),
                c.intIn("limits.lowWaterBytes", 8 << 10, 0, 16 << 20),
                c.intIn("limits.tlsTaskThreads", 2, 1, 64),
                c.intIn("limits.commandQueue", 1_024, 1, 1_000_000),
                c.intIn("limits.backlog", 512, 1, 65_535),
                c.intIn("limits.maxAcceptsPerEvent", 64, 1, 10_000));
    }
}
