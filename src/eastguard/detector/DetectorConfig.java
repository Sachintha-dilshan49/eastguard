package eastguard.detector;

import eastguard.common.Config;
import eastguard.common.Endpoint;
import eastguard.common.Ids;
import eastguard.common.SecretSource;
import eastguard.control.ControlClient;
import eastguard.tokensvc.TlsContextFactory;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;

/**
 * Threat detector configuration, see {@code config/detector.properties.example}.
 *
 * <pre>
 * cluster.id=eg-demo
 * listen=127.0.0.1:5514                     UDP telemetry listener (management network)
 * telemetry.acceptanceMillis=30000          event-time window; dedup retention; restart guard
 * telemetry.maxSkewMillis=5000  telemetry.seqWindow=1024  telemetry.maxBootsPerProducer=8
 * producers, producer.&lt;id&gt;.*              trusted inventory, see {@link ProducerInventory}
 * detector.maxActors=10000  detector.maxEventsPerActor=256  detector.cooldownMillis=60000
 * detector.maxAlerts=200    detector.protectedIdentities=   (never proposed for automatic action)
 * automation.leaseReduction=false           alert-only until enabled (the control plane must allow it too)
 * automation.quarantine=false
 * automation.actionTtlSeconds=300           expiry proposed for automatic actions
 * cidr.managed, cidr.shared, cidr.protected source-IP classification, see {@link CidrClassifier}
 * learning.batchSize=100  learning.flushMillis=5000  learning.maxPending=1000
 * tls.*, control.*                          RMI client identity and credential (role DETECTOR)
 * </pre>
 */
public record DetectorConfig(String clusterId, Endpoint listen, TelemetryVerifier.Settings telemetry,
        List<ProducerInventory.Spec> producers, RiskEngine.Settings risk, CidrClassifier cidrs, Duration actionTtl,
        int learningBatch, long learningFlushMillis, int learningMaxPending, TlsContextFactory.Material tls,
        ControlClient.Settings control) {

    public DetectorConfig {
        Ids.require(clusterId, "clusterId");
        Objects.requireNonNull(listen, "listen");
        Objects.requireNonNull(telemetry, "telemetry");
        producers = List.copyOf(producers);
        Objects.requireNonNull(risk, "risk");
        Objects.requireNonNull(cidrs, "cidrs");
        Objects.requireNonNull(actionTtl, "actionTtl");
        Objects.requireNonNull(tls, "tls");
        Objects.requireNonNull(control, "control");
    }

    public static DetectorConfig load(Path file) {
        return from(Config.load(file));
    }

    public static DetectorConfig from(Config c) {
        String cluster = c.id("cluster.id");
        Endpoint listen = c.endpoint("listen");
        long acceptance = c.longIn("telemetry.acceptanceMillis", 30_000, 1_000, 600_000);
        TelemetryVerifier.Settings telemetry = new TelemetryVerifier.Settings(acceptance,
                c.longIn("telemetry.maxSkewMillis", 5_000, 0, 60_000), c.intIn("telemetry.seqWindow", 1_024, 64, 65_536),
                c.intIn("telemetry.maxBootsPerProducer", 8, 1, 1_024));
        List<ProducerInventory.Spec> producers = ProducerInventory.specs(c);
        RiskEngine.Settings risk = new RiskEngine.Settings(c.intIn("detector.maxActors", 10_000, 1, 1_000_000),
                c.intIn("detector.maxEventsPerActor", 256, 16, 100_000),
                c.longIn("detector.cooldownMillis", 60_000, 0, 86_400_000),
                c.bool("automation.leaseReduction", false), c.bool("automation.quarantine", false),
                acceptance, new HashSet<>(c.idList("detector.protectedIdentities")),
                c.intIn("detector.maxAlerts", 200, 1, 100_000));
        CidrClassifier cidrs = new CidrClassifier(c.cidrList("cidr.managed"), c.cidrList("cidr.shared"),
                c.cidrList("cidr.protected"));
        Duration ttl = Duration.ofSeconds(c.longIn("automation.actionTtlSeconds", 300, 1, 86_400));
        int batch = c.intIn("learning.batchSize", 100, 1, 500);
        long flush = c.longIn("learning.flushMillis", 5_000, 100, 600_000);
        int maxPending = c.intIn("learning.maxPending", 1_000, 1, 100_000);
        var tls = new TlsContextFactory.Material(c.path("tls.keyStore"), c.path("tls.trustStore"),
                new SecretSource(c.string("tls.passwordEnv", "EASTGUARD_STORE_PASS"),
                        c.path("tls.passwordFile", "keys/store.pass")));
        ControlClient.Settings control = ControlClient.Settings.from(c);
        c.requireNoUnknownKeys();
        return new DetectorConfig(cluster, listen, telemetry, producers, risk, cidrs, ttl, batch, flush, maxPending, tls,
                control);
    }
}
