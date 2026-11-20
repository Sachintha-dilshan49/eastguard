package eastguard.detector;

import eastguard.common.Selector;
import eastguard.control.ControlClient;
import eastguard.tokensvc.TlsContextFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;

/**
 * The threat detector (spec §6.1): receives authenticated UDP telemetry ({@link FlowReceiver},
 * {@link TelemetryVerifier}), scores it ({@link RiskEngine}), collects learning observations
 * ({@link LearningCollector}), and sends proposals and observation batches to the control plane
 * ({@link ActionDispatcher}). It holds no signing key and never broadcasts: the control plane alone commits.
 *
 * <p>Verification, scoring and learning all run on the receive thread under this object's lock; only the
 * control-plane calls run elsewhere.
 *
 * Run: {@code java -cp out eastguard.detector.ThreatDetector --config config/detector.properties}
 */
public final class ThreatDetector implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(ThreatDetector.class.getName());

    /** Everything but the control-plane connection; see {@link DetectorConfig}. */
    public record Settings(String clusterId, InetSocketAddress bind, TelemetryVerifier.Settings telemetry,
            RiskEngine.Settings risk, CidrClassifier cidrs, Duration actionTtl, int learningBatch,
            long learningFlushMillis, int learningMaxPending) {
        public Settings {
            Objects.requireNonNull(bind, "bind");
            Objects.requireNonNull(telemetry, "telemetry");
            Objects.requireNonNull(risk, "risk");
            Objects.requireNonNull(cidrs, "cidrs");
            Objects.requireNonNull(actionTtl, "actionTtl");
        }

        public static Settings of(DetectorConfig c) {
            return new Settings(c.clusterId(), c.listen().toSocketAddress(), c.telemetry(), c.risk(), c.cidrs(),
                    c.actionTtl(), c.learningBatch(), c.learningFlushMillis(), c.learningMaxPending());
        }
    }

    private final Settings settings;
    private final TelemetryVerifier verifier;
    private final RiskEngine engine;
    private final LearningCollector learning;
    private final ActionDispatcher dispatcher;
    private final FlowReceiver receiver;
    private final LongSupplier nanos;
    private final String batchPrefix;
    private volatile Consumer<RiskEngine.Detection> onDetection = d -> { };
    private long batches;
    private long processed;

    public ThreatDetector(Settings settings, ProducerInventory inventory, DetectorControl control, Clock clock,
            LongSupplier nanos) {
        this.settings = Objects.requireNonNull(settings, "settings");
        this.nanos = Objects.requireNonNull(nanos, "nanos");
        long start = nanos.getAsLong();
        SecureRandom random = new SecureRandom();
        this.verifier = new TelemetryVerifier(settings.clusterId(), inventory, settings.telemetry(), clock);
        this.engine = new RiskEngine(settings.risk(), settings.cidrs(), verifier::degraded, clock, start, random);
        this.learning = new LearningCollector(settings.learningMaxPending(), settings.learningBatch(),
                settings.learningFlushMillis(), start);
        this.dispatcher = new ActionDispatcher(control, 256, 3, 200);
        this.receiver = new FlowReceiver(settings.bind(), verifier, this::onEvent, this::tick, nanos);
        byte[] b = new byte[6];
        random.nextBytes(b);
        this.batchPrefix = "obs-" + HexFormat.of().formatHex(b) + "-";
    }

    /** Called on the receive thread for every raised alert (demos, dashboards). Must not block. */
    public void onDetection(Consumer<RiskEngine.Detection> listener) {
        this.onDetection = Objects.requireNonNull(listener, "listener");
    }

    public void start() throws IOException {
        receiver.start();
        LOG.info(() -> "threat detector started: automation leaseReduction=" + settings.risk().proposeLeaseReduction()
                + " quarantine=" + settings.risk().proposeQuarantine() + "; no automatic action for the first "
                + settings.risk().warmupMillis() + " ms (restart guard)");
    }

    public int port() {
        return receiver.port();
    }

    private synchronized void onEvent(TelemetryVerifier.Verified v) {
        try {
            handle(v);
        } finally {
            processed++;
        }
    }

    private void handle(TelemetryVerifier.Verified v) {
        learning.accept(v);
        RiskEngine.Detection d = engine.accept(v);
        if (d == null) {
            return;
        }
        LOG.warning(() -> d.level() + " alert " + d.alert().id() + " actor=" + d.actor() + " zone=" + d.zone()
                + " score=" + d.alert().score() + " signals=" + d.alert().signals() + " -> "
                + (d.proposal() != null ? "propose " + d.proposal().type() : d.note()));
        if (d.proposal() != null) {
            dispatcher.propose(d.alert().id(), d.proposal(), settings.actionTtl());
        }
        try {
            onDetection.accept(d);
        } catch (RuntimeException e) {
            LOG.log(Level.FINE, "detection listener failed", e);
        }
    }

    private synchronized void tick() {
        long now = nanos.getAsLong();
        engine.tick(now);
        for (List<eastguard.control.Dto.Observation> batch : learning.due(now)) {
            dispatcher.observe(batchPrefix + (++batches), batch);
        }
    }

    /** Forces pending learning observations out now (demos, shutdown). */
    public synchronized void flushLearning() {
        for (List<eastguard.control.Dto.Observation> batch : learning.due(Long.MAX_VALUE / 2)) {
            dispatcher.observe(batchPrefix + (++batches), batch);
        }
    }

    public synchronized int score(Selector actor) {
        return engine.score(actor, nanos.getAsLong());
    }

    /** Verified events fully handled (learned and scored) so far. */
    public synchronized long eventsProcessed() {
        return processed;
    }

    public synchronized TelemetryVerifier.Stats telemetryStats() {
        return verifier.stats();
    }

    public synchronized List<RiskEngine.Detection> alerts() {
        return engine.history();
    }

    public synchronized int pendingObservations() {
        return learning.pending();
    }

    public ActionDispatcher dispatcher() {
        return dispatcher;
    }

    @Override
    public void close() {
        receiver.close();
        flushLearning();
        dispatcher.close();
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2 || !"--config".equals(args[0])) {
            System.err.println("usage: java -cp out eastguard.detector.ThreatDetector --config config/detector.properties");
            System.exit(2);
        }
        DetectorConfig cfg = DetectorConfig.load(Path.of(args[1]));
        SSLContext ctx = TlsContextFactory.create(cfg.tls());
        ControlClient client = new ControlClient(cfg.control(), ctx);
        ThreatDetector d = new ThreatDetector(Settings.of(cfg), ProducerInventory.load(cfg.producers()),
                DetectorControl.of(client), Clock.systemUTC(), System::nanoTime);
        Runtime.getRuntime().addShutdownHook(new Thread(d::close, "detector-shutdown"));
        d.start();
    }
}
