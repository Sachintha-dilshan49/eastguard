package eastguard.test;

import static eastguard.test.Assert.assertEquals;
import static eastguard.test.Assert.assertTrue;

import eastguard.common.Cidr;
import eastguard.common.Config;
import eastguard.common.Endpoint;
import eastguard.common.IpAddress;
import eastguard.common.ReasonCode;
import eastguard.common.Restriction;
import eastguard.common.Selector;
import eastguard.common.TelemetrySender;
import eastguard.common.Verdict;
import eastguard.control.ControlPlaneImpl;
import eastguard.control.Dto;
import eastguard.control.Journal;
import eastguard.detector.ActionDispatcher;
import eastguard.detector.CidrClassifier;
import eastguard.detector.DetectorConfig;
import eastguard.detector.DetectorControl;
import eastguard.detector.ProducerInventory;
import eastguard.detector.RiskEngine;
import eastguard.detector.TelemetryVerifier;
import eastguard.detector.ThreatDetector;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/** The detector end to end: real UDP in, verified, scored, learned, and committed by an in-process control plane. */
public final class DetectorPipelineTest {
    private static final java.util.logging.Logger QUIET = java.util.logging.Logger.getLogger("eastguard");
    private final ControlFixtures fx = new ControlFixtures();

    public DetectorPipelineTest() {
        QUIET.setLevel(java.util.logging.Level.SEVERE);
    }

    static ThreatDetector.Settings settings(boolean automated) {
        return new ThreatDetector.Settings("eg-demo", new InetSocketAddress(InetAddress.getLoopbackAddress(), 0),
                TelemetryVerifier.Settings.defaults(),
                new RiskEngine.Settings(100, 256, 60_000, automated, automated, 0, Set.of(), 50),
                new CidrClassifier(List.of(Cidr.parse("10.0.0.0/8")), List.of(Cidr.parse("10.0.99.0/24")), List.of()),
                Duration.ofMinutes(5), 100, 60_000, 100);
    }

    public void testUdpToCommittedQuarantineAndLearningDraft() throws Exception {
        Path file = ControlFixtures.freshJournal();
        try (Journal j = Journal.open(file)) {
            // Control plane uses wall time here: the detector's events carry System.currentTimeMillis().
            ControlPlaneImpl cp = ControlPlaneImpl.open(j, Clock.systemUTC(), fx.credentials,
                    ControlPlaneImpl.Settings.defaults().withAutomation(DetectorControlTest.automation(20)));
            var learning = DetectorControlTest.learning();
            assertTrue(cp.bootstrap(new eastguard.common.EnforcementSnapshot("eg-demo", 1, learning.policy(),
                    learning.workloads(), learning.services(), List.of(), List.of(), java.util.Map.of(),
                    learning.tokenKeys(), Set.of()), "admin", "test").ok(), "bootstrap");
            ThreatDetector d = new ThreatDetector(settings(true), TelemetryVerifierTest.inventory(),
                    DetectorControl.direct(cp, fx.cred("detector")), Clock.systemUTC(), System::nanoTime);
            d.start();
            TelemetrySender gw = new TelemetrySender("eg-demo", "gw-app-02", "tk1", TelemetryVerifierTest.GW_KEY,
                    new InetSocketAddress(InetAddress.getLoopbackAddress(), d.port()), 64, new SecureRandom());
            gw.start();
            try {
                Endpoint listener = TelemetryVerifierTest.GW;
                IpAddress api = IpAddress.parse("10.0.1.11");
                for (int i = 0; i < 3; i++) { // healthy pilot discovery: learned, never scored
                    gw.offer(System.currentTimeMillis(), "api-01", api, "app-02", listener, Verdict.ALLOW, ReasonCode.OK,
                            true, 1);
                }
                IpAddress intruder = IpAddress.parse("10.0.1.50");
                gw.offer(System.currentTimeMillis(), null, intruder, "decoy-9003", TelemetryVerifierTest.DECOY,
                        Verdict.DECOY, ReasonCode.DECOY_TOUCH, false, 1);
                long deadline = System.nanoTime() + 5_000_000_000L;
                while (d.alerts().isEmpty() && System.nanoTime() < deadline) {
                    Thread.sleep(10);
                }
                assertEquals(0, d.score(Selector.identity("api-01")));
                assertEquals(100, d.score(Selector.ip(intruder)));
                d.flushLearning();
                assertTrue(d.dispatcher().awaitIdle(Duration.ofSeconds(5)), "control-plane calls done");
                List<Restriction> r = cp.snapshot().restrictions();
                assertEquals(1, r.size());
                assertEquals(Selector.ip(intruder), r.get(0).selector());
                assertEquals(ReasonCode.RISK_SCORE, r.get(0).reason());
                assertEquals(List.of("DECOY"), cp.alerts().get(0).signals());
                List<Dto.Observation> draft = cp.draft();
                assertEquals(1, draft.size());
                assertEquals(DetectorControlTest.API_APP02, draft.get(0).edge());
                assertEquals(3, draft.get(0).count());
                assertEquals(4, d.telemetryStats().count(TelemetryVerifier.Result.ACCEPTED));
            } finally {
                gw.close();
                d.close();
            }
        }
    }

    /**
     * Spec §10 "untrusted or duplicate UDP does not inflate scores", end to end over real UDP: between two genuine
     * events, forged (wrong key), wrong-cluster, out-of-scope, replayed and oversized datagrams for the same actor
     * reach the detector, and the score is exactly what the two genuine events give (30 + 10).
     */
    public void testForgedDuplicateAndOutOfScopeUdpDoNotInflateScores() throws Exception {
        Path file = ControlFixtures.freshJournal();
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = ControlPlaneImpl.open(j, Clock.systemUTC(), fx.credentials,
                    ControlPlaneImpl.Settings.defaults());
            assertTrue(cp.bootstrap(DetectorControlTest.learning(), "admin", "test").ok(), "bootstrap");
            ThreatDetector d = new ThreatDetector(settings(false), TelemetryVerifierTest.inventory(),
                    DetectorControl.direct(cp, fx.cred("detector")), Clock.systemUTC(), System::nanoTime);
            d.start();
            try (java.net.DatagramSocket out = new java.net.DatagramSocket()) {
                InetSocketAddress to = new InetSocketAddress(InetAddress.getLoopbackAddress(), d.port());
                long now = System.currentTimeMillis();
                eastguard.common.Bytes boot = TelemetryVerifierTest.BOOT;
                IpAddress ip = TelemetryVerifierTest.IP;
                Endpoint gwL = TelemetryVerifierTest.GW;
                java.util.function.BiFunction<Long, ReasonCode, eastguard.common.Telemetry> deny = (seq, r) ->
                        TelemetryVerifierTest.event("gw-app-02", boot, seq, now, "web-01", ip, "app-02", gwL, Verdict.DENY,
                                r, false);
                byte[] first = TelemetryVerifierTest.gw(deny.apply(0L, ReasonCode.POLICY_DENY)); // +30
                List<byte[]> junk = new java.util.ArrayList<>();
                for (long seq = 1; seq <= 5; seq++) {
                    junk.add(first); // replayed / duplicated: same producer, boot and sequence number
                    junk.add(eastguard.common.TelemetryCodec.encode(deny.apply(seq, ReasonCode.POLICY_DENY),
                            TelemetryVerifierTest.ISS_KEY)); // forged: another producer's key
                    junk.add(TelemetryVerifierTest.gw(new eastguard.common.Telemetry("other-cluster", "gw-app-02", "tk1",
                            boot, 100 + seq, now, 3, "web-01", ip, "app-02", gwL.ip(), gwL.port(), Verdict.DENY,
                            ReasonCode.POLICY_DENY, false))); // wrong cluster
                    junk.add(TelemetryVerifierTest.gw(TelemetryVerifierTest.event("gw-app-02", boot, 200 + seq, now,
                            "web-01", ip, "app-05", TelemetryVerifierTest.GW5, Verdict.DENY, ReasonCode.POLICY_DENY,
                            false))); // out of scope: gw-app-02 does not own app-05's listener
                    byte[] big = new byte[1_300];
                    System.arraycopy(first, 0, big, 0, first.length);
                    junk.add(big); // oversized: rejected before parsing
                }
                byte[] last = TelemetryVerifierTest.gw(deny.apply(1L, ReasonCode.INVALID_TOKEN)); // +10, the marker
                out.send(new java.net.DatagramPacket(first, first.length, to));
                for (byte[] b : junk) {
                    out.send(new java.net.DatagramPacket(b, b.length, to));
                }
                out.send(new java.net.DatagramPacket(last, last.length, to));
                long deadline = System.nanoTime() + 5_000_000_000L;
                while (d.telemetryStats().count(TelemetryVerifier.Result.ACCEPTED) < 2 && System.nanoTime() < deadline) {
                    Thread.sleep(10);
                }
                Thread.sleep(200); // anything still in flight would land now
                assertEquals(40, d.score(Selector.identity("web-01")));
                assertEquals(0, d.score(Selector.ip(ip)));
                TelemetryVerifier.Stats s = d.telemetryStats();
                assertEquals(2, s.count(TelemetryVerifier.Result.ACCEPTED));
                assertEquals(5, s.count(TelemetryVerifier.Result.DUPLICATE));
                assertEquals(2, d.eventsProcessed());
                assertTrue(d.alerts().isEmpty(), "no alert from junk");
            } finally {
                d.close();
            }
        }
    }

    /** The reply to a committed proposal is lost; the retry with the same ID is answered as a replay. */
    public void testDispatcherRetriesWithTheSameIdempotencyId() throws Exception {
        Path file = ControlFixtures.freshJournal();
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = ControlPlaneImpl.open(j, fx.clock, fx.credentials,
                    ControlPlaneImpl.Settings.defaults().withAutomation(DetectorControlTest.automation(20)));
            assertTrue(cp.bootstrap(DetectorControlTest.learning(), "admin", "test").ok(), "bootstrap");
            DetectorControl real = DetectorControl.direct(cp, fx.cred("detector"));
            AtomicInteger calls = new AtomicInteger();
            DetectorControl lossy = new DetectorControl() {
                @Override
                public Dto.MutationResult recordObservations(String id, List<Dto.Observation> obs) throws IOException {
                    return real.recordObservations(id, obs);
                }

                @Override
                public Dto.MutationResult proposeAction(String id, Dto.ActionType a, List<Selector> sel, Duration ttl,
                        int score, List<String> signals, List<String> evidence) throws IOException {
                    Dto.MutationResult r = real.proposeAction(id, a, sel, ttl, score, signals, evidence);
                    if (calls.incrementAndGet() == 1) {
                        throw new IOException("reply lost after commit");
                    }
                    return r;
                }
            };
            try (ActionDispatcher disp = new ActionDispatcher(lossy, 8, 3, 1)) {
                disp.propose("det-x-1", new RiskEngine.Proposal(RiskEngine.ActionType.QUARANTINE,
                        Selector.identity("web-01"), 120, List.of("DECOY"), List.of("gw-app-02/00/1")), Duration.ofMinutes(1));
                assertTrue(disp.awaitIdle(Duration.ofSeconds(5)), "done");
                ActionDispatcher.Outcome o = disp.recent().get(0);
                assertTrue(o.committed(), "committed");
                assertTrue(o.result().replayed(), "the retry was answered from the idempotency record");
                assertEquals(2, calls.get());
                assertEquals(2, cp.snapshot().revision()); // one commit, not two
            }
        }
    }

    public void testExampleConfigParses() {
        DetectorConfig c = DetectorConfig.load(Path.of("config", "detector.properties.example"));
        assertEquals(2, c.producers().size());
        assertEquals(ProducerInventory.Kind.ISSUER, c.producers().get(1).producer().kind());
        assertTrue(!c.risk().proposeQuarantine() && !c.risk().proposeLeaseReduction(), "alert-only by default");
        assertEquals(30_000, c.risk().warmupMillis());
        assertEquals(CidrClassifier.Zone.SHARED, c.cidrs().classify(IpAddress.parse("10.0.99.4")));
        assertEquals(CidrClassifier.Zone.PROTECTED, c.cidrs().classify(IpAddress.parse("10.0.0.3")));
        assertEquals(CidrClassifier.Zone.MANAGED, c.cidrs().classify(IpAddress.parse("127.0.0.1")));
        assertEquals(CidrClassifier.Zone.UNMANAGED, c.cidrs().classify(IpAddress.parse("192.168.1.1")));
        eastguard.control.ControlConfig cc = eastguard.control.ControlConfig.load(Path.of("config",
                "control.properties.example"));
        assertTrue(!cc.settings().automation().quarantine(), "control plane alert-only by default");
        assertEquals(Duration.ofSeconds(10), cc.settings().automation().stepUpLease());
        java.util.Properties p = new java.util.Properties();
        p.setProperty("cluster.id", "eg-demo");
        assertTrue(Assert.assertThrows(IllegalArgumentException.class, () -> DetectorConfig.from(Config.of(p, "t")))
                .getMessage().contains("listen"), "required keys");
    }
}
