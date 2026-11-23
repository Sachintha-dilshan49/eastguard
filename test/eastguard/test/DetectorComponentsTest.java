package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Bytes;
import eastguard.common.Cidr;
import eastguard.common.Edge;
import eastguard.common.Endpoint;
import eastguard.common.IpAddress;
import eastguard.common.ReasonCode;
import eastguard.common.Selector;
import eastguard.common.Telemetry;
import eastguard.common.Verdict;
import eastguard.control.Dto;
import eastguard.detector.ActionDispatcher;
import eastguard.detector.CidrClassifier;
import eastguard.detector.DetectorControl;
import eastguard.detector.LearningCollector;
import eastguard.detector.ProducerInventory;
import eastguard.detector.RiskEngine;
import eastguard.detector.TelemetryVerifier;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Unit tests for detector subsystem components:
 * {@link eastguard.detector.SeqWindow}, {@link CidrClassifier}, {@link LearningCollector},
 * and {@link ActionDispatcher}.
 */
public final class DetectorComponentsTest {

    // ---------------------------------------------------------
    // SeqWindow Tests
    // ---------------------------------------------------------

    public void testSeqWindowValidation() throws Exception {
        // Must be power of 2 in [64, 65536]
        assertThrows(IllegalArgumentException.class, () -> createSeqWindow(63));
        assertThrows(IllegalArgumentException.class, () -> createSeqWindow(65));
        assertThrows(IllegalArgumentException.class, () -> createSeqWindow(32));
        assertThrows(IllegalArgumentException.class, () -> createSeqWindow(131072));
        assertThrows(IllegalArgumentException.class, () -> createSeqWindow(0));
        assertThrows(IllegalArgumentException.class, () -> createSeqWindow(-64));

        Object w64 = createSeqWindow(64);
        assertTrue(w64 != null, "w64 created");
    }

    public void testSeqWindowSequenceProgressionAndReordering() throws Exception {
        Object w = createSeqWindow(64);

        // Negative seq is TOO_OLD
        assertEquals("TOO_OLD", mark(w, -1));

        // First seq
        assertEquals("NEW", mark(w, 100));
        assertEquals(100L, highest(w));
        assertEquals(0L, missing(w));
        assertEquals(0L, reordered(w));

        // Next sequential
        assertEquals("NEW", mark(w, 101));
        assertEquals(101L, highest(w));
        assertEquals(0L, missing(w));

        // Duplicate
        assertEquals("DUPLICATE", mark(w, 100));
        assertEquals("DUPLICATE", mark(w, 101));

        // Advance jumping 5 sequences: skipped 102, 103, 104, 105 (4 missing)
        assertEquals("NEW", mark(w, 106));
        assertEquals(106L, highest(w));
        assertEquals(4L, missing(w));
        assertEquals(0L, reordered(w));

        // Arrive late (reordered within window)
        assertEquals("NEW", mark(w, 103));
        assertEquals(3L, missing(w));
        assertEquals(1L, reordered(w));

        // Duplicate of late arrival
        assertEquals("DUPLICATE", mark(w, 103));

        // Sequence too old (<= highest - size: 106 - 64 = 42)
        assertEquals("TOO_OLD", mark(w, 42));
        assertEquals("TOO_OLD", mark(w, 40));

        // Wide jump (advance >= size) clears bitmask
        assertEquals("NEW", mark(w, 300));
        assertEquals(300L, highest(w));
        assertEquals("TOO_OLD", mark(w, 106));
    }

    private static Object createSeqWindow(int size) throws Exception {
        Class<?> cls = Class.forName("eastguard.detector.SeqWindow");
        var ctor = cls.getDeclaredConstructor(int.class);
        ctor.setAccessible(true);
        try {
            return ctor.newInstance(size);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) throw re;
            throw new RuntimeException(e.getCause());
        }
    }

    private static String mark(Object window, long seq) throws Exception {
        var method = window.getClass().getDeclaredMethod("mark", long.class);
        method.setAccessible(true);
        Object res = method.invoke(window, seq);
        return res.toString();
    }

    private static long highest(Object window) throws Exception {
        var m = window.getClass().getDeclaredMethod("highest");
        m.setAccessible(true);
        return (long) m.invoke(window);
    }

    private static long missing(Object window) throws Exception {
        var m = window.getClass().getDeclaredMethod("missing");
        m.setAccessible(true);
        return (long) m.invoke(window);
    }

    private static long reordered(Object window) throws Exception {
        var m = window.getClass().getDeclaredMethod("reordered");
        m.setAccessible(true);
        return (long) m.invoke(window);
    }

    // ---------------------------------------------------------
    // CidrClassifier Tests
    // ---------------------------------------------------------

    public void testCidrClassifierZonesAndPrecedence() {
        Cidr protectedZone = Cidr.parse("10.0.0.0/24");
        Cidr sharedZone = Cidr.parse("10.0.1.0/24");
        Cidr managedZone = Cidr.parse("10.0.2.0/24");
        Cidr alsoManaged = Cidr.parse("10.0.0.0/16"); // Broader, overlaps with protected and shared

        // Protected takes precedence over broader managed
        CidrClassifier classifier = new CidrClassifier(List.of(alsoManaged, managedZone), List.of(sharedZone),
                List.of(protectedZone));

        assertEquals(CidrClassifier.Zone.PROTECTED, classifier.classify(IpAddress.parse("10.0.0.15")));
        assertFalse(classifier.eligibleForAutomation(IpAddress.parse("10.0.0.15")), "protected not eligible");

        assertEquals(CidrClassifier.Zone.SHARED, classifier.classify(IpAddress.parse("10.0.1.50")));
        assertFalse(classifier.eligibleForAutomation(IpAddress.parse("10.0.1.50")), "shared not eligible");

        assertEquals(CidrClassifier.Zone.MANAGED, classifier.classify(IpAddress.parse("10.0.2.99")));
        assertTrue(classifier.eligibleForAutomation(IpAddress.parse("10.0.2.99")), "managed eligible");

        assertEquals(CidrClassifier.Zone.UNMANAGED, classifier.classify(IpAddress.parse("192.168.1.1")));
        assertFalse(classifier.eligibleForAutomation(IpAddress.parse("192.168.1.1")), "unmanaged not eligible");

        assertEquals(CidrClassifier.Zone.UNMANAGED, CidrClassifier.NONE.classify(IpAddress.parse("10.0.2.99")));
        assertFalse(CidrClassifier.NONE.eligibleForAutomation(IpAddress.parse("10.0.2.99")), "NONE not eligible");
    }

    // ---------------------------------------------------------
    // LearningCollector Tests
    // ---------------------------------------------------------

    public void testLearningCollectorArgumentValidation() {
        assertThrows(IllegalArgumentException.class, () -> new LearningCollector(0, 10, 1000, 0));
        assertThrows(IllegalArgumentException.class, () -> new LearningCollector(10, 0, 1000, 0));
        assertThrows(IllegalArgumentException.class, () -> new LearningCollector(10, 501, 1000, 0));
        assertThrows(IllegalArgumentException.class, () -> new LearningCollector(10, 10, 0, 0));
    }

    public void testLearningCollectorObservationFilteringAndAggregation() {
        LearningCollector collector = new LearningCollector(2, 5, 1_000, 0);

        // Non-observation: Issuer kind
        TelemetryVerifier.Verified vTokensvc = new TelemetryVerifier.Verified(
                telemetry("web-01", "app-02", Verdict.ALLOW, true), ProducerInventory.Kind.ISSUER, 1000);
        assertFalse(LearningCollector.isObservation(vTokensvc), "issuer not observation");
        collector.accept(vTokensvc);
        assertEquals(0, collector.pending());
        assertEquals(0L, collector.observed());

        // Non-observation: Gateway with Verdict.DENY
        TelemetryVerifier.Verified vDeny = new TelemetryVerifier.Verified(
                telemetry("web-01", "app-02", Verdict.DENY, true), ProducerInventory.Kind.GATEWAY, 1000);
        assertFalse(LearningCollector.isObservation(vDeny), "deny not observation");
        collector.accept(vDeny);
        assertEquals(0, collector.pending());

        // Non-observation: inside approved graph (outsideApprovedGraph == false)
        TelemetryVerifier.Verified vApproved = new TelemetryVerifier.Verified(
                telemetry("web-01", "app-02", Verdict.ALLOW, false), ProducerInventory.Kind.GATEWAY, 1000);
        assertFalse(LearningCollector.isObservation(vApproved), "approved not observation");
        collector.accept(vApproved);
        assertEquals(0, collector.pending());

        // Valid observation 1: edge web-01 -> app-02
        TelemetryVerifier.Verified vObs1 = new TelemetryVerifier.Verified(
                telemetry("web-01", "app-02", Verdict.ALLOW, true, 1000), ProducerInventory.Kind.GATEWAY, 1000);
        assertTrue(LearningCollector.isObservation(vObs1), "valid observation");
        collector.accept(vObs1);
        assertEquals(1, collector.pending());
        assertEquals(1L, collector.observed());

        // Same edge again at later timestamp: aggregates into same pending edge
        TelemetryVerifier.Verified vObs1Later = new TelemetryVerifier.Verified(
                telemetry("web-01", "app-02", Verdict.ALLOW, true, 2000), ProducerInventory.Kind.GATEWAY, 2000);
        collector.accept(vObs1Later);
        assertEquals(1, collector.pending());
        assertEquals(2L, collector.observed());

        // Distinct edge 2: web-01 -> app-03 (reaches maxPending = 2)
        TelemetryVerifier.Verified vObs2 = new TelemetryVerifier.Verified(
                telemetry("web-01", "app-03", Verdict.ALLOW, true, 1500), ProducerInventory.Kind.GATEWAY, 1500);
        collector.accept(vObs2);
        assertEquals(2, collector.pending());
        assertEquals(3L, collector.observed());
        assertEquals(0L, collector.dropped());

        // Distinct edge 3: api-01 -> app-02 (dropped because pending == maxPending)
        TelemetryVerifier.Verified vObs3 = new TelemetryVerifier.Verified(
                telemetry("api-01", "app-02", Verdict.ALLOW, true, 1600), ProducerInventory.Kind.GATEWAY, 1600);
        collector.accept(vObs3);
        assertEquals(2, collector.pending());
        assertEquals(3L, collector.observed());
        assertEquals(1L, collector.dropped());

        // Not due yet before flush interval (nowNanos = 500ms, batchSize = 5 not reached)
        List<List<Dto.Observation>> batches = collector.due(500_000_000L);
        assertTrue(batches.isEmpty(), "batches empty before flush");

        // Due after flush interval (nowNanos = 1.1s > 1000ms flushMillis)
        batches = collector.due(1_100_000_000L);
        assertEquals(1, batches.size());
        assertEquals(2, batches.get(0).size());
        assertEquals(0, collector.pending());

        // Check aggregation of edge web-01 -> app-02
        Dto.Observation o1 = batches.get(0).get(0);
        assertEquals(new Edge("web-01", "app-02"), o1.edge());
        assertEquals(1000L, o1.firstSeenMillis());
        assertEquals(2000L, o1.lastSeenMillis());
        assertEquals(2L, o1.count());
    }

    private static Telemetry telemetry(String src, String service, Verdict v, boolean outside) {
        return telemetry(src, service, v, outside, 1000);
    }

    private static Telemetry telemetry(String src, String service, Verdict v, boolean outside, long timeMs) {
        ReasonCode reason = (v == Verdict.ALLOW) ? ReasonCode.OK : ReasonCode.POLICY_DENY;
        return new Telemetry("eg-demo", "gw-app-02", "tk1", Bytes.copyOf(new byte[16]), 1, timeMs,
                1, src, IpAddress.parse("10.0.1.10"), service, IpAddress.parse("10.0.2.10"), 9002,
                v, reason, outside);
    }

    // ---------------------------------------------------------
    // ActionDispatcher Tests
    // ---------------------------------------------------------

    public void testActionDispatcherQueueAndRetry() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        DetectorControl control = new DetectorControl() {
            @Override
            public Dto.MutationResult proposeAction(String reqId, Dto.ActionType type, List<Selector> sel,
                    Duration ttl, int score, List<String> sig, List<String> ev) throws IOException {
                int c = calls.incrementAndGet();
                if (c == 1) {
                    throw new IOException("transient error");
                }
                return new Dto.MutationResult(null, null, 10, 5, false);
            }

            @Override
            public Dto.MutationResult recordObservations(String reqId, List<Dto.Observation> obs) {
                return new Dto.MutationResult(null, null, 10, 5, false);
            }
        };

        try (ActionDispatcher dispatcher = new ActionDispatcher(control, 10, 3, 10)) {
            RiskEngine.Proposal proposal = new RiskEngine.Proposal(RiskEngine.ActionType.QUARANTINE,
                    Selector.identity("web-01"), 100, List.of("DECOY"), List.of("evidence"));

            boolean submitted = dispatcher.propose("req-1", proposal, Duration.ofMinutes(5));
            assertTrue(submitted, "proposal submitted");

            boolean idle = dispatcher.awaitIdle(Duration.ofSeconds(2));
            assertTrue(idle, "dispatcher idle");
            assertEquals(2, calls.get()); // First failed, retry succeeded
        }
    }
}
