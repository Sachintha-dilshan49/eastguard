package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Alert;
import eastguard.common.AlertStatus;
import eastguard.common.Bytes;
import eastguard.common.CandidateEdge;
import eastguard.common.Cidr;
import eastguard.common.Edge;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.IpAddress;
import eastguard.common.LearningDraft;
import eastguard.common.LeaseReduction;
import eastguard.common.PilotScope;
import eastguard.common.Policy;
import eastguard.common.PolicyMode;
import eastguard.common.ReasonCode;
import eastguard.common.Restriction;
import eastguard.common.Selector;
import eastguard.common.SelectorType;
import eastguard.common.Service;
import eastguard.common.Workload;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class DomainTest {
    private static final Instant T0 = Instant.parse("2026-11-19T10:00:00Z");

    public void testEndpointParse() {
        assertEquals(new Endpoint(IpAddress.parse("10.0.0.1"), 8443), Endpoint.parse("10.0.0.1:8443"));
        assertEquals(new Endpoint(IpAddress.parse("2001:db8::1"), 443), Endpoint.parse("[2001:db8::1]:443"));
        Endpoint v6 = Endpoint.parse("[2001:db8::1]:443");
        assertEquals(v6, Endpoint.parse(v6.toString()));
        assertEquals("10.0.0.1:8443", Endpoint.parse("10.0.0.1:8443").toString());
        for (String bad : new String[] {"10.0.0.1", "10.0.0.1:0", "10.0.0.1:65536", "2001:db8::1:443",
                "host:80", "10.0.0.1:+80", "[::1]80", "10.0.0.1:"}) {
            assertThrows(IllegalArgumentException.class, () -> Endpoint.parse(bad));
        }
    }

    public void testSelectorExactlyOneTarget() {
        Selector id = Selector.identity("web-01");
        Selector ip = Selector.ip(IpAddress.parse("10.0.0.5"));
        assertTrue(id.matches("web-01", IpAddress.parse("1.1.1.1")), "identity match ignores ip");
        assertFalse(id.matches(null, IpAddress.parse("1.1.1.1")), "no identity, no match");
        assertTrue(ip.matches(null, IpAddress.parse("10.0.0.5")), "ip match ignores identity");
        assertFalse(ip.matches("web-01", IpAddress.parse("10.0.0.6")), "different ip");
        assertThrows(IllegalArgumentException.class,
                () -> new Selector(SelectorType.IDENTITY, "web-01", IpAddress.parse("10.0.0.5")));
        assertThrows(IllegalArgumentException.class,
                () -> new Selector(SelectorType.IP, "web-01", IpAddress.parse("10.0.0.5")));
        assertThrows(NullPointerException.class, () -> new Selector(SelectorType.IP, null, null));
        assertThrows(IllegalArgumentException.class, () -> Selector.identity("Bad"));
    }

    public void testRecordsDefensivelyCopyCollections() {
        Set<Edge> edges = new HashSet<>(Set.of(new Edge("web-01", "app-02")));
        Policy p = new Policy(PolicyMode.ENFORCE, edges, PilotScope.NONE, 1, Duration.ofSeconds(60));
        edges.add(new Edge("evil", "app-02"));
        assertEquals(1, p.approvedEdges().size());
        assertThrows(UnsupportedOperationException.class, () -> p.approvedEdges().add(new Edge("x", "y")));

        List<String> signals = new ArrayList<>(List.of("DECOY_TOUCH"));
        Alert a = new Alert("a-1", null, IpAddress.parse("10.0.0.9"), signals, 100, AlertStatus.OPEN,
                List.of("gw-1/1"), T0);
        signals.clear();
        assertEquals(List.of("DECOY_TOUCH"), a.signals());

        Map<String, Workload> workloads = new HashMap<>(Map.of("web-01", Workload.enabled("web-01")));
        EnforcementSnapshot s = snapshot(workloads, List.of(), Map.of(), 5);
        workloads.clear();
        assertEquals(1, s.workloads().size());
    }

    public void testPolicyRules() {
        Edge approved = new Edge("web-01", "app-02");
        Edge pilot = new Edge("batch-01", "app-02");
        Edge unscoped = new Edge("batch-01", "db-01");
        PilotScope scope = new PilotScope(Set.of("batch-01"), Set.of("app-02"));
        Policy learn = new Policy(PolicyMode.LEARN, Set.of(approved), scope, 3, Duration.ofSeconds(60));
        Policy enforce = new Policy(PolicyMode.ENFORCE, Set.of(approved), scope, 3, Duration.ofSeconds(60));
        assertTrue(learn.isApproved(approved), "approved");
        assertFalse(learn.isPilotEdge(approved), "approved edge is not a pilot edge");
        assertTrue(learn.isPilotEdge(pilot), "pilot in LEARN");
        assertFalse(learn.isPilotEdge(unscoped), "unscoped stays out");
        assertFalse(enforce.isPilotEdge(pilot), "ENFORCE ignores the pilot scope");
    }

    public void testLeaseLengthBounds() {
        assertThrows(IllegalArgumentException.class,
                () -> new Policy(PolicyMode.ENFORCE, Set.of(), PilotScope.NONE, 0, Duration.ofSeconds(61)));
        assertThrows(IllegalArgumentException.class,
                () -> new Policy(PolicyMode.ENFORCE, Set.of(), PilotScope.NONE, 0, Duration.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> new Policy(PolicyMode.ENFORCE, Set.of(), PilotScope.NONE, -1, Duration.ofSeconds(10)));
        assertThrows(IllegalArgumentException.class, () -> new LeaseReduction(Selector.identity("web-01"),
                Duration.ofSeconds(-1), T0, 1));
    }

    public void testWorkloadCredentialRestrictionsAndZone() {
        Bytes fp = Bytes.copyOf(new byte[32]);
        Workload w = new Workload("web-01", true, Set.of(fp), Cidr.parse("10.1.0.0/16"));
        assertTrue(w.isCertificateRevoked(fp), "revoked fingerprint");
        assertTrue(w.allowsIp(IpAddress.parse("10.1.2.3")), "inside zone");
        assertFalse(w.allowsIp(IpAddress.parse("10.2.0.1")), "outside zone");
        assertFalse(w.allowsIp(IpAddress.parse("2001:db8::1")), "other family outside zone");
        assertTrue(Workload.enabled("web-01").allowsIp(IpAddress.parse("2001:db8::1")), "no zone allows any ip");
        assertThrows(IllegalArgumentException.class,
                () -> new Workload("web-01", true, Set.of(Bytes.copyOf(new byte[31])), null));
    }

    public void testLearningDraftRejectsDuplicates() {
        CandidateEdge c = new CandidateEdge(new Edge("a", "b"), T0, T0.plusSeconds(5), 3);
        assertEquals(Set.of(new Edge("a", "b")), new LearningDraft(List.of(c), 1).edges());
        assertThrows(IllegalArgumentException.class, () -> new LearningDraft(List.of(c, c), 1));
        assertThrows(IllegalArgumentException.class,
                () -> new CandidateEdge(new Edge("a", "b"), T0, T0.minusSeconds(1), 1));
        assertThrows(IllegalArgumentException.class, () -> new CandidateEdge(new Edge("a", "b"), T0, T0, 0));
    }

    public void testRestrictionValidation() {
        assertThrows(IllegalArgumentException.class, () -> new Restriction(Selector.identity("web-01"),
                ReasonCode.DECOY_TOUCH, "detector", T0, T0, 1));
        assertThrows(IllegalArgumentException.class, () -> new Restriction(Selector.identity("web-01"),
                ReasonCode.DECOY_TOUCH, "Bad Actor", T0, T0.plusSeconds(1), 1));
    }

    public void testServiceValidation() {
        Endpoint e = Endpoint.parse("127.0.0.1:9000");
        new Service("app-02", "gw-1", e, "gateway.eastguard.test", e);
        assertThrows(IllegalArgumentException.class, () -> new Service("app-02", "gw-1", e, "bad name", e));
        assertThrows(IllegalArgumentException.class, () -> new Service("app-02", "gw-1", e, "", e));
    }

    public void testSnapshotConsistency() {
        Restriction newer = new Restriction(Selector.identity("web-01"), ReasonCode.OPERATOR_ACTION, "ops",
                T0, T0.plusSeconds(60), 6);
        assertThrows(IllegalArgumentException.class, () -> snapshot(Map.of(), List.of(newer), Map.of(), 5));
        assertThrows(IllegalArgumentException.class,
                () -> snapshot(Map.of(), List.of(), Map.of(Selector.identity("web-01"), 6L), 5));
        assertThrows(IllegalArgumentException.class,
                () -> snapshot(Map.of("web-02", Workload.enabled("web-01")), List.of(), Map.of(), 5));
        // Policy revision newer than the snapshot is inconsistent.
        Policy p = new Policy(PolicyMode.ENFORCE, Set.of(), PilotScope.NONE, 9, Duration.ofSeconds(60));
        assertThrows(IllegalArgumentException.class, () -> new EnforcementSnapshot("c1", 5, p, Map.of(), Map.of(),
                List.of(), List.of(), Map.of(), Map.of(), Set.of()));
    }

    private static EnforcementSnapshot snapshot(Map<String, Workload> workloads, List<Restriction> restrictions,
            Map<Selector, Long> watermarks, long revision) {
        Policy p = new Policy(PolicyMode.ENFORCE, Set.of(), PilotScope.NONE, 1, Duration.ofSeconds(60));
        return new EnforcementSnapshot("c1", revision, p, workloads, Map.of(), restrictions, List.of(), watermarks,
                Map.of(), Set.of());
    }
}
