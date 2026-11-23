package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Edge;
import eastguard.common.IpAddress;
import eastguard.common.PolicyMode;
import eastguard.common.Selector;
import eastguard.control.Dto;
import eastguard.control.Role;
import eastguard.dashboard.AlertRows;
import eastguard.dashboard.ConsoleApi;
import eastguard.dashboard.ConsoleSnapshot;
import eastguard.dashboard.FixtureScenarios;
import eastguard.dashboard.TopologyModel;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

/**
 * Tests for dashboard domain models and demo fixtures:
 * {@link TopologyModel}, {@link AlertRows}, and {@link FixtureScenarios}.
 */
public final class DashboardComponentsTest {
    private static final Clock FIXED = Clock.fixed(Instant.parse("2026-03-01T12:00:00Z"), ZoneOffset.UTC);

    public void testTopologyModelDerivation() {
        Edge approvedEdge = new Edge("web-01", "app-02");
        Edge candidateEdge = new Edge("api-01", "app-02");
        Edge deniedEdge = new Edge("untrusted-01", "app-02");

        Dto.RestrictionView rId = new Dto.RestrictionView(Selector.identity("web-01"), "RISK", "detector",
                1000, 2000, 10);
        Dto.RestrictionView rIp = new Dto.RestrictionView(Selector.ip(IpAddress.parse("10.0.1.50")), "DECOY", "operator",
                1000, 2000, 11);

        Dto.AlertView denyAlert = new Dto.AlertView("alert-1", "detector", Dto.ActionType.QUARANTINE,
                List.of(Selector.identity("web-01")), 60, List.of("POLICY_DENY"), List.of("evidence-1"), 1000,
                0, -1, "refused");

        Dto.DashboardView dash = new Dto.DashboardView(null, null, 10, 5, PolicyMode.LEARN,
                List.of(rId, rIp), List.of(), 0, List.of(denyAlert), Role.OPERATOR,
                List.of("web-01", "api-01"), List.of("app-02"));

        Dto.LearningDraftView draft = new Dto.LearningDraftView(null, null, 10, 5, 1, PolicyMode.LEARN,
                List.of("web-01", "api-01"), List.of("app-02"), List.of(approvedEdge),
                List.of(new Dto.Observation(candidateEdge, 100, 200, 5)), 0, 0, 0);

        ConsoleSnapshot snap = new ConsoleSnapshot(dash, draft, null, List.of(deniedEdge), 1000);
        TopologyModel topo = TopologyModel.of(snap);

        // Web-01 is quarantined and has denials
        TopologyModel.Node webNode = topo.workloads().stream().filter(n -> n.id().equals("web-01")).findFirst().orElseThrow();
        assertTrue(webNode.quarantined(), "web-01 quarantined");
        assertTrue(webNode.markers().contains(TopologyModel.QUARANTINED), "web-01 has quarantined marker");
        assertTrue(webNode.markers().contains(TopologyModel.DENIALS), "web-01 has denials marker");

        // Links
        // web-01 is quarantined, so its approved edge becomes BLAST_RADIUS
        TopologyModel.Link link1 = topo.links().stream().filter(l -> l.edge().equals(approvedEdge)).findFirst().orElseThrow();
        assertEquals(TopologyModel.LinkKind.BLAST_RADIUS, link1.kind());

        // candidate edge
        TopologyModel.Link link2 = topo.links().stream().filter(l -> l.edge().equals(candidateEdge)).findFirst().orElseThrow();
        assertEquals(TopologyModel.LinkKind.CANDIDATE, link2.kind());

        // denied edge
        TopologyModel.Link link3 = topo.links().stream().filter(l -> l.edge().equals(deniedEdge)).findFirst().orElseThrow();
        assertEquals(TopologyModel.LinkKind.DENIED, link3.kind());

        // IP restrictions
        assertEquals(1, topo.ipRestrictions().size());
        assertTrue(topo.ipRestrictions().get(0).contains("10.0.1.50"), "ip restriction contains 10.0.1.50");

        // Blast radius helper
        List<String> radius = TopologyModel.blastRadius("web-01", List.of(approvedEdge, new Edge("web-01", "app-03")));
        assertEquals(List.of("app-02", "app-03"), radius);
    }

    public void testAlertRowsFormatting() {
        Dto.AlertView committed = new Dto.AlertView("a-1", "detector", Dto.ActionType.QUARANTINE,
                List.of(Selector.identity("web-01")), 100, List.of("DECOY"), List.of(), 1000, 5000, 12,
                Dto.AlertView.COMMITTED);
        Dto.AlertView proposed = new Dto.AlertView("a-2", "detector", Dto.ActionType.LEASE_REDUCTION,
                List.of(Selector.ip(IpAddress.parse("10.0.1.10"))), 50, List.of("PORT_SCAN"), List.of(), 2000, 0, -1,
                "refused");

        Dto.DashboardView dash = new Dto.DashboardView(null, null, 12, 5, PolicyMode.ENFORCE,
                List.of(), List.of(), 0, List.of(committed, proposed), Role.VIEWER, List.of(), List.of());

        List<AlertRows.Row> rows = AlertRows.of(dash);
        assertEquals(2, rows.size());

        // Reverse sorted by timestamp (newest first)
        AlertRows.Row first = rows.get(0);
        assertEquals(AlertRows.PROPOSED, first.stage());
        assertEquals("IP 10.0.1.10", first.target());
        assertEquals(50, first.score());
        assertEquals("PORT_SCAN", first.signals());
        assertEquals("refused", first.outcome());

        AlertRows.Row second = rows.get(1);
        assertEquals(AlertRows.COMMITTED, second.stage());
        assertEquals("identity web-01", second.target());
        assertEquals(100, second.score());
        assertTrue(second.outcome().contains("committed at revision 12"), second.outcome());
    }

    public void testFixtureScenariosAllAndApi() throws Exception {
        List<FixtureScenarios.Scenario> scenarios = FixtureScenarios.all(FIXED);
        assertEquals(3, scenarios.size());

        FixtureScenarios.Scenario sA = scenarios.get(0);
        assertTrue(sA.label().contains("Fixture A"), "scenario A label");
        assertTrue(sA.dashboard() != null, "dashboard not null");
        assertTrue(sA.draft() != null, "draft not null");

        ConsoleApi api = FixtureScenarios.api(() -> sA);
        assertTrue(api.dashboard(10) != null, "api dashboard not null");
        assertTrue(api.learningDraft() != null, "api draft not null");
        assertTrue(api.fixtureLabel().contains("Fixture A"), "api fixture label");

        // All mutations return UNAVAILABLE in fixture demo mode
        Dto.MutationResult r = api.quarantine("req", List.of(Selector.identity("web-01")), Duration.ofMinutes(5), "test");
        assertEquals(Dto.ErrorCode.UNAVAILABLE, r.error());
        assertFalse(r.ok(), "mutation not ok");
    }
}
