package eastguard.dashboard;

import eastguard.common.Edge;
import eastguard.common.SelectorType;
import eastguard.control.Dto;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * What the topology panel draws, derived from one {@link ConsoleSnapshot} (spec §7.3 topology). Every node and
 * link carries a text label and a symbol, not only a colour, so the view is readable without colour vision.
 *
 * <ul>
 *   <li>APPROVED: an edge of the active allow-list.</li>
 *   <li>CANDIDATE: a learning observation, not a permission.</li>
 *   <li>DENIED: a denied flow (demo fixtures only; live denials appear as a marker on the source from alerts).</li>
 *   <li>BLAST_RADIUS: an approved edge from a quarantined identity: where it could still be <em>allowed</em> to go
 *       once released, i.e. its potential blast radius. Not observed compromise.</li>
 * </ul>
 */
public record TopologyModel(List<Node> workloads, List<Node> services, List<Link> links, List<String> ipRestrictions) {
    public static final String BLAST_RADIUS_LABEL = "potential blast radius (allowed by policy; not observed compromise)";

    public enum LinkKind {
        APPROVED("✔", "approved"),
        CANDIDATE("?", "candidate (observed in pilot, not approved)"),
        DENIED("✖", "denied"),
        BLAST_RADIUS("⚠", BLAST_RADIUS_LABEL);

        public final String symbol;
        public final String label;

        LinkKind(String symbol, String label) {
            this.symbol = symbol;
            this.label = label;
        }
    }

    /**
     * @param markers short labels such as {@code "QUARANTINED"} or {@code "DENIALS (alert)"}
     */
    public record Node(String id, List<String> markers) {
        public Node {
            markers = List.copyOf(markers);
        }

        public boolean quarantined() {
            return markers.contains(QUARANTINED);
        }
    }

    public record Link(Edge edge, LinkKind kind) {
    }

    public static final String QUARANTINED = "⛔ QUARANTINED";
    public static final String DENIALS = "✖ DENIALS (alert)";

    public TopologyModel {
        workloads = List.copyOf(workloads);
        services = List.copyOf(services);
        links = List.copyOf(links);
        ipRestrictions = List.copyOf(ipRestrictions);
    }

    public static TopologyModel of(ConsoleSnapshot s) {
        Dto.DashboardView d = s.dashboard();
        Dto.LearningDraftView draft = s.draft();
        Set<String> quarantined = new LinkedHashSet<>();
        List<String> ips = new ArrayList<>();
        for (Dto.RestrictionView r : d.restrictions()) {
            if (r.selector().type() == SelectorType.IDENTITY) {
                quarantined.add(r.selector().identity());
            } else {
                ips.add(r.selector().ip() + " " + QUARANTINED);
            }
        }
        Set<String> denied = new LinkedHashSet<>();
        for (Dto.AlertView a : d.alerts()) {
            if (a.signals().contains("POLICY_DENY") || a.signals().contains("SECURITY_DENY")) {
                a.selectors().stream().filter(x -> x.type() == SelectorType.IDENTITY).forEach(x -> denied.add(x.identity()));
            }
        }
        Map<String, List<String>> marks = new LinkedHashMap<>();
        d.workloads().forEach(w -> marks.put(w, new ArrayList<>()));
        quarantined.forEach(w -> marks.computeIfAbsent(w, k -> new ArrayList<>()).add(QUARANTINED));
        denied.forEach(w -> marks.computeIfAbsent(w, k -> new ArrayList<>()).add(DENIALS));
        List<Node> workloads = marks.entrySet().stream().map(e -> new Node(e.getKey(), e.getValue())).toList();
        List<Node> services = d.services().stream().map(x -> new Node(x, List.of())).toList();

        List<Link> links = new ArrayList<>();
        Set<Edge> approved = new LinkedHashSet<>(draft.approved());
        for (Edge e : draft.approved()) {
            links.add(new Link(e, quarantined.contains(e.sourceIdentity()) ? LinkKind.BLAST_RADIUS : LinkKind.APPROVED));
        }
        for (Dto.Observation o : draft.candidates()) {
            if (!approved.contains(o.edge())) {
                links.add(new Link(o.edge(), LinkKind.CANDIDATE));
            }
        }
        for (Edge e : s.deniedEdges()) {
            links.add(new Link(e, LinkKind.DENIED));
        }
        return new TopologyModel(workloads, services, links, ips);
    }

    /** Services a quarantined identity is directly allowed to reach by policy: its potential blast radius. */
    public static List<String> blastRadius(String identity, List<Edge> approved) {
        return approved.stream().filter(e -> e.sourceIdentity().equals(identity)).map(Edge::serviceId).distinct()
                .sorted().toList();
    }
}
