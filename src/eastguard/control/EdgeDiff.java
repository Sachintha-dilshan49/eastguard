package eastguard.control;

import eastguard.common.Edge;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The exact difference between the current allow-list and a reviewed one (spec §3.2 "show additions, removals").
 * The dashboard's freeze preview and the control plane's audit record use this one function, so the preview
 * shows exactly what a freeze commits.
 *
 * @param additions edges in the reviewed set that are not approved now, sorted
 * @param removals  edges approved now that the reviewed set leaves out, sorted
 * @param kept      edges in both, sorted
 */
public record EdgeDiff(List<Edge> additions, List<Edge> removals, List<Edge> kept) {
    public EdgeDiff {
        additions = List.copyOf(additions);
        removals = List.copyOf(removals);
        kept = List.copyOf(kept);
    }

    public static EdgeDiff of(Collection<Edge> current, Collection<Edge> reviewed) {
        Set<Edge> now = new HashSet<>(current);
        Set<Edge> next = new HashSet<>(reviewed);
        return new EdgeDiff(
                next.stream().filter(e -> !now.contains(e)).sorted(Dto.EDGE_ORDER).toList(),
                now.stream().filter(e -> !next.contains(e)).sorted(Dto.EDGE_ORDER).toList(),
                next.stream().filter(now::contains).sorted(Dto.EDGE_ORDER).toList());
    }

    public boolean empty() {
        return additions.isEmpty() && removals.isEmpty();
    }

    /** {@code [+a->s, -b->s]}, as recorded in the audit. */
    @Override
    public String toString() {
        StringBuilder b = new StringBuilder("[");
        additions.forEach(e -> b.append(b.length() > 1 ? ", " : "").append('+').append(e));
        removals.forEach(e -> b.append(b.length() > 1 ? ", " : "").append('-').append(e));
        return b.append(']').toString();
    }
}
