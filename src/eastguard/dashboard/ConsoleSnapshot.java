package eastguard.dashboard;

import eastguard.common.Edge;
import eastguard.control.Dto;
import java.util.List;
import java.util.Objects;

/**
 * The data of one successful poll: the dashboard and learning-draft reads, taken together.
 *
 * @param fixture      the label of a demo fixture scenario, or {@code null} for live control-plane data
 * @param deniedEdges  denied flows to draw in the topology; only fixtures carry them (the control plane has no
 *                     per-flow denial feed, see DEVIATIONS 9.4)
 * @param fetchedAtMillis wall-clock time of the poll, for display only
 */
public record ConsoleSnapshot(Dto.DashboardView dashboard, Dto.LearningDraftView draft, String fixture,
        List<Edge> deniedEdges, long fetchedAtMillis) {
    public ConsoleSnapshot {
        Objects.requireNonNull(dashboard, "dashboard");
        Objects.requireNonNull(draft, "draft");
        deniedEdges = List.copyOf(deniedEdges);
    }
}
