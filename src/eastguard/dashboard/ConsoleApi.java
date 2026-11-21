package eastguard.dashboard;

import eastguard.common.Edge;
import eastguard.common.Selector;
import eastguard.control.ControlClient;
import eastguard.control.Dto;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * What the dashboard needs from the control plane (spec §8 adapter): the RMI client in production
 * ({@link #rmi}), labeled fixtures in the demo profile ({@link FixtureScenarios}), and slow or failing doubles in
 * tests. Every method may block for the RMI deadlines; only {@link ConsoleWorker} calls it, never the EDT.
 */
public interface ConsoleApi {
    /** Recent audit, restrictions and alerts, the caller's role, known workloads and services. */
    Dto.DashboardView dashboard(int limit) throws IOException;

    /** Approved edges, the learning draft and its version. */
    Dto.LearningDraftView learningDraft() throws IOException;

    Dto.MutationResult quarantine(String requestId, List<Selector> selectors, Duration ttl, String reason)
            throws IOException;

    Dto.MutationResult release(String requestId, List<Selector> selectors, String reason) throws IOException;

    Dto.MutationResult freeze(String requestId, long expectedPolicyRevision, long expectedDraftVersion,
            List<Edge> reviewedEdges, String reason) throws IOException;

    /** The label of the demo fixture being served, or {@code null} for live data. */
    default String fixtureLabel() {
        return null;
    }

    /** Denied flows to draw (fixtures only; the control plane has no per-flow denial feed). */
    default List<Edge> deniedEdges() {
        return List.of();
    }

    static ConsoleApi rmi(ControlClient c) {
        Objects.requireNonNull(c, "client");
        return new ConsoleApi() {
            public Dto.DashboardView dashboard(int limit) throws IOException {
                return c.getDashboard(0, limit);
            }

            public Dto.LearningDraftView learningDraft() throws IOException {
                return c.getLearningDraft();
            }

            public Dto.MutationResult quarantine(String id, List<Selector> s, Duration ttl, String reason)
                    throws IOException {
                return c.quarantine(id, s, ttl, reason);
            }

            public Dto.MutationResult release(String id, List<Selector> s, String reason) throws IOException {
                return c.release(id, s, reason);
            }

            public Dto.MutationResult freeze(String id, long policyRevision, long draftVersion, List<Edge> edges,
                    String reason) throws IOException {
                return c.freezeBaseline(id, policyRevision, draftVersion, edges, reason);
            }
        };
    }
}
