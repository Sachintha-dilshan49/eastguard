package eastguard.common;

import java.time.Duration;
import java.util.Objects;
import java.util.Set;

/** Access policy (spec §3.1, §3.2). Default deny: only approved edges, plus pilot edges in LEARN mode. */
public record Policy(PolicyMode mode, Set<Edge> approvedEdges, PilotScope pilotScope, long revision,
        Duration defaultLeaseLength) {

    public static final Duration MAX_LEASE = Duration.ofSeconds(60);

    public Policy {
        Objects.requireNonNull(mode, "mode");
        approvedEdges = Set.copyOf(Objects.requireNonNull(approvedEdges, "approvedEdges"));
        Objects.requireNonNull(pilotScope, "pilotScope");
        Objects.requireNonNull(defaultLeaseLength, "defaultLeaseLength");
        if (revision < 0) {
            throw new IllegalArgumentException("policy revision negative");
        }
        requireLeaseLength(defaultLeaseLength);
    }

    /** Lease lengths are whole milliseconds in {@code (0, 60s]}. */
    static void requireLeaseLength(Duration d) {
        if (d.compareTo(Duration.ofMillis(1)) < 0 || d.compareTo(MAX_LEASE) > 0) {
            throw new IllegalArgumentException("lease length must be in (0, 60s]");
        }
    }

    public boolean isApproved(Edge edge) {
        return approvedEdges.contains(edge);
    }

    /** True only in LEARN mode for an unapproved edge inside the explicit pilot scope. */
    public boolean isPilotEdge(Edge edge) {
        return mode == PolicyMode.LEARN && !isApproved(edge) && pilotScope.covers(edge);
    }
}
