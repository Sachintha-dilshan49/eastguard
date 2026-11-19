package eastguard.common;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Candidate edges collected in LEARN mode. Versioned separately from the enforcement revision so a new
 * observation does not invalidate every gateway's snapshot (spec §3.1).
 */
public record LearningDraft(List<CandidateEdge> candidates, long version) {
    public static final LearningDraft EMPTY = new LearningDraft(List.of(), 0);

    public LearningDraft {
        candidates = List.copyOf(Objects.requireNonNull(candidates, "candidates"));
        if (version < 0) {
            throw new IllegalArgumentException("draft version negative");
        }
        Set<Edge> seen = new HashSet<>();
        for (CandidateEdge c : candidates) {
            if (!seen.add(c.edge())) {
                throw new IllegalArgumentException("duplicate candidate edge");
            }
        }
    }

    public Set<Edge> edges() {
        Set<Edge> out = new HashSet<>();
        candidates.forEach(c -> out.add(c.edge()));
        return Set.copyOf(out);
    }
}
