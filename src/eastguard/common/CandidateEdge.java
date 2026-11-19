package eastguard.common;

import java.time.Instant;
import java.util.Objects;

/** An edge observed during the learning pilot; it grants nothing until an operator freezes it (spec §3.2). */
public record CandidateEdge(Edge edge, Instant firstSeen, Instant lastSeen, long observations) {
    public CandidateEdge {
        Objects.requireNonNull(edge, "edge");
        Objects.requireNonNull(firstSeen, "firstSeen");
        Objects.requireNonNull(lastSeen, "lastSeen");
        if (lastSeen.isBefore(firstSeen)) {
            throw new IllegalArgumentException("lastSeen before firstSeen");
        }
        if (observations < 1) {
            throw new IllegalArgumentException("observations must be positive");
        }
    }
}
