package eastguard.handlers;

import eastguard.common.Edge;
import eastguard.common.Ids;
import eastguard.common.PolicyMode;
import eastguard.control.Dto;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * Typed, read-only policy of one service, as returned by {@code ztp://policy/<service>} through
 * {@link PolicyContentHandler} (spec §7.3).
 *
 * @param allowedSources workload identities with an approved edge to this service, sorted
 */
public record PolicyView(String serviceId, PolicyMode mode, long policyRevision, long enforcementRevision,
        Duration defaultLease, List<String> allowedSources) {
    public PolicyView {
        Ids.require(serviceId, "serviceId");
        Objects.requireNonNull(mode, "mode");
        Objects.requireNonNull(defaultLease, "defaultLease");
        allowedSources = List.copyOf(allowedSources);
    }

    /** Converts a successful control-plane answer for {@code serviceId}; anything else is an error. */
    static PolicyView from(String serviceId, Dto.PolicyView v) throws IOException {
        if (v == null || !v.ok() || v.mode() == null) {
            throw new IOException("policy read failed: " + (v == null ? "no answer" : v.error() + " " + v.message()));
        }
        for (Edge e : v.edges()) {
            if (!e.serviceId().equals(serviceId)) {
                throw new IOException("control plane returned an edge for another service");
            }
        }
        List<String> sources = v.edges().stream().map(Edge::sourceIdentity).distinct().sorted().toList();
        return new PolicyView(serviceId, v.mode(), v.policyRevision(), v.revision(),
                Duration.ofMillis(v.defaultLeaseMillis()), sources);
    }

    /** {@code key=value} lines, the connection's byte form. */
    String toText() {
        return "service=" + serviceId + "\nmode=" + mode + "\npolicyRevision=" + policyRevision + "\nrevision="
                + enforcementRevision + "\ndefaultLeaseMillis=" + defaultLease.toMillis() + "\nallowedSources="
                + String.join(",", allowedSources) + "\n";
    }
}
