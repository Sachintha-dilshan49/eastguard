package eastguard.common;

import java.util.Objects;
import java.util.Set;

/**
 * Explicit learning-pilot scope (spec §3.2): an edge is in scope only if both its source identity and its
 * service are listed. Being in the same CIDR or holding a valid certificate never puts traffic in scope.
 */
public record PilotScope(Set<String> sourceIdentities, Set<String> serviceIds) {
    public static final PilotScope NONE = new PilotScope(Set.of(), Set.of());

    public PilotScope {
        sourceIdentities = Set.copyOf(Objects.requireNonNull(sourceIdentities, "sourceIdentities"));
        serviceIds = Set.copyOf(Objects.requireNonNull(serviceIds, "serviceIds"));
        sourceIdentities.forEach(id -> Ids.require(id, "pilot source"));
        serviceIds.forEach(id -> Ids.require(id, "pilot service"));
    }

    public boolean covers(Edge edge) {
        return sourceIdentities.contains(edge.sourceIdentity()) && serviceIds.contains(edge.serviceId());
    }
}
