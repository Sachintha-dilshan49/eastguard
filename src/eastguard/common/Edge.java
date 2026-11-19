package eastguard.common;

/**
 * An allowed (or candidate) connection: source workload identity to service. The service determines the
 * listener and fixed backend, so the caller never chooses a relay destination (spec §3.1).
 */
public record Edge(String sourceIdentity, String serviceId) {
    public Edge {
        Ids.require(sourceIdentity, "sourceIdentity");
        Ids.require(serviceId, "serviceId");
    }

    @Override
    public String toString() {
        return sourceIdentity + "->" + serviceId;
    }
}
