package eastguard.common;

import java.util.Objects;

/**
 * Protected service (spec §3.1). Each protected listener has its own service ID; the backend is fixed.
 *
 * @param tlsServerName DNS name or IP literal the client validates against the gateway certificate SAN
 */
public record Service(String id, String gatewayId, Endpoint listener, String tlsServerName, Endpoint backend) {
    public Service {
        Ids.require(id, "service id");
        Ids.require(gatewayId, "gateway id");
        Objects.requireNonNull(listener, "listener");
        Objects.requireNonNull(backend, "backend");
        if (tlsServerName == null || tlsServerName.isEmpty() || tlsServerName.length() > 253
                || !tlsServerName.chars().allMatch(c -> c > 0x20 && c < 0x7f)) {
            throw new IllegalArgumentException("invalid tls server name");
        }
    }
}
