package eastguard.handlers;

import eastguard.control.Dto;
import java.io.IOException;

/**
 * Where {@code ztp://policy/<service>} reads come from: the configured control-plane client (spec §7.3), e.g.
 * {@code ControlClient::getPolicy}. The URL only names the service; it never chooses the endpoint.
 */
@FunctionalInterface
public interface PolicySource {
    Dto.PolicyView policy(String serviceId) throws IOException;
}
