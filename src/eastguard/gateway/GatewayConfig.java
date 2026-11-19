package eastguard.gateway;

import eastguard.common.BootstrapState;
import eastguard.common.Config;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.Ids;
import eastguard.common.SecretSource;
import eastguard.tokensvc.TlsContextFactory;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Gateway configuration (spec §9.1), see {@code config/gateway-app-02.properties.example}.
 *
 * <pre>
 * gateway.service=app-02                 fixed service ID: the only lease audience this gateway accepts
 * listen=127.0.0.1:9002                  workload-facing mTLS listener
 * backend=127.0.0.1:7002                 fixed private backend (numeric; never resolved)
 * decoy.listen=127.0.0.1:9003            optional accept-and-close decoy
 * decoy.id=decoy-9003                    telemetry service ID for decoy hits (default "decoy")
 * tls.keyStore, tls.trustStore, tls.passwordEnv, tls.passwordFile    as for the token service
 * limits.*                               see {@link GatewayLimits}
 * bootstrap.file=config/token.properties.example
 * </pre>
 *
 * Until control-plane sync exists (Task 6) the gateway uses the same static bootstrap snapshot as the token
 * service: {@code bootstrap.file} names a file whose {@code cluster.id}, {@code lease.defaultSeconds} and
 * {@code bootstrap.*} keys are read by {@link BootstrapState}. The configured service must exist in it.
 */
public record GatewayConfig(String serviceId, Endpoint listen, Endpoint backend, Endpoint decoyListen, String decoyId,
        TlsContextFactory.Material tls, GatewayLimits limits, EnforcementSnapshot bootstrap) {

    public GatewayConfig {
        Ids.require(serviceId, "serviceId");
        Objects.requireNonNull(listen, "listen");
        Objects.requireNonNull(backend, "backend");
        Ids.require(decoyId, "decoyId");
        Objects.requireNonNull(tls, "tls");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(bootstrap, "bootstrap");
        if (!bootstrap.services().containsKey(serviceId)) {
            throw new IllegalArgumentException("bootstrap state has no service '" + serviceId + "'");
        }
    }

    public static GatewayConfig load(Path file) {
        return from(Config.load(file));
    }

    public static GatewayConfig from(Config c) {
        String service = c.id("gateway.service");
        Endpoint listen = c.endpoint("listen");
        Endpoint backend = c.endpoint("backend");
        Endpoint decoy = c.optional("decoy.listen") == null ? null : c.endpoint("decoy.listen");
        String decoyId = c.optional("decoy.id") == null ? "decoy" : c.id("decoy.id");
        var tls = new TlsContextFactory.Material(c.path("tls.keyStore"), c.path("tls.trustStore"),
                new SecretSource(c.string("tls.passwordEnv", "EASTGUARD_STORE_PASS"),
                        c.path("tls.passwordFile", "keys/store.pass")));
        GatewayLimits limits = GatewayLimits.from(c);
        EnforcementSnapshot bootstrap = BootstrapState.snapshot(Config.load(c.path("bootstrap.file")));
        c.requireNoUnknownKeys();
        return new GatewayConfig(service, listen, backend, decoy, decoyId, tls, limits, bootstrap);
    }
}
