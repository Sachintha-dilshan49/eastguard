package eastguard.gateway;

import eastguard.common.Config;
import eastguard.common.Endpoint;
import eastguard.common.Ids;
import eastguard.common.SecretSource;
import eastguard.common.TelemetrySender;
import eastguard.control.ControlClient;
import eastguard.control.StateSync;
import eastguard.tokensvc.TlsContextFactory;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Gateway configuration (spec §9.1), see {@code config/gateway-app-02.properties.example}.
 *
 * <pre>
 * cluster.id=eg-demo
 * gateway.service=app-02                 fixed service ID: the only lease audience this gateway accepts
 * listen=127.0.0.1:9002                  workload-facing mTLS listener
 * backend=127.0.0.1:7002                 fixed private backend (numeric; never resolved)
 * decoy.listen=127.0.0.1:9003            optional accept-and-close decoy
 * decoy.id=decoy-9003                    telemetry service ID for decoy hits (default "decoy")
 * tls.keyStore, tls.trustStore, tls.passwordEnv, tls.passwordFile    as for the token service; the same
 *                                        certificate is the gateway's RMI client identity
 * control.*                              see {@link ControlClient.Settings}
 * state.pollMillis, state.maxAgeMillis   see {@link StateSync.Settings}
 * limits.*                               see {@link GatewayLimits}
 * telemetry.*                            optional UDP producer, see {@link TelemetrySender.Settings}
 * </pre>
 */
public record GatewayConfig(String serviceId, Endpoint listen, Endpoint backend, Endpoint decoyListen, String decoyId,
        TlsContextFactory.Material tls, GatewayLimits limits, ControlClient.Settings control, StateSync.Settings sync,
        TelemetrySender.Settings telemetry) {

    public GatewayConfig {
        Ids.require(serviceId, "serviceId");
        Objects.requireNonNull(listen, "listen");
        Objects.requireNonNull(backend, "backend");
        Ids.require(decoyId, "decoyId");
        Objects.requireNonNull(tls, "tls");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(control, "control");
        Objects.requireNonNull(sync, "sync");
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
        ControlClient.Settings control = ControlClient.Settings.from(c);
        StateSync.Settings sync = StateSync.Settings.from(c);
        TelemetrySender.Settings telemetry = TelemetrySender.Settings.from(c); // null: no collector
        c.requireNoUnknownKeys();
        return new GatewayConfig(service, listen, backend, decoy, decoyId, tls, limits, control, sync, telemetry);
    }
}
