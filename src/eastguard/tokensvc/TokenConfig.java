package eastguard.tokensvc;

import eastguard.common.Config;
import eastguard.common.Endpoint;
import eastguard.common.Ids;
import eastguard.common.SecretSource;
import eastguard.common.TelemetrySender;
import eastguard.control.ControlClient;
import eastguard.control.StateSync;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Token service configuration, see {@code config/token.properties.example}. Paths are relative to the working
 * directory. Passwords are read from the named environment variable, else the named (git-ignored) file.
 *
 * <pre>
 * cluster.id=eg-demo
 * listen=127.0.0.1:8443
 * tls.keyStore=keys/tokensvc.p12          tls.trustStore=keys/truststore.p12
 * tls.passwordEnv=EASTGUARD_STORE_PASS    tls.passwordFile=keys/store.pass
 * lease.keyStore=keys/lease-signer.p12    lease.keyAlias=lease-k1    lease.keyId=lease-k1
 * lease.passwordEnv=EASTGUARD_SIGNER_PASS lease.passwordFile=keys/signer.pass
 * limits.maxConcurrent=64                 concurrent handshakes + requests; excess connections are closed
 * limits.deadlineMillis=5000              total per-connection deadline (handshake, request, reply)
 * limits.backlog=128
 * limits.issuePerIdentityPerSecond=20
 * control.*                               see {@link ControlClient.Settings}
 * state.pollMillis, state.maxAgeMillis    see {@link StateSync.Settings}
 * telemetry.*                             optional UDP producer for selected denials, see
 *                                         {@link TelemetrySender.Settings}
 * </pre>
 *
 * Policy, workloads, services and the published lease keys come from the control plane; the lease length is a
 * policy setting there.
 */
public record TokenConfig(Endpoint listen, TlsContextFactory.Material tls, Path signerStore, String signerAlias,
        String keyId, SecretSource signerPassword, TokenServer.Limits limits, int issuePerIdentityPerSecond,
        ControlClient.Settings control, StateSync.Settings sync, TelemetrySender.Settings telemetry) {

    public TokenConfig {
        Objects.requireNonNull(listen, "listen");
        Objects.requireNonNull(tls, "tls");
        Objects.requireNonNull(signerStore, "signerStore");
        Objects.requireNonNull(signerAlias, "signerAlias");
        Ids.require(keyId, "keyId");
        Objects.requireNonNull(signerPassword, "signerPassword");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(control, "control");
        Objects.requireNonNull(sync, "sync");
        if (issuePerIdentityPerSecond < 1) {
            throw new IllegalArgumentException("issuePerIdentityPerSecond must be positive");
        }
    }

    public static TokenConfig load(Path file) {
        return from(Config.load(file));
    }

    public static TokenConfig from(Config c) {
        Endpoint listen = c.endpoint("listen");
        var tls = new TlsContextFactory.Material(c.path("tls.keyStore"), c.path("tls.trustStore"),
                new SecretSource(c.string("tls.passwordEnv", "EASTGUARD_STORE_PASS"),
                        c.path("tls.passwordFile", "keys/store.pass")));
        Path signer = c.path("lease.keyStore");
        String alias = c.string("lease.keyAlias");
        String keyId = c.id("lease.keyId");
        var signerPass = new SecretSource(c.string("lease.passwordEnv", "EASTGUARD_SIGNER_PASS"),
                c.path("lease.passwordFile", "keys/signer.pass"));
        var limits = new TokenServer.Limits(
                c.intIn("limits.maxConcurrent", 64, 1, 10_000),
                c.millis("limits.deadlineMillis", 5_000, 100, 60_000),
                c.intIn("limits.backlog", 128, 1, 4_096));
        int perIdentity = c.intIn("limits.issuePerIdentityPerSecond", 20, 1, 10_000);
        ControlClient.Settings control = ControlClient.Settings.from(c);
        StateSync.Settings sync = StateSync.Settings.from(c);
        TelemetrySender.Settings telemetry = TelemetrySender.Settings.from(c); // null: no collector
        c.requireNoUnknownKeys();
        return new TokenConfig(listen, tls, signer, alias, keyId, signerPass, limits, perIdentity, control, sync,
                telemetry);
    }
}
