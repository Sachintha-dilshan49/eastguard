package eastguard.tokensvc;

import eastguard.common.BootstrapState;
import eastguard.common.Config;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.Ids;
import eastguard.common.SecretSource;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Token service configuration, see {@code config/token.properties.example}. Paths are relative to the working
 * directory. Passwords are read from the named environment variable, else the named (git-ignored) file.
 *
 * <pre>
 * listen=127.0.0.1:8443
 * tls.keyStore=keys/tokensvc.p12          tls.trustStore=keys/truststore.p12
 * tls.passwordEnv=EASTGUARD_STORE_PASS    tls.passwordFile=keys/store.pass
 * lease.keyStore=keys/lease-signer.p12    lease.keyAlias=lease-k1    lease.keyId=lease-k1
 * lease.passwordEnv=EASTGUARD_SIGNER_PASS lease.passwordFile=keys/signer.pass
 * limits.maxConcurrent=64                 concurrent handshakes + requests; excess connections are closed
 * limits.deadlineMillis=5000              total per-connection deadline (handshake, request, reply)
 * limits.backlog=128
 * limits.issuePerIdentityPerSecond=20
 * cluster.id, lease.defaultSeconds, bootstrap.*   see {@link BootstrapState}
 * </pre>
 */
public record TokenConfig(Endpoint listen, TlsContextFactory.Material tls, Path signerStore, String signerAlias,
        String keyId, SecretSource signerPassword, TokenServer.Limits limits, int issuePerIdentityPerSecond,
        EnforcementSnapshot bootstrap) {

    public TokenConfig {
        Objects.requireNonNull(listen, "listen");
        Objects.requireNonNull(tls, "tls");
        Objects.requireNonNull(signerStore, "signerStore");
        Objects.requireNonNull(signerAlias, "signerAlias");
        Ids.require(keyId, "keyId");
        Objects.requireNonNull(signerPassword, "signerPassword");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(bootstrap, "bootstrap");
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
        EnforcementSnapshot bootstrap = BootstrapState.snapshot(c);
        c.requireNoUnknownKeys();
        return new TokenConfig(listen, tls, signer, alias, keyId, signerPass, limits, perIdentity, bootstrap);
    }
}
