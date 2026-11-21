package eastguard.demos;

import eastguard.common.SecretSource;
import eastguard.control.AuditClient;
import eastguard.tokensvc.TlsContextFactory;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;

/**
 * Readiness probe for {@code scripts\run-demo.ps1}: one GET of the control plane's {@code /health/ready} over TLS
 * 1.3 with the operator console's client certificate (every audit-export endpoint requires an authorized
 * certificate, spec §7.3). Exit code 0 when the answer is 200, 1 otherwise. Prints nothing secret.
 *
 * <pre>
 * java -cp out eastguard.demos.HealthProbe https://127.0.0.1:9443/health/ready
 * </pre>
 */
public final class HealthProbe {
    private HealthProbe() {
    }

    public static void main(String[] args) {
        if (args.length != 1 || !args[0].startsWith("https://")) {
            System.err.println("usage: java -cp out eastguard.demos.HealthProbe https://<host>:<port>/health/ready");
            System.exit(2);
        }
        try {
            AuditClient client = new AuditClient(TlsContextFactory.create(new TlsContextFactory.Material(
                    Path.of("keys/console.p12"), Path.of("keys/truststore.p12"),
                    new SecretSource("EASTGUARD_STORE_PASS", Path.of("keys/store.pass")))), Duration.ofSeconds(3));
            int status = client.get(URI.create(args[0])).status();
            System.out.println(args[0] + " -> " + status);
            System.exit(status == 200 ? 0 : 1);
        } catch (IOException | RuntimeException e) {
            System.out.println(args[0] + " -> " + e.getClass().getSimpleName());
            System.exit(1);
        }
    }
}
