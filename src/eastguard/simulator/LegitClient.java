package eastguard.simulator;

import eastguard.client.EastGuardClient;
import eastguard.client.GatewaySession;
import eastguard.common.Bytes;
import eastguard.common.Endpoint;
import eastguard.common.IssuerReply;
import eastguard.common.ReplyStatus;
import eastguard.common.SecretSource;
import eastguard.tokensvc.TlsContextFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;

/**
 * Legitimate workload simulator (idea §7, §10): simulates authorized microservice communication.
 * Obtains an Ed25519-signed lease from the token service over mTLS, presents it to the target gateway
 * over mTLS, exchanges application payload through the relay, and automatically refreshes leases before expiry.
 */
public final class LegitClient {
    private static final Logger LOG = Logger.getLogger(LegitClient.class.getName());
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);

    private final EastGuardClient client;
    private final Endpoint gateway;
    private final String gatewayServerName;
    private final String targetService;

    public record Options(
            Path keystore,
            Path truststore,
            SecretSource storePass,
            Endpoint issuer,
            String issuerServerName,
            Endpoint gateway,
            String gatewayServerName,
            String targetService,
            Duration timeout) {

        public Options {
            Objects.requireNonNull(keystore, "keystore");
            Objects.requireNonNull(truststore, "truststore");
            Objects.requireNonNull(storePass, "storePass");
            Objects.requireNonNull(issuer, "issuer");
            Objects.requireNonNull(issuerServerName, "issuerServerName");
            Objects.requireNonNull(gateway, "gateway");
            Objects.requireNonNull(gatewayServerName, "gatewayServerName");
            Objects.requireNonNull(targetService, "targetService");
            timeout = timeout == null ? DEFAULT_TIMEOUT : timeout;
        }

        public static Options defaults(Path keysDir, String workloadName, String targetService, Endpoint gateway) {
            Path ks = keysDir.resolve("workload-" + workloadName + ".p12");
            Path ts = keysDir.resolve("truststore.p12");
            SecretSource pass = new SecretSource("EASTGUARD_STORE_PASS", keysDir.resolve("store.pass"));
            return new Options(ks, ts, pass,
                    new Endpoint(gateway.ip(), 8443), "localhost",
                    gateway, "localhost", targetService, DEFAULT_TIMEOUT);
        }
    }

    public record Result(boolean success, ReplyStatus status, String response, Duration duration) {}

    public LegitClient(Options options) {
        Objects.requireNonNull(options, "options");
        SSLContext ctx = TlsContextFactory.create(new TlsContextFactory.Material(
                options.keystore(), options.truststore(), options.storePass()));
        this.client = new EastGuardClient(ctx, options.issuer(), options.issuerServerName(), options.timeout());
        this.gateway = options.gateway();
        this.gatewayServerName = options.gatewayServerName();
        this.targetService = options.targetService();
    }

    /** Requests a fresh lease and executes a single request-response exchange through the gateway. */
    public Result exchange(String message) throws IOException {
        long t0 = System.nanoTime();
        IssuerReply reply = client.requestLease(targetService);
        if (reply.status() != ReplyStatus.SUCCESS) {
            long ms = (System.nanoTime() - t0) / 1_000_000;
            return new Result(false, reply.status(), null, Duration.ofMillis(ms));
        }

        try (GatewaySession session = client.connect(gateway, gatewayServerName, reply.token())) {
            if (session.status() != ReplyStatus.SUCCESS) {
                long ms = (System.nanoTime() - t0) / 1_000_000;
                return new Result(false, session.status(), null, Duration.ofMillis(ms));
            }

            byte[] outBytes = message.getBytes(StandardCharsets.UTF_8);
            OutputStream out = session.output();
            out.write(outBytes);
            out.flush();

            byte[] inBytes = new byte[outBytes.length];
            InputStream in = session.input();
            int read = in.readNBytes(inBytes, 0, inBytes.length);
            long ms = (System.nanoTime() - t0) / 1_000_000;
            String response = new String(inBytes, 0, read, StandardCharsets.UTF_8);
            return new Result(true, ReplyStatus.SUCCESS, response, Duration.ofMillis(ms));
        }
    }

    public static void main(String[] args) throws Exception {
        Path keysDir = Path.of(args.length > 0 ? args[0] : "keys");
        String workload = args.length > 1 ? args[1] : "web-01";
        String service = args.length > 2 ? args[2] : "app-02";
        int port = args.length > 3 ? Integer.parseInt(args[3]) : 9002;

        Endpoint gw = new Endpoint(eastguard.common.IpAddress.parse("127.0.0.1"), port);
        Options opts = Options.defaults(keysDir, workload, service, gw);
        LegitClient client = new LegitClient(opts);

        LOG.info(() -> "LegitClient starting for " + workload + " -> " + service + " on " + gw);
        Result res = client.exchange("Hello EastGuard at " + Instant.now());
        if (res.success()) {
            System.out.println("[OK] Exchange succeeded in " + res.duration().toMillis() + " ms: " + res.response());
        } else {
            System.out.println("[DENIED] Exchange failed with status: " + res.status());
            System.exit(1);
        }
    }
}
