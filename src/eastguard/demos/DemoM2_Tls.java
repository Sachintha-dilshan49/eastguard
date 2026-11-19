package eastguard.demos;

import eastguard.client.EastGuardClient;
import eastguard.common.Bytes;
import eastguard.common.Ed25519;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementView;
import eastguard.common.IpAddress;
import eastguard.common.IssuerReply;
import eastguard.common.KeyStores;
import eastguard.common.Lease;
import eastguard.common.LeaseCodec;
import eastguard.common.Peer;
import eastguard.common.PolicyEvaluator;
import eastguard.common.ReplyStatus;
import eastguard.common.SecretSource;
import eastguard.common.SignedLease;
import eastguard.common.WorkloadIdentity;
import eastguard.tokensvc.TlsContextFactory;
import eastguard.tokensvc.TokenConfig;
import eastguard.tokensvc.TokenServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.function.BooleanSupplier;
import javax.net.ssl.SSLContext;

/**
 * M2 demo (spec §11): a trusted client obtains a lease over mTLS, an unapproved edge is denied, a certificate
 * from an untrusted CA fails the TLS handshake, and tampered lease fixtures are rejected by the same verifier
 * the gateway uses.
 *
 * <pre>
 * .\scripts\gen-certs.ps1                     # once
 * java -cp out eastguard.demos.DemoM2_Tls     # optional arg: token config file
 * </pre>
 *
 * Starts its own token service on an ephemeral loopback port. Exit code 0 when every expectation holds.
 */
public final class DemoM2_Tls {
    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static int failures;

    private DemoM2_Tls() {
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("java.util.logging.SimpleFormatter.format", "        [server %4$s] %5$s%6$s%n");
        Path cfgFile = Path.of(args.length > 0 ? args[0] : "config/token.properties.example");
        if (!Files.isRegularFile(Path.of("keys", "truststore.p12"))) {
            System.err.println("keys\\ not found. Run .\\scripts\\gen-certs.ps1 from the project root first.");
            System.exit(2);
        }
        TokenConfig cfg = TokenConfig.load(cfgFile);
        Clock clock = Clock.systemUTC();
        Path trust = cfg.tls().trustStore();
        SecretSource storePass = cfg.tls().password();
        IpAddress loopback = IpAddress.parse("127.0.0.1");

        try (TokenServer server = TokenServer.create(cfg, clock,
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))) {
            server.start();
            Endpoint issuer = new Endpoint(loopback, server.port());
            title("Token service on " + issuer + " (TLS 1.3 only, client certificate required)");

            // 1. Trusted workload gets a lease.
            title("1. web-01 (trusted CA, URI SAN urn:eastguard:workload:web-01) requests app-02");
            Path webStore = Path.of("keys", "workload-web-01.p12");
            EastGuardClient web = client(webStore, trust, storePass, issuer);
            IssuerReply reply = web.requestLease("app-02");
            check(reply.status() == ReplyStatus.SUCCESS, "lease issued (status " + reply.status() + ")");
            byte[] token = reply.token().toArray();
            Lease lease = LeaseCodec.parse(token).lease();
            Bytes webFp = fingerprint(webStore, storePass);
            say("claims: sub=" + lease.subject() + " aud=" + lease.audience() + " srcIp=" + lease.sourceIp()
                    + " keyId=" + lease.keyId() + " ttl=" + (lease.expiresAtMs() - lease.issuedAtMs()) / 1000 + "s"
                    + " rev=" + lease.issuedAtRevision() + " (" + token.length + "-byte token, not printed)");
            check(lease.subject().equals("web-01") && lease.sourceIp().equals(loopback)
                    && lease.leafSha256().equals(webFp), "lease bound to web-01, its certificate, and the socket IP");

            PolicyEvaluator verifier = new PolicyEvaluator(clock);
            EnforcementView gatewayView = EnforcementView.fresh(cfg.bootstrap());
            Peer webPeer = new Peer("web-01", webFp, loopback);
            var genuine = verifier.admit(gatewayView, webPeer, "app-02", token);
            check(genuine.allowed(), "gateway verifier admits the genuine lease (" + genuine.reason() + ")");

            // 2. Default deny.
            title("2. api-01 (trusted, but no approved edge to app-02) requests app-02");
            IssuerReply api = client(Path.of("keys", "workload-api-01.p12"), trust, storePass, issuer)
                    .requestLease("app-02");
            check(api.status() == ReplyStatus.DENY && api.token().length() == 0,
                    "denied with no token (status " + api.status() + ")");

            // 3. Untrusted CA.
            title("3. 'web-01' certificate issued by an untrusted CA requests app-02");
            long tlsFailuresBefore = server.stats().handshakeFailures();
            try {
                client(Path.of("keys", "untrusted-web-01.p12"), trust, storePass, issuer).requestLease("app-02");
                check(false, "untrusted certificate should not get any reply");
            } catch (IOException e) {
                // TLS 1.3: the client finishes its side before the server rejects the certificate, so the failure
                // shows up on the first read, as the server's alert or (on Windows) a reset that discarded it.
                say("client saw " + e.getClass().getSimpleName() + ": " + e.getMessage());
                check(awaitTrue(() -> server.stats().handshakeFailures() > tlsFailuresBefore),
                        "server rejected the certificate during the TLS handshake; no application reply");
            }

            // 4. Tampered lease fixtures.
            title("4. Tampered lease fixtures against the gateway verifier");
            SignedLease signed = LeaseCodec.parse(token);
            byte[] sig = signed.signature().toArray();

            IpAddress attackerIp = IpAddress.parse("10.6.6.6");
            Lease rebound = new Lease(lease.cluster(), lease.keyId(), lease.subject(), lease.audience(), attackerIp,
                    lease.leafSha256(), lease.issuedAtMs(), lease.expiresAtMs(), lease.jti(), lease.issuedAtRevision());
            var r1 = verifier.admit(gatewayView, new Peer("web-01", webFp, attackerIp), "app-02",
                    assemble(LeaseCodec.encodeBody(rebound), sig));
            check(!r1.allowed(), "claims edited (srcIp -> " + attackerIp + "), original signature: " + r1.reason());

            byte[] flipped = sig.clone();
            flipped[0] ^= 0x01;
            var r2 = verifier.admit(gatewayView, webPeer, "app-02", assemble(signed.body().toArray(), flipped));
            check(!r2.allowed(), "one signature bit flipped: " + r2.reason());

            var forger = Ed25519.generate();
            var r3 = verifier.admit(gatewayView, webPeer, "app-02", LeaseCodec.issue(lease, forger.getPrivate()));
            check(!r3.allowed(), "re-signed with an attacker key claiming keyId " + lease.keyId() + ": " + r3.reason());

            var r4 = verifier.admit(gatewayView, webPeer, "app-02", "not.a-lease".getBytes(StandardCharsets.US_ASCII));
            check(!r4.allowed(), "garbage token: " + r4.reason());

            TokenServer.Stats st = server.stats();
            title("Token service counters: issued=" + st.issued() + " denied=" + st.denied()
                    + " tlsFailures=" + st.handshakeFailures() + " malformed=" + st.malformed());
        }
        System.out.println();
        System.out.println(failures == 0 ? "DemoM2_Tls: all checks passed" : "DemoM2_Tls: " + failures + " check(s) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    private static EastGuardClient client(Path store, Path trust, SecretSource pass, Endpoint issuer) {
        SSLContext ctx = TlsContextFactory.create(new TlsContextFactory.Material(store, trust, pass));
        return new EastGuardClient(ctx, issuer, "127.0.0.1", TIMEOUT);
    }

    private static Bytes fingerprint(Path store, SecretSource pass) throws Exception {
        char[] pw = pass.read();
        try {
            KeyStore ks = KeyStores.load(store, pw);
            X509Certificate leaf = KeyStores.certificate(ks, KeyStores.singleKeyAlias(ks, store), store);
            return WorkloadIdentity.fingerprint(leaf);
        } finally {
            Arrays.fill(pw, '\0');
        }
    }

    /** {@code base64url(body) "." base64url(sig)}: the token layout, without signing. */
    private static byte[] assemble(byte[] body, byte[] sig) {
        String t = B64.encodeToString(body) + "." + B64.encodeToString(sig);
        return t.getBytes(StandardCharsets.US_ASCII);
    }

    private static boolean awaitTrue(BooleanSupplier condition) throws InterruptedException {
        long end = System.nanoTime() + TIMEOUT.toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > end) {
                return false;
            }
            Thread.sleep(10);
        }
        return true;
    }

    private static void title(String s) {
        System.out.println();
        System.out.println(s);
    }

    private static void say(String s) {
        System.out.println("    " + s);
    }

    private static void check(boolean ok, String what) {
        if (!ok) {
            failures++;
        }
        System.out.println("  " + (ok ? "[ok]   " : "[FAIL] ") + what);
    }
}
