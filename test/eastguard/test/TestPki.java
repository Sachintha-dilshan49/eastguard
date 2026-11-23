package eastguard.test;

import eastguard.common.Bytes;
import eastguard.common.KeyStores;
import eastguard.common.SecretSource;
import eastguard.common.WorkloadIdentity;
import eastguard.tokensvc.TlsContextFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;

/**
 * Test PKI produced by the real {@code scripts/gen-certs.ps1 -TestFixtures} into {@code out/test-pki} (git-ignored).
 * Generated once (about 20 s) and reused until a file is missing or the certificates are within a week of expiry.
 * The script runs without the {@code EASTGUARD_*} password variables so it creates password files in that
 * directory, which these helpers read.
 */
final class TestPki {
    static final Path DIR = Path.of("out", "test-pki").toAbsolutePath();
    private static final List<String> REQUIRED = List.of("truststore.p12", "tokensvc.p12", "gateway-app-02.p12",
            "workload-web-01.p12", "workload-api-01.p12", "untrusted-web-01.p12", "workload-nosan.p12",
            "workload-twosan.p12", "lease-signer.p12", "lease-k1.cer", "store.pass", "signer.pass", "control.p12",
            "console.p12");
    private static boolean ready;

    private TestPki() {
    }

    static synchronized Path dir() {
        if (!ready) {
            if (!usable()) {
                generate();
            }
            ready = true;
        }
        return DIR;
    }

    private static boolean usable() {
        for (String f : REQUIRED) {
            if (!Files.isRegularFile(DIR.resolve(f))) {
                return false;
            }
        }
        Instant notAfter = leafUnchecked("workload-web-01").getNotAfter().toInstant();
        return notAfter.isAfter(Instant.now().plus(Duration.ofDays(7)));
    }

    private static void generate() {
        Path log = DIR.resolveSibling("test-pki.log");
        try {
            Files.createDirectories(DIR.getParent());
            boolean isWindows = System.getProperty("os.name", "").toLowerCase().contains("win");
            ProcessBuilder pb;
            if (!isWindows && Files.isRegularFile(Path.of("scripts", "gen-certs.sh"))) {
                pb = new ProcessBuilder("bash", Path.of("scripts", "gen-certs.sh").toString(),
                        "-OutDir", DIR.toString(), "-TestFixtures", "-Force");
            } else {
                pb = new ProcessBuilder("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                        "Bypass", "-File", Path.of("scripts", "gen-certs.ps1").toString(),
                        "-OutDir", DIR.toString(), "-TestFixtures", "-Force");
            }
            pb.environment().keySet().removeIf(k -> k.toUpperCase().startsWith("EASTGUARD_"));
            pb.redirectErrorStream(true).redirectOutput(log.toFile());
            System.out.println("generating test PKI in " + DIR + " (log: " + log + ")");
            Process p = pb.start();
            if (!p.waitFor(180, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                throw new IllegalStateException("gen-certs timed out; see " + log);
            }
            if (p.exitValue() != 0) {
                throw new IllegalStateException("gen-certs failed (exit " + p.exitValue() + "); see " + log);
            }
        } catch (IOException e) {
            throw new IllegalStateException("cannot run gen-certs", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    static SecretSource storePass() {
        return new SecretSource("EASTGUARD_TEST_PKI_STORE_PASS", dir().resolve("store.pass"));
    }

    static SecretSource signerPass() {
        return new SecretSource("EASTGUARD_TEST_PKI_SIGNER_PASS", dir().resolve("signer.pass"));
    }

    static Path p12(String name) {
        return dir().resolve(name + ".p12");
    }

    static Path trustStore() {
        return p12("truststore");
    }

    static TlsContextFactory.Material material(String name) {
        return new TlsContextFactory.Material(p12(name), trustStore(), storePass());
    }

    static SSLContext context(String name) {
        return TlsContextFactory.create(material(name));
    }

    static KeyStore load(Path file, SecretSource pass) {
        char[] pw = pass.read();
        try {
            return KeyStores.load(file, pw);
        } finally {
            Arrays.fill(pw, '\0');
        }
    }

    static X509Certificate leaf(String name) {
        dir();
        return leafUnchecked(name);
    }

    private static X509Certificate leafUnchecked(String name) {
        Path file = DIR.resolve(name + ".p12");
        KeyStore ks = load(file, new SecretSource("EASTGUARD_TEST_PKI_STORE_PASS", DIR.resolve("store.pass")));
        return KeyStores.certificate(ks, KeyStores.singleKeyAlias(ks, file), file);
    }

    static Bytes fingerprint(String name) {
        try {
            return WorkloadIdentity.fingerprint(leaf(name));
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    static PrivateKey leaseSigningKey() {
        Path file = p12("lease-signer");
        char[] pw = signerPass().read();
        try {
            return KeyStores.privateKey(KeyStores.load(file, pw), "lease-k1", pw, file);
        } finally {
            Arrays.fill(pw, '\0');
        }
    }

    static PublicKey leaseVerifyKey() {
        return KeyStores.ed25519PublicKey(dir().resolve("lease-k1.cer"));
    }
}
