package eastguard.tokensvc;

import eastguard.common.Endpoint;
import eastguard.common.IpAddress;
import eastguard.common.KeyStores;
import eastguard.common.SecretSource;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * TLS configuration for every EastGuard role (spec §4.1).
 *
 * <ul>
 *   <li>TLS 1.3 only, PKCS#12 key and trust stores.</li>
 *   <li>Every call to {@link #create} builds a new {@link SSLContext}; each role (token service listener, gateway
 *       listener, workload client, RMI client, ...) owns its own. The JVM default context is never used or set.</li>
 *   <li>Servers require client authentication. Trust is the JDK PKIX trust manager over the configured trust
 *       store, which validates the chain, validity period, key usage, and extended key usage
 *       (clientAuth/serverAuth) of the peer. There is no trust-all path.</li>
 *   <li>Clients always use HTTPS endpoint identification against the configured DNS name or IP literal.</li>
 * </ul>
 */
public final class TlsContextFactory {
    public static final String PROTOCOL = "TLSv1.3";
    private static final String[] PROTOCOLS = {PROTOCOL};

    /**
     * Key material for one role. The key store must hold exactly one private key; the trust store only trusted
     * certificates. Both are opened with the same password.
     */
    public record Material(Path keyStore, Path trustStore, SecretSource password) {
        public Material {
            Objects.requireNonNull(keyStore, "keyStore");
            Objects.requireNonNull(trustStore, "trustStore");
            Objects.requireNonNull(password, "password");
        }
    }

    private TlsContextFactory() {
    }

    public static SSLContext create(Material m) {
        char[] pw = m.password().read();
        try {
            KeyStore ks = KeyStores.load(m.keyStore(), pw);
            KeyStores.singleKeyAlias(ks, m.keyStore());
            KeyStore ts = KeyStores.load(m.trustStore(), pw);
            KeyStores.requireTrustStore(ts, m.trustStore());
            return create(ks, pw, ts);
        } finally {
            Arrays.fill(pw, '\0');
        }
    }

    /** As {@link #create(Material)} for already loaded stores. {@code keyStore} may not be null. */
    public static SSLContext create(KeyStore keyStore, char[] keyPassword, KeyStore trustStore) {
        Objects.requireNonNull(keyStore, "keyStore");
        Objects.requireNonNull(trustStore, "trustStore");
        try {
            // PKIX key manager selects our certificate by key type and EKU for the side of the handshake.
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
            kmf.init(keyStore, keyPassword);
            SSLContext ctx = SSLContext.getInstance(PROTOCOL);
            ctx.init(kmf.getKeyManagers(), new TrustManager[] {pkixTrustManager(trustStore)}, null);
            return ctx;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cannot initialise TLS context: " + e.getMessage(), e);
        }
    }

    /** The JDK PKIX trust manager for {@code trustStore}; never a permissive substitute. */
    public static X509ExtendedTrustManager pkixTrustManager(KeyStore trustStore) throws GeneralSecurityException {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(trustStore);
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509ExtendedTrustManager x) {
                return x;
            }
        }
        throw new GeneralSecurityException("no X509ExtendedTrustManager available");
    }

    public static SSLParameters serverParameters(SSLContext ctx) {
        SSLParameters p = ctx.getDefaultSSLParameters();
        p.setProtocols(PROTOCOLS);
        p.setNeedClientAuth(true);
        return p;
    }

    /**
     * Client parameters that verify the server certificate against {@code serverName}: a DNS SAN for a host
     * name (also sent as SNI), an IP SAN for an IP literal.
     */
    public static SSLParameters clientParameters(SSLContext ctx, String serverName) {
        SSLParameters p = ctx.getDefaultSSLParameters();
        p.setProtocols(PROTOCOLS);
        p.setEndpointIdentificationAlgorithm("HTTPS");
        if (!isIpLiteral(serverName)) {
            p.setServerNames(List.of(new SNIHostName(serverName)));
        }
        return p;
    }

    /** Bound, configured server socket. Port 0 picks an ephemeral port. */
    public static SSLServerSocket serverSocket(SSLContext ctx, InetSocketAddress bind, int backlog)
            throws IOException {
        SSLServerSocket s = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket();
        try {
            s.setSSLParameters(serverParameters(ctx));
            s.bind(bind, backlog);
            return s;
        } catch (IOException | RuntimeException e) {
            s.close();
            throw e;
        }
    }

    /** Server-mode engine for the NIO gateway. */
    public static SSLEngine serverEngine(SSLContext ctx) {
        SSLEngine e = ctx.createSSLEngine();
        e.setUseClientMode(false);
        e.setSSLParameters(serverParameters(ctx));
        return e;
    }

    /**
     * Connects to a numeric endpoint (no DNS lookup), then runs the TLS handshake verifying the server against
     * {@code serverName}. {@code timeout} bounds the TCP connect and each blocking read, including the handshake.
     */
    public static SSLSocket connect(SSLContext ctx, Endpoint target, String serverName, Duration timeout)
            throws IOException {
        Objects.requireNonNull(serverName, "serverName");
        int ms = Math.toIntExact(Math.max(1, timeout.toMillis()));
        Socket plain = new Socket();
        try {
            plain.connect(target.toSocketAddress(), ms);
            plain.setSoTimeout(ms);
            plain.setTcpNoDelay(true);
            SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(plain, serverName, target.port(), true);
            s.setUseClientMode(true);
            s.setSSLParameters(clientParameters(ctx, serverName));
            s.startHandshake();
            return s;
        } catch (IOException | RuntimeException e) {
            plain.close();
            throw e;
        }
    }

    static boolean isIpLiteral(String name) {
        try {
            IpAddress.parse(name);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
