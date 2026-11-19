package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Endpoint;
import eastguard.common.IpAddress;
import eastguard.common.SecretSource;
import eastguard.tokensvc.TlsContextFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

/** {@link TlsContextFactory} against the generated test PKI, on ephemeral loopback ports. */
public final class TlsTest {
    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final String LOOPBACK = "127.0.0.1";

    /** Accepts one connection, completes the handshake, sends one byte, and reports the session or the error. */
    private static final class OneShotServer implements AutoCloseable {
        final SSLServerSocket socket;
        final CompletableFuture<SSLSession> session = new CompletableFuture<>();

        OneShotServer(SSLContext ctx) throws IOException {
            socket = TlsContextFactory.serverSocket(ctx, new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 4);
            Thread.ofVirtual().start(() -> {
                try (SSLSocket s = (SSLSocket) socket.accept()) {
                    s.setSoTimeout((int) TIMEOUT.toMillis());
                    s.startHandshake();
                    s.getOutputStream().write(42);
                    s.getOutputStream().flush();
                    session.complete(s.getSession());
                    s.getInputStream().read(); // until the client closes
                } catch (Throwable t) {
                    session.completeExceptionally(t);
                }
            });
        }

        Endpoint endpoint() {
            return new Endpoint(IpAddress.parse(LOOPBACK), socket.getLocalPort());
        }

        SSLSession awaitSession() throws Exception {
            return session.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
        }

        void assertServerFailed() throws Exception {
            try {
                awaitSession();
                fail("server side should have failed the handshake");
            } catch (ExecutionException e) {
                assertTrue(e.getCause() instanceof IOException, "server failure should be an I/O error: " + e.getCause());
            }
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    /** Client connects and reads the server's byte; any TLS failure surfaces as an IOException. */
    private static int roundTrip(SSLContext client, Endpoint ep, String serverName) throws IOException {
        try (SSLSocket s = TlsContextFactory.connect(client, ep, serverName, TIMEOUT)) {
            return s.getInputStream().read();
        }
    }

    public void testMutualTls13Handshake() throws Exception {
        try (OneShotServer server = new OneShotServer(TestPki.context("tokensvc"))) {
            assertEquals(42, roundTrip(TestPki.context("workload-web-01"), server.endpoint(), LOOPBACK));
            SSLSession s = server.awaitSession();
            assertEquals("TLSv1.3", s.getProtocol());
            assertEquals(TestPki.leaf("workload-web-01"), s.getPeerCertificates()[0]);
        }
    }

    public void testDnsServerNameMatchesDnsSan() throws Exception {
        try (OneShotServer server = new OneShotServer(TestPki.context("tokensvc"))) {
            assertEquals(42, roundTrip(TestPki.context("workload-web-01"), server.endpoint(), "localhost"));
        }
    }

    public void testUntrustedClientCertificateFailsHandshake() throws Exception {
        try (OneShotServer server = new OneShotServer(TestPki.context("tokensvc"))) {
            SSLContext rogue = TestPki.context("untrusted-web-01");
            assertThrows(IOException.class, () -> roundTrip(rogue, server.endpoint(), LOOPBACK)); // alert or reset (TLS 1.3)
            server.assertServerFailed();
        }
    }

    public void testClientWithoutCertificateFailsHandshake() throws Exception {
        KeyStore ts = TestPki.load(TestPki.trustStore(), TestPki.storePass());
        SSLContext noCert = SSLContext.getInstance("TLSv1.3");
        noCert.init(null, new TrustManager[] {TlsContextFactory.pkixTrustManager(ts)}, null);
        try (OneShotServer server = new OneShotServer(TestPki.context("tokensvc"))) {
            assertThrows(IOException.class, () -> roundTrip(noCert, server.endpoint(), LOOPBACK));
            server.assertServerFailed();
        }
    }

    public void testWrongServerNameFailsHandshake() throws Exception {
        SSLContext client = TestPki.context("workload-web-01");
        for (String wrong : new String[] {"app-02.eastguard.internal", "127.0.0.2"}) {
            try (OneShotServer server = new OneShotServer(TestPki.context("tokensvc"))) {
                assertThrows(SSLException.class, () -> roundTrip(client, server.endpoint(), wrong));
                server.assertServerFailed();
            }
        }
    }

    public void testWorkloadCertificateCannotActAsServer() throws Exception {
        // Workload certificates carry only the clientAuth EKU (and no DNS/IP SAN).
        try (OneShotServer server = new OneShotServer(TestPki.context("workload-api-01"))) {
            assertThrows(SSLException.class,
                    () -> roundTrip(TestPki.context("workload-web-01"), server.endpoint(), LOOPBACK));
        }
    }

    public void testTls12ClientRejected() throws Exception {
        SSLContext client = TestPki.context("workload-web-01");
        try (OneShotServer server = new OneShotServer(TestPki.context("tokensvc"))) {
            Socket plain = new Socket();
            plain.connect(server.endpoint().toSocketAddress(), (int) TIMEOUT.toMillis());
            plain.setSoTimeout((int) TIMEOUT.toMillis());
            try (SSLSocket s = (SSLSocket) client.getSocketFactory().createSocket(plain, LOOPBACK, 0, true)) {
                s.setEnabledProtocols(new String[] {"TLSv1.2"});
                assertThrows(SSLException.class, s::startHandshake);
            }
            server.assertServerFailed();
        }
    }

    public void testParametersPinTls13AndClientAuth() throws Exception {
        SSLContext ctx = TestPki.context("tokensvc");
        var server = TlsContextFactory.serverParameters(ctx);
        assertArrayEqualsStr(new String[] {"TLSv1.3"}, server.getProtocols());
        assertTrue(server.getNeedClientAuth(), "client auth required");
        var client = TlsContextFactory.clientParameters(ctx, "localhost");
        assertArrayEqualsStr(new String[] {"TLSv1.3"}, client.getProtocols());
        assertEquals("HTTPS", client.getEndpointIdentificationAlgorithm());
        assertEquals(1, client.getServerNames().size());
        var ipNames = TlsContextFactory.clientParameters(ctx, LOOPBACK).getServerNames();
        assertTrue(ipNames == null || ipNames.isEmpty(), "no SNI for an IP literal");
        var engine = TlsContextFactory.serverEngine(ctx);
        assertTrue(engine.getNeedClientAuth() && !engine.getUseClientMode(), "server engine needs client auth");
    }

    public void testEachCallBuildsASeparateContext() {
        assertTrue(TestPki.context("tokensvc") != TestPki.context("tokensvc"), "fresh SSLContext per call");
    }

    public void testTrustManagerIsPkix() throws Exception {
        KeyStore ts = TestPki.load(TestPki.trustStore(), TestPki.storePass());
        X509ExtendedTrustManager tm = TlsContextFactory.pkixTrustManager(ts);
        assertEquals(1, tm.getAcceptedIssuers().length);
    }

    public void testRejectsBadStores() throws Exception {
        Path wrongPass = Files.createTempFile("eg-wrong", ".pass");
        try {
            Files.writeString(wrongPass, "definitely-not-the-password");
            var bad = new TlsContextFactory.Material(TestPki.p12("tokensvc"), TestPki.trustStore(),
                    new SecretSource("EASTGUARD_TEST_UNSET_VAR", wrongPass));
            assertThrows(IllegalStateException.class, () -> TlsContextFactory.create(bad));
        } finally {
            Files.delete(wrongPass);
        }
        // A key store used as the trust store is refused (it holds a private key).
        var swapped = new TlsContextFactory.Material(TestPki.p12("tokensvc"), TestPki.p12("workload-web-01"),
                TestPki.storePass());
        assertThrows(IllegalStateException.class, () -> TlsContextFactory.create(swapped));
        // The trust store has no private key to serve.
        var noKey = new TlsContextFactory.Material(TestPki.trustStore(), TestPki.trustStore(), TestPki.storePass());
        assertThrows(IllegalStateException.class, () -> TlsContextFactory.create(noKey));
        // Missing password source.
        var missing = new TlsContextFactory.Material(TestPki.p12("tokensvc"), TestPki.trustStore(),
                new SecretSource("EASTGUARD_TEST_UNSET_VAR", TestPki.dir().resolve("no-such.pass")));
        assertThrows(IllegalStateException.class, () -> TlsContextFactory.create(missing));
    }

    private static void assertArrayEqualsStr(String[] expected, String[] actual) {
        assertEquals(java.util.List.of(expected), java.util.List.of(actual));
    }
}
