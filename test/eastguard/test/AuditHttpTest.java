package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Endpoint;
import eastguard.common.Selector;
import eastguard.control.AuditClient;
import eastguard.control.AuditHttpServer;
import eastguard.control.ControlPlaneImpl;
import eastguard.control.Dto;
import eastguard.control.Journal;
import eastguard.tokensvc.TlsContextFactory;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

/** HTTPS audit export (spec §7.3): required authorized client certificate, pagination, read-only, no secrets. */
public final class AuditHttpTest {
    private static final java.util.logging.Logger QUIET = java.util.logging.Logger.getLogger("eastguard.control");
    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private final ControlFixtures fx = new ControlFixtures();

    public AuditHttpTest() {
        QUIET.setLevel(java.util.logging.Level.OFF); // refused clients log WARNING on purpose
    }

    private interface Body {
        void run(ControlPlaneImpl cp, String base) throws Exception;
    }

    /** A bootstrapped control plane with 6 audited revisions and an export on an ephemeral port. */
    private void withServer(Body body) throws Exception {
        try (Journal j = Journal.open(ControlFixtures.freshJournal())) {
            ControlPlaneImpl cp = fx.bootstrapped(j);
            for (int i = 1; i <= 5; i++) {
                Dto.MutationResult r = i % 2 == 1
                        ? cp.quarantine(new Dto.QuarantineRequest(fx.cred("operator"), "q-" + i,
                                List.of(Selector.identity("web-01")), 60_000, "audit test " + i))
                        : cp.release(new Dto.ReleaseRequest(fx.cred("operator"), "r-" + i,
                                List.of(Selector.identity("web-01")), "audit test " + i));
                assertTrue(r.ok(), "mutation " + i + ": " + r);
            }
            AuditHttpServer server = AuditHttpServer.start(cp, TestPki.context("control"),
                    new AuditHttpServer.Settings(Endpoint.parse("127.0.0.1:" + RmiTest.freePort()),
                            Set.of(AuditHttpServer.CONSOLE_IDENTITY)));
            try {
                body.run(cp, "https://127.0.0.1:" + server.port());
            } finally {
                server.close();
            }
        }
    }

    private static AuditClient console() {
        return new AuditClient(TestPki.context("console"), TIMEOUT);
    }

    private static List<Long> revisions(String json) {
        Matcher m = Pattern.compile("\"revision\":(\\d+)").matcher(json);
        List<Long> out = new java.util.ArrayList<>();
        while (m.find()) {
            out.add(Long.parseLong(m.group(1)));
        }
        return out;
    }

    private static long nextCursor(String json) {
        Matcher m = Pattern.compile("\"nextCursor\":(\\d+)").matcher(json);
        assertTrue(m.find(), "nextCursor in " + json);
        return Long.parseLong(m.group(1));
    }

    public void testAuditIsPaginatedNewestFirst() throws Exception {
        withServer((cp, base) -> {
            AuditClient c = console();
            AuditClient.Response p1 = c.get(URI.create(base + "/audit?limit=2"));
            assertEquals(200, p1.status());
            assertTrue(p1.contentType().startsWith("application/json"), p1.contentType());
            assertEquals(List.of(6L, 5L), revisions(p1.body()));
            assertEquals(5, nextCursor(p1.body()));
            AuditClient.Response p2 = c.get(URI.create(base + "/audit?cursor=5&limit=2"));
            assertEquals(List.of(4L, 3L), revisions(p2.body()));
            AuditClient.Response p3 = c.get(URI.create(base + "/audit?limit=2&cursor=" + nextCursor(p2.body())));
            assertEquals(List.of(2L, 1L), revisions(p3.body()));
            assertEquals(0, nextCursor(p3.body())); // no older page
            assertTrue(p1.body().contains("\"operation\":\"QUARANTINE\"") && p1.body().contains("\"actor\":\"operator\""),
                    p1.body());
            assertEquals(List.of(6L, 5L, 4L, 3L, 2L, 1L), revisions(c.get(URI.create(base + "/audit")).body()));
        });
    }

    public void testNoClientCertificateFailsTheHandshake() throws Exception {
        withServer((cp, base) -> {
            SSLContext noCert = SSLContext.getInstance("TLSv1.3");
            KeyStore trust = TestPki.load(TestPki.trustStore(), TestPki.storePass());
            noCert.init(null, new TrustManager[] {TlsContextFactory.pkixTrustManager(trust)}, null);
            // TLS 1.3: the client may only notice on its first read (DEVIATIONS 4.4); either way no response.
            assertThrows(IOException.class, () -> new AuditClient(noCert, TIMEOUT).get(URI.create(base + "/audit")));
            assertThrows(IOException.class, () -> new AuditClient(TestPki.context("untrusted-web-01"), TIMEOUT)
                    .get(URI.create(base + "/audit")));
        });
    }

    public void testTrustedButUnauthorizedCertificateIsForbidden() throws Exception {
        withServer((cp, base) -> {
            for (String other : new String[] {"workload-web-01", "tokensvc"}) {
                AuditClient c = new AuditClient(TestPki.context(other), TIMEOUT);
                for (String path : new String[] {"/audit", "/metrics", "/health/ready"}) {
                    AuditClient.Response r = c.get(URI.create(base + path));
                    assertEquals(403, r.status());
                    assertFalse(r.body().contains("revision") || r.body().contains("eastguard_"),
                            "no data for " + other + " on " + path + ": " + r.body());
                }
            }
            AuditClient.Response m = console().get(URI.create(base + "/metrics"));
            assertTrue(m.body().contains("eastguard_audit_http_forbidden_total 6"), m.body());
        });
    }

    public void testReadOnlyAndStrictRequests() throws Exception {
        withServer((cp, base) -> {
            AuditClient c = console();
            for (String bad : new String[] {"/audit?limit=0", "/audit?limit=201", "/audit?limit=abc",
                    "/audit?cursor=-1", "/audit?limit=2&limit=3", "/audit?evil=1", "/metrics?x=1"}) {
                assertEquals(400, c.get(URI.create(base + bad)).status());
            }
            assertEquals(404, c.get(URI.create(base + "/audit/../keys")).status());
            assertEquals(404, c.get(URI.create(base + "/")).status());
            HttpsURLConnection post = (HttpsURLConnection) URI.create(base + "/audit").toURL().openConnection();
            post.setSSLSocketFactory(TestPki.context("console").getSocketFactory());
            post.setRequestMethod("POST");
            post.setDoOutput(true);
            post.getOutputStream().write("{}".getBytes());
            assertEquals(HttpURLConnection.HTTP_BAD_METHOD, post.getResponseCode());
            assertEquals("GET, HEAD", post.getHeaderField("Allow"));
            post.disconnect();
            assertEquals(6, cp.snapshot().revision()); // nothing changed
        });
    }

    public void testHealthAndMetricsWithoutSecrets() throws Exception {
        withServer((cp, base) -> {
            AuditClient c = console();
            AuditClient.Response live = c.get(URI.create(base + "/health/live"));
            AuditClient.Response ready = c.get(URI.create(base + "/health/ready"));
            assertEquals(200, live.status());
            assertEquals("live\n", live.body());
            assertEquals(200, ready.status());
            assertEquals("ready\n", ready.body());
            AuditClient.Response m = c.get(URI.create(base + "/metrics"));
            assertTrue(m.body().contains("eastguard_ready 1\n") && m.body().contains("eastguard_enforcement_revision 6\n"),
                    m.body());
            String all = m.body() + c.get(URI.create(base + "/audit?limit=200")).body();
            for (var s : fx.secrets.values()) {
                assertFalse(all.contains(Base64.getUrlEncoder().withoutPadding().encodeToString(s.toArray())),
                        "no API secret in responses");
                assertFalse(all.contains(java.util.HexFormat.of().formatHex(
                        eastguard.common.Sha256.digest(s.toArray()).toArray())), "no credential digest in responses");
            }
        });
    }

    public void testAuditJsonEscaping() {
        assertEquals("\"a\\\"b\\\\c\\u003cd\\u000a\"", escape("a\"b\\c<d\n"));
        assertEquals("null", escape(null));
    }

    private static String escape(String s) {
        try {
            var m = AuditHttpServer.class.getDeclaredMethod("str", String.class);
            m.setAccessible(true);
            return (String) m.invoke(null, s);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }
}
