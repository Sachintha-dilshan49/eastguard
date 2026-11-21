package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.PolicyMode;
import eastguard.control.ControlPlaneImpl;
import eastguard.control.Dto;
import eastguard.control.Journal;
import eastguard.handlers.PolicySource;
import eastguard.handlers.PolicyURLConnection;
import eastguard.handlers.PolicyView;
import eastguard.handlers.ZtpUrlHandler;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownServiceException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/** {@code ztp://policy/<service>} (spec §7.3): typed read through the configured client; nothing else accepted. */
public final class ZtpHandlerTest {
    private static final java.util.logging.Logger QUIET = java.util.logging.Logger.getLogger("eastguard.control");
    private final ControlFixtures fx = new ControlFixtures();

    public ZtpHandlerTest() {
        QUIET.setLevel(java.util.logging.Level.OFF); // the unauthorized read logs a WARNING on purpose
    }

    private static URL ztp(String uri, ZtpUrlHandler h) throws MalformedURLException {
        return URL.of(URI.create(uri), h);
    }

    public void testTypedPolicyReadFromTheControlPlane() throws Exception {
        try (Journal j = Journal.open(ControlFixtures.freshJournal())) {
            ControlPlaneImpl cp = fx.bootstrapped(j);
            PolicySource viewer = id -> cp.getPolicy(new Dto.PolicyRequest(fx.cred("viewer"), id));
            URL u = ztp("ztp://policy/app-02", new ZtpUrlHandler(viewer));
            Object content = u.getContent();
            assertTrue(content instanceof PolicyView, "typed content: " + content);
            PolicyView p = (PolicyView) content;
            assertEquals("app-02", p.serviceId());
            assertEquals(PolicyMode.ENFORCE, p.mode());
            assertEquals(List.of("web-01"), p.allowedSources());
            assertEquals(Duration.ofSeconds(60), p.defaultLease());
            assertEquals(1, p.enforcementRevision());

            URLConnection c = u.openConnection();
            assertTrue(c instanceof PolicyURLConnection, "our connection");
            assertEquals(PolicyURLConnection.CONTENT_TYPE, c.getContentType());
            String text = new String(c.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            assertTrue(text.contains("service=app-02\n") && text.contains("allowedSources=web-01\n"), text);
            assertEquals(p, u.openConnection().getContent(new Class<?>[] {PolicyView.class}));
            assertNull(u.openConnection().getContent(new Class<?>[] {String.class}));

            // A valid ID for a service the control plane does not know, and a caller without read rights.
            assertThrows(FileNotFoundException.class, () -> ztp("ztp://policy/app-99", new ZtpUrlHandler(viewer)).getContent());
            PolicySource gateway = id -> cp.getPolicy(new Dto.PolicyRequest(fx.cred("gw-app-02"), id));
            IOException denied = assertThrows(IOException.class,
                    () -> ztp("ztp://policy/app-02", new ZtpUrlHandler(gateway)).getContent());
            assertTrue(denied.getMessage().contains("UNAUTHORIZED"), denied.getMessage());
        }
    }

    public void testOnlyTheFixedAuthorityAndOneServiceIdAreAccepted() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        ZtpUrlHandler h = new ZtpUrlHandler(id -> {
            calls.incrementAndGet();
            throw new IOException("must not be reached");
        });
        String[] bad = {
                "ztp://control/app-02",          // wrong authority
                "ztp://POLICY/app-02",           // the authority is case-sensitive
                "ztp://127.0.0.1/app-02",        // a URL cannot pick a host ...
                "ztp://policy:1099/app-02",      // ... or a port
                "ztp://admin@policy/app-02",     // no user info
                "ztp://policy/App-02",           // invalid service ID
                "ztp://policy/-app",
                "ztp://policy/",                 // no service
                "ztp://policy",
                "ztp://policy/app-02/edges",     // extra path segment
                "ztp://policy/../keys",
                "ztp://policy/app%2D02",         // no escapes
                "ztp://policy/app-02?host=10.0.0.9", // no query
                "ztp://policy/app-02#x",         // no fragment
                "ztp:///app-02",
        };
        for (String b : bad) {
            assertThrows(MalformedURLException.class, () -> ztp(b, h));
        }
        assertEquals(0, calls.get()); // nothing was ever fetched
        URL ok = ztp("ztp://policy/app-02", h);
        assertEquals("app-02", ZtpUrlHandler.serviceId(ok));
    }

    public void testConnectionIsReadOnly() throws Exception {
        PolicySource fixed = id -> new Dto.PolicyView(null, null, 7, 3, 2, PolicyMode.LEARN, 30_000,
                List.of(new eastguard.common.Edge("api-01", id)), List.of(), List.of(), List.of());
        URLConnection c = ztp("ztp://policy/app-02", new ZtpUrlHandler(fixed)).openConnection();
        assertThrows(IllegalArgumentException.class, () -> c.setDoOutput(true));
        assertThrows(UnknownServiceException.class, c::getOutputStream);
        assertEquals(List.of("api-01"), ((PolicyView) c.getContent()).allowedSources());
    }

    public void testAnEdgeForAnotherServiceIsRefused() throws Exception {
        PolicySource confused = id -> new Dto.PolicyView(null, null, 7, 3, 2, PolicyMode.ENFORCE, 30_000,
                List.of(new eastguard.common.Edge("api-01", "app-03")), List.of(), List.of(), List.of());
        assertThrows(IOException.class, () -> ztp("ztp://policy/app-02", new ZtpUrlHandler(confused)).getContent());
    }

    public void testNoGlobalHandlerIsRegistered() {
        assertThrows(MalformedURLException.class, () -> URI.create("ztp://policy/app-02").toURL());
    }
}
