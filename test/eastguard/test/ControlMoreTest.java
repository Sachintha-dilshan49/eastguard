package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Bytes;
import eastguard.common.Edge;
import eastguard.common.Endpoint;
import eastguard.common.IpAddress;
import eastguard.common.SecretSource;
import eastguard.control.AuditClient;
import eastguard.control.ControlClient;
import eastguard.control.EdgeDiff;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Set;

/**
 * Tests for control plane helper classes:
 * {@link EdgeDiff}, {@link AuditClient} parameter checking, and {@link ControlClient} settings and secret parsing.
 */
public final class ControlMoreTest {

    public void testEdgeDiffAdditionsRemovalsAndKept() {
        Edge webApp02 = new Edge("web-01", "app-02");
        Edge webApp03 = new Edge("web-01", "app-03");
        Edge apiApp02 = new Edge("api-01", "app-02");

        List<Edge> current = List.of(webApp02, webApp03);
        List<Edge> reviewed = List.of(webApp02, apiApp02);

        EdgeDiff diff = EdgeDiff.of(current, reviewed);

        assertFalse(diff.empty(), "diff not empty");
        assertEquals(List.of(apiApp02), diff.additions());
        assertEquals(List.of(webApp03), diff.removals());
        assertEquals(List.of(webApp02), diff.kept());

        String s = diff.toString();
        assertEquals("[+api-01->app-02, -web-01->app-03]", s);

        // Identical sets -> empty diff
        EdgeDiff identical = EdgeDiff.of(current, current);
        assertTrue(identical.empty(), "identical is empty");
        assertEquals(List.of(), identical.additions());
        assertEquals(List.of(), identical.removals());
        assertEquals(current, identical.kept());
    }

    public void testAuditClientRejectsNonHttps() {
        AuditClient client = new AuditClient(TestPki.context("console"), Duration.ofSeconds(2));
        assertThrows(IOException.class, () -> client.get(URI.create("http://127.0.0.1:9443/audit")));
        assertThrows(IOException.class, () -> client.get(URI.create("ftp://127.0.0.1:9443/audit")));
    }

    public void testControlClientSettingsAndSecretParsing() throws IOException {
        Endpoint reg = new Endpoint(IpAddress.parse("127.0.0.1"), 1099);
        SecretSource sec = new SecretSource("DUMMY_ENV", Path.of("keys/api/gw-app-02.secret"));

        assertThrows(NullPointerException.class, () -> new ControlClient.Settings(null, 1100, "gw", sec));
        assertThrows(IllegalArgumentException.class, () -> new ControlClient.Settings(reg, 0, "gw", sec));
        assertThrows(IllegalArgumentException.class, () -> new ControlClient.Settings(reg, 70000, "gw", sec));
        assertThrows(IllegalArgumentException.class, () -> new ControlClient.Settings(reg, 1100, null, sec));
        assertThrows(NullPointerException.class, () -> new ControlClient.Settings(reg, 1100, "gw", null));

        ControlClient.Settings settings = new ControlClient.Settings(reg, 1100, "gw-app-02", sec);
        assertEquals(Set.of(reg, new Endpoint(reg.ip(), 1100)), settings.endpoints());

        // Test readSecret with valid 32-byte secret read from temporary file
        byte[] raw = new byte[32];
        for (int i = 0; i < 32; i++) raw[i] = (byte) i;
        String b64 = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        Path tmp = Files.createTempFile("test-secret", ".txt");
        try {
            Files.writeString(tmp, b64);
            SecretSource fileSource = new SecretSource("NON_EXISTENT_VAR_" + System.currentTimeMillis(), tmp);
            Bytes secret = ControlClient.readSecret(fileSource);
            assertArrayEquals(raw, secret.toArray());
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
