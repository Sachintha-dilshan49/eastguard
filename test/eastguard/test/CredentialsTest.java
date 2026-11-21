package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Bytes;
import eastguard.common.Endpoint;
import eastguard.common.IpAddress;
import eastguard.common.Sha256;
import eastguard.control.ControlClient;
import eastguard.control.ControlPlaneImpl;
import eastguard.control.ControlServer;
import eastguard.control.Credentials;
import eastguard.control.Dto;
import eastguard.control.Dto.ErrorCode;
import eastguard.control.Journal;
import eastguard.control.Role;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.HexFormat;
import java.util.function.BooleanSupplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Spec §10 "key rotation or revocation" for API credentials: the file {@code scripts\gen-credentials.ps1} writes,
 * a planned rotation (two digests during the overlap, then retire), emergency revocation, and the control plane
 * picking each change up without a restart.
 */
public final class CredentialsTest {
    private static final Logger QUIET = Logger.getLogger("eastguard.control");
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Bytes oldSecret = secret();
    private final Bytes newSecret = secret();
    private final Path file;

    public CredentialsTest() throws Exception {
        QUIET.setLevel(Level.OFF); // refused calls log on purpose
        Path dir = Files.createTempDirectory(Files.createDirectories(Path.of("out", "test-control")), "cred");
        file = dir.resolve("control-credentials.properties");
    }

    private static Bytes secret() {
        byte[] b = new byte[32];
        RANDOM.nextBytes(b);
        return Bytes.copyOf(b);
    }

    private static String hex(Bytes secret) {
        return HexFormat.of().formatHex(Sha256.digest(secret.toArray()).toArray());
    }

    /** The exact layout gen-credentials.ps1 writes: digests newest first, comma separated. */
    private void write(boolean enabled, Bytes... digestsOf) throws Exception {
        StringBuilder d = new StringBuilder();
        for (Bytes s : digestsOf) {
            d.append(d.length() > 0 ? "," : "").append(hex(s));
        }
        String text = "# EastGuard control-plane API credentials: SHA-256 digests only, never secrets.\n"
                + "principals=op,viewer\n"
                + "principal.op.role=OPERATOR\n"
                + "principal.op.sha256=" + d + "\n"
                + "principal.op.enabled=" + enabled + "\n"
                + "principal.viewer.role=VIEWER\n"
                + "principal.viewer.sha256=" + hex(oldSecret) + "\n"
                + "principal.viewer.enabled=true\n";
        Files.writeString(file, text, StandardCharsets.UTF_8);
    }

    private static Dto.Credential op(Bytes secret) {
        return new Dto.Credential("op", secret);
    }

    public void testRotationOverlapAcceptsBothSecretsUntilRetired() throws Exception {
        write(true, oldSecret);
        assertEquals(Role.OPERATOR, Credentials.load(file).authenticate(op(oldSecret)));
        assertNull(Credentials.load(file).authenticate(op(newSecret)));

        write(true, newSecret, oldSecret); // -Rotate op: new digest first, old kept for the overlap
        Credentials overlap = Credentials.load(file);
        assertEquals(Role.OPERATOR, overlap.authenticate(op(newSecret)));
        assertEquals(Role.OPERATOR, overlap.authenticate(op(oldSecret)));

        write(true, newSecret); // -Retire op
        Credentials retired = Credentials.load(file);
        assertEquals(Role.OPERATOR, retired.authenticate(op(newSecret)));
        assertNull(retired.authenticate(op(oldSecret)));
    }

    public void testRevokedPrincipalIsRejectedAndMalformedFilesFail() throws Exception {
        write(false, newSecret); // -Revoke op
        Credentials c = Credentials.load(file);
        assertNull(c.authenticate(op(newSecret)));
        assertEquals(Role.VIEWER, c.authenticate(new Dto.Credential("viewer", oldSecret)));
        assertNull(c.authenticate(new Dto.Credential("viewer", newSecret)));
        assertNull(c.authenticate(new Dto.Credential("nobody", oldSecret)));

        Files.writeString(file, "principals=op\nprincipal.op.role=OPERATOR\nprincipal.op.sha256=not-hex\n");
        assertThrows(IllegalArgumentException.class, () -> Credentials.load(file));
        Files.writeString(file, "principals=op\nprincipal.op.role=ROOT\nprincipal.op.sha256=" + hex(oldSecret) + "\n");
        assertThrows(IllegalArgumentException.class, () -> Credentials.load(file));
    }

    /** Over real RMI: rotation, retirement and revocation take effect on the next call, no restart. */
    public void testControlServerReloadsRotationAndRevocationWithoutRestart() throws Exception {
        ControlFixtures fx = new ControlFixtures();
        int registryPort = RmiTest.freePort();
        int objectPort = RmiTest.freePort();
        write(true, oldSecret);
        try (Journal j = Journal.open(ControlFixtures.freshJournal())) {
            ControlPlaneImpl impl = fx.bootstrapped(j);
            impl.setCredentials(Credentials.load(file)); // what ControlPlaneImpl.main loads at startup
            ControlServer server = ControlServer.start(impl, TestPki.context("control"), "127.0.0.1", registryPort,
                    objectPort, file);
            try {
                Endpoint registry = new Endpoint(IpAddress.parse("127.0.0.1"), registryPort);
                ControlClient withOld = new ControlClient(registry, objectPort, op(oldSecret), TestPki.context("tokensvc"));
                ControlClient withNew = new ControlClient(registry, objectPort, op(newSecret), TestPki.context("tokensvc"));
                assertTrue(withOld.getDashboard(0, 1).ok(), "old secret works before the rotation");
                assertEquals(ErrorCode.UNAUTHORIZED, withNew.getDashboard(0, 1).error());

                write(true, newSecret, oldSecret);
                touch(1);
                await(() -> ok(withNew), "rotated secret accepted after the reload");
                assertTrue(ok(withOld), "old secret still accepted during the overlap");

                write(true, newSecret);
                touch(2);
                await(() -> !ok(withOld), "retired secret refused");
                assertTrue(ok(withNew), "new secret still accepted");

                write(false, newSecret);
                touch(3);
                await(() -> !ok(withNew), "revoked principal refused without a restart");
                assertEquals(ErrorCode.UNAUTHORIZED, withNew.getDashboard(0, 1).error());
            } finally {
                server.close();
            }
        }
    }

    private static boolean ok(ControlClient c) {
        try {
            return c.getDashboard(0, 1).ok();
        } catch (java.io.IOException e) {
            return false;
        }
    }

    /** Distinct modification times even on file systems with coarse timestamps. */
    private void touch(int step) throws Exception {
        Files.setLastModifiedTime(file, FileTime.from(Instant.now().plusSeconds(10L * step)));
    }

    private static void await(BooleanSupplier condition, String what) throws InterruptedException {
        long end = System.nanoTime() + 5_000_000_000L;
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > end) {
                fail("timed out waiting: " + what);
            }
            Thread.sleep(100);
        }
    }
}
