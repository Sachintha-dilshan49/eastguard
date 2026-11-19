package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Bytes;
import eastguard.common.IpAddress;
import eastguard.common.ReasonCode;
import eastguard.common.Sha256;
import eastguard.common.Workload;
import eastguard.common.WorkloadIdentity;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class WorkloadIdentityTest {
    private static final IpAddress IP = IpAddress.parse("127.0.0.1");
    private static final Map<String, Workload> REGISTRY = Map.of(
            "web-01", Workload.enabled("web-01"), "api-01", Workload.enabled("api-01"));

    private static List<List<?>> sans(Object... tagValuePairs) {
        List<List<?>> out = new java.util.ArrayList<>();
        for (int i = 0; i < tagValuePairs.length; i += 2) {
            out.add(Arrays.asList(tagValuePairs[i], tagValuePairs[i + 1]));
        }
        return out;
    }

    private static String id(Object... tagValuePairs) {
        return WorkloadIdentity.workloadIdFromSans(sans(tagValuePairs));
    }

    // ---- pure SAN mapping ----

    public void testSingleWorkloadUriMaps() {
        assertEquals("web-01", id(6, "urn:eastguard:workload:web-01"));
        assertEquals("a.b_c-9", id(6, "urn:eastguard:workload:a.b_c-9"));
    }

    public void testOtherSanTypesAndNamespacesIgnored() {
        assertEquals("web-01", id(2, "localhost", 7, "127.0.0.1", 6, "urn:eastguard:component:gateway-app-02",
                6, "urn:eastguard:workload:web-01", 6, "https://example.test/x"));
    }

    public void testMissingIdentityRejected() {
        assertNull(WorkloadIdentity.workloadIdFromSans(null));
        assertNull(id());
        assertNull(id(2, "web-01"));
        assertNull(id(6, "urn:eastguard:component:web-01"));
        assertNull(id(6, "urn:eastguard:workloads:web-01"));
    }

    public void testMultipleIdentitiesRejected() {
        assertNull(id(6, "urn:eastguard:workload:web-01", 6, "urn:eastguard:workload:api-01"));
        assertNull(id(6, "urn:eastguard:workload:web-01", 6, "urn:eastguard:workload:web-01"));
        // A case variant of the prefix still counts, so it cannot hide a second identity.
        assertNull(id(6, "urn:eastguard:workload:web-01", 6, "URN:EastGuard:Workload:api-01"));
    }

    public void testNonCanonicalOrInvalidIdRejected() {
        assertNull(id(6, "URN:EASTGUARD:WORKLOAD:web-01"));
        assertNull(id(6, "urn:eastguard:workload:"));
        assertNull(id(6, "urn:eastguard:workload:Web-01"));
        assertNull(id(6, "urn:eastguard:workload:web-01/extra"));
        assertNull(id(6, "urn:eastguard:workload:-web"));
        assertNull(id(6, "urn:eastguard:workload:" + "a".repeat(65)));
    }

    public void testMalformedEntriesIgnored() {
        List<List<?>> odd = new java.util.ArrayList<>();
        odd.add(null);
        odd.add(List.of(6));
        odd.add(Arrays.asList(6, new byte[] {1}));
        odd.add(Arrays.asList("6", "urn:eastguard:workload:api-01"));
        odd.add(Arrays.asList(6, "urn:eastguard:workload:web-01"));
        assertEquals("web-01", WorkloadIdentity.workloadIdFromSans(odd));
    }

    // ---- real certificates from gen-certs.ps1 ----

    private static WorkloadIdentity.Result auth(String store, Map<String, Workload> registry, Clock clock) {
        return WorkloadIdentity.authenticate(TestPki.leaf(store), IP, registry, clock);
    }

    private static WorkloadIdentity.Result auth(String store) {
        return auth(store, REGISTRY, Clock.systemUTC());
    }

    public void testRealWorkloadCertificate() throws Exception {
        X509Certificate leaf = TestPki.leaf("workload-web-01");
        WorkloadIdentity.Result r = auth("workload-web-01");
        assertTrue(r.ok(), "web-01 should authenticate: " + r.reason());
        assertEquals("web-01", r.peer().identity());
        assertEquals(IP, r.peer().ip());
        assertEquals(Sha256.digest(leaf.getEncoded()), r.peer().leafSha256());
        assertEquals("api-01", auth("workload-api-01").peer().identity());
    }

    public void testCommonNameNeverUsed() {
        // CN=web-01 but no SAN.
        assertEquals(ReasonCode.BAD_IDENTITY, auth("workload-nosan").reason());
    }

    public void testAmbiguousCertificateRejected() {
        assertEquals(ReasonCode.BAD_IDENTITY, auth("workload-twosan").reason());
    }

    public void testComponentCertificateIsNotAWorkload() {
        assertEquals(ReasonCode.BAD_IDENTITY, auth("tokensvc").reason());
        assertEquals(ReasonCode.BAD_IDENTITY, auth("gateway-app-02").reason());
    }

    public void testUnregisteredOrDisabledRejected() {
        assertEquals(ReasonCode.IDENTITY_DISABLED,
                auth("workload-web-01", Map.of("api-01", Workload.enabled("api-01")), Clock.systemUTC()).reason());
        Workload disabled = new Workload("web-01", false, Set.of(), null);
        assertEquals(ReasonCode.IDENTITY_DISABLED,
                auth("workload-web-01", Map.of("web-01", disabled), Clock.systemUTC()).reason());
    }

    public void testRevokedCertificateRejected() {
        Bytes fp = TestPki.fingerprint("workload-web-01");
        Workload revoked = new Workload("web-01", true, Set.of(fp), null);
        assertEquals(ReasonCode.REVOKED, auth("workload-web-01", Map.of("web-01", revoked), Clock.systemUTC()).reason());
        // Revoking a different certificate does not affect this one.
        Workload other = new Workload("web-01", true, Set.of(TestPki.fingerprint("workload-api-01")), null);
        assertTrue(auth("workload-web-01", Map.of("web-01", other), Clock.systemUTC()).ok(), "other cert revoked");
    }

    public void testCertificateOutsideValidityRejected() {
        X509Certificate leaf = TestPki.leaf("workload-web-01");
        Clock afterExpiry = Clock.fixed(leaf.getNotAfter().toInstant().plusSeconds(1), ZoneOffset.UTC);
        Clock beforeStart = Clock.fixed(leaf.getNotBefore().toInstant().minus(Duration.ofDays(1)), ZoneOffset.UTC);
        assertEquals(ReasonCode.BAD_IDENTITY, auth("workload-web-01", REGISTRY, afterExpiry).reason());
        assertEquals(ReasonCode.BAD_IDENTITY, auth("workload-web-01", REGISTRY, beforeStart).reason());
    }

    public void testFingerprintIsSha256OfDer() throws Exception {
        X509Certificate leaf = TestPki.leaf("workload-api-01");
        assertEquals(Sha256.digest(leaf.getEncoded()), WorkloadIdentity.fingerprint(leaf));
        assertEquals(32, WorkloadIdentity.fingerprint(leaf).length());
    }
}
