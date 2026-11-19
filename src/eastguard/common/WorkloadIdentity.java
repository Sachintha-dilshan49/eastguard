package eastguard.common;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

/**
 * Maps a verified client certificate to a registered workload (spec §4.1).
 *
 * <p>The identity is the one URI SAN of the form {@code urn:eastguard:workload:<id>}. The certificate CN is never
 * used. A certificate is rejected when it has no such SAN, more than one (in any letter case, so a case variant
 * cannot smuggle in a second identity), a malformed ID, or is outside its validity period at the injected clock
 * (session resumption can outlive a certificate). The ID must be registered, enabled, and the leaf must not be
 * revoked. URI SANs in other namespaces (e.g. {@code urn:eastguard:component:*}) are ignored.
 *
 * <p>This runs on every connection, including resumed TLS sessions, against the currently installed registry.
 * {@link PolicyEvaluator} repeats the registry checks; this class adds the certificate-to-identity binding.
 */
public final class WorkloadIdentity {
    public static final String URI_PREFIX = "urn:eastguard:workload:";
    /** GeneralName tag for uniformResourceIdentifier, as reported by {@link X509Certificate#getSubjectAlternativeNames}. */
    private static final int SAN_URI = 6;

    /** {@code peer} is set only when {@code reason} is {@link ReasonCode#OK}. */
    public record Result(ReasonCode reason, Peer peer) {
        public Result {
            Objects.requireNonNull(reason, "reason");
            if ((reason == ReasonCode.OK) != (peer != null)) {
                throw new IllegalArgumentException("peer must be present exactly when OK");
            }
        }

        static Result deny(ReasonCode reason) {
            return new Result(reason, null);
        }

        public boolean ok() {
            return reason == ReasonCode.OK;
        }
    }

    private WorkloadIdentity() {
    }

    /**
     * Authenticates the peer of an established TLS session. {@code socketIp} must come from the accepted socket,
     * never from anything the peer sent.
     */
    public static Result authenticate(SSLSession session, IpAddress socketIp, Map<String, Workload> registry,
            Clock clock) {
        Certificate[] chain;
        try {
            chain = session.getPeerCertificates();
        } catch (SSLPeerUnverifiedException e) {
            return Result.deny(ReasonCode.BAD_IDENTITY);
        }
        if (chain == null || chain.length == 0 || !(chain[0] instanceof X509Certificate leaf)) {
            return Result.deny(ReasonCode.BAD_IDENTITY);
        }
        return authenticate(leaf, socketIp, registry, clock);
    }

    /** As {@link #authenticate(SSLSession, IpAddress, Map, Clock)} for a leaf already verified by the TLS layer. */
    public static Result authenticate(X509Certificate leaf, IpAddress socketIp, Map<String, Workload> registry,
            Clock clock) {
        Objects.requireNonNull(socketIp, "socketIp");
        Objects.requireNonNull(registry, "registry");
        try {
            leaf.checkValidity(Date.from(clock.instant()));
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            return Result.deny(ReasonCode.BAD_IDENTITY);
        }
        String id;
        try {
            id = workloadIdFromSans(leaf.getSubjectAlternativeNames());
        } catch (CertificateParsingException e) {
            return Result.deny(ReasonCode.BAD_IDENTITY);
        }
        if (id == null) {
            return Result.deny(ReasonCode.BAD_IDENTITY);
        }
        Workload w = registry.get(id);
        if (w == null || !w.enabled()) {
            return Result.deny(ReasonCode.IDENTITY_DISABLED);
        }
        Bytes fingerprint;
        try {
            fingerprint = fingerprint(leaf);
        } catch (CertificateException e) {
            return Result.deny(ReasonCode.BAD_IDENTITY);
        }
        if (w.isCertificateRevoked(fingerprint)) {
            return Result.deny(ReasonCode.REVOKED);
        }
        return new Result(ReasonCode.OK, new Peer(id, fingerprint, socketIp));
    }

    /**
     * Pure mapping from SAN entries (the format of {@link X509Certificate#getSubjectAlternativeNames()}) to a
     * workload ID. Returns {@code null} when there is not exactly one workload URI SAN or its ID is invalid.
     */
    public static String workloadIdFromSans(Collection<List<?>> sans) {
        if (sans == null) {
            return null;
        }
        String found = null;
        int count = 0;
        for (List<?> entry : sans) {
            if (entry == null || entry.size() < 2 || !(entry.get(0) instanceof Integer tag) || tag != SAN_URI
                    || !(entry.get(1) instanceof String uri)) {
                continue;
            }
            if (uri.length() >= URI_PREFIX.length()
                    && uri.substring(0, URI_PREFIX.length()).toLowerCase(Locale.ROOT).equals(URI_PREFIX)) {
                count++;
                found = uri;
            }
        }
        if (count != 1 || !found.startsWith(URI_PREFIX)) {
            return null;
        }
        String id = found.substring(URI_PREFIX.length());
        return Ids.isValid(id) ? id : null;
    }

    /** SHA-256 of the DER-encoded certificate: the {@code leafSha256} bound into leases. */
    public static Bytes fingerprint(X509Certificate cert) throws CertificateEncodingException {
        return Sha256.digest(cert.getEncoded());
    }
}
