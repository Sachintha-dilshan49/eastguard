package eastguard.control;

import eastguard.common.Bytes;
import eastguard.common.Config;
import eastguard.common.Edge;
import eastguard.common.Endpoint;
import eastguard.common.Ids;
import eastguard.common.PolicyMode;
import eastguard.common.SecretSource;
import eastguard.common.Selector;
import eastguard.control.Dto.Credential;
import eastguard.control.Dto.MutationResult;
import java.io.IOException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import javax.net.ssl.SSLContext;

/**
 * Client of the control plane for gateways, the token service, operators and the dashboard (spec §7.1). Looks up
 * the stub through the TLS registry on first use and again after a transport failure. Every call sends this
 * client's API credential. Calls block for at most the RMI deadlines in {@link RmiSupport}; never call this from a
 * selector or UI thread.
 */
public final class ControlClient {
    /**
     * Client settings, from a component's properties:
     *
     * <pre>
     * control.registry=127.0.0.1:1099           numeric; the stub's object endpoint must be on the same IP
     * control.objectPort=1100
     * control.principal=gw-app-02
     * control.secretEnv=EASTGUARD_API_SECRET    base64url secret, else from the file below
     * control.secretFile=keys/api/gw-app-02.secret
     * </pre>
     */
    public record Settings(Endpoint registry, int objectPort, String principal, SecretSource secret) {
        public Settings {
            Objects.requireNonNull(registry, "registry");
            if (objectPort < 1 || objectPort > 65_535) {
                throw new IllegalArgumentException("objectPort out of range");
            }
            Ids.require(principal, "principal");
            Objects.requireNonNull(secret, "secret");
        }

        public static Settings from(Config c) {
            return new Settings(c.endpoint("control.registry"), c.intIn("control.objectPort", 1100, 1, 65_535),
                    c.id("control.principal"), new SecretSource(c.string("control.secretEnv", "EASTGUARD_API_SECRET"),
                            c.path("control.secretFile")));
        }

        /** The control-plane endpoints a client may connect to: the registry and the object port. */
        public Set<Endpoint> endpoints() {
            return Set.of(registry, new Endpoint(registry.ip(), objectPort));
        }
    }

    private final Endpoint registry;
    private final Credential credential;
    private volatile ControlPlane stub;

    /** @param ctx this process's RMI client TLS context (see {@link RmiSupport#installClient}) */
    public ControlClient(Settings settings, SSLContext ctx) {
        this(settings.registry(), settings.objectPort(), new Credential(settings.principal(), readSecret(settings.secret())),
                ctx);
    }

    public ControlClient(Endpoint registry, int objectPort, Credential credential, SSLContext ctx) {
        this.registry = Objects.requireNonNull(registry, "registry");
        this.credential = Objects.requireNonNull(credential, "credential");
        RmiSupport.installClient(ctx, Set.of(registry, new Endpoint(registry.ip(), objectPort)));
    }

    /** Decodes a base64url secret (as written by {@code scripts/gen-credentials.ps1}). */
    public static Bytes readSecret(SecretSource source) {
        char[] chars = source.read();
        byte[] ascii = new byte[chars.length];
        try {
            for (int i = 0; i < chars.length; i++) {
                ascii[i] = (byte) chars[i];
            }
            byte[] raw = Base64.getUrlDecoder().decode(ascii);
            if (raw.length < Credentials.MIN_SECRET || raw.length > Credentials.MAX_SECRET) {
                throw new IllegalArgumentException("API secret from " + source + " has the wrong length");
            }
            Bytes b = Bytes.copyOf(raw);
            Arrays.fill(raw, (byte) 0);
            return b;
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("API secret from " + source + " is not base64url", e);
        } finally {
            Arrays.fill(chars, '\0');
            Arrays.fill(ascii, (byte) 0);
        }
    }

    public String principal() {
        return credential.principal();
    }

    @FunctionalInterface
    private interface Call<T> {
        T on(ControlPlane cp) throws RemoteException;
    }

    private <T> T call(Call<T> c) throws IOException {
        ControlPlane cp = stub;
        if (cp == null) {
            Registry r = LocateRegistry.getRegistry(registry.ip().toString(), registry.port(), new TlsRmiClientSocketFactory());
            try {
                cp = (ControlPlane) r.lookup(ControlPlane.NAME);
            } catch (NotBoundException e) {
                throw new IOException("control plane is not bound in the registry");
            } catch (ClassCastException e) {
                throw new IOException("registry returned an unexpected object");
            }
            stub = cp;
        }
        try {
            return c.on(cp);
        } catch (RemoteException e) {
            stub = null; // look up again next time (control plane restarted or moved ports)
            throw e;
        }
    }

    public Dto.SyncResponse sync(long knownRevision) throws IOException {
        return call(cp -> cp.sync(new Dto.SyncRequest(credential, knownRevision)));
    }

    public Dto.DashboardView getDashboard(long cursor, int limit) throws IOException {
        return call(cp -> cp.getDashboard(new Dto.DashboardRequest(credential, cursor, limit)));
    }

    public Dto.PolicyView getPolicy(String serviceId) throws IOException {
        return call(cp -> cp.getPolicy(new Dto.PolicyRequest(credential, serviceId)));
    }

    public MutationResult quarantine(String requestId, List<Selector> selectors, Duration ttl, String reason)
            throws IOException {
        return call(cp -> cp.quarantine(new Dto.QuarantineRequest(credential, requestId, selectors, ttl.toMillis(), reason)));
    }

    public MutationResult release(String requestId, List<Selector> selectors, String reason) throws IOException {
        return call(cp -> cp.release(new Dto.ReleaseRequest(credential, requestId, selectors, reason)));
    }

    public MutationResult replacePolicy(String requestId, long expectedPolicyRevision, List<Edge> edges, String reason)
            throws IOException {
        return call(cp -> cp.replacePolicy(new Dto.ReplacePolicyRequest(credential, requestId, expectedPolicyRevision,
                edges, reason)));
    }

    public MutationResult setMode(String requestId, long expectedPolicyRevision, PolicyMode mode,
            List<String> pilotSources, List<String> pilotServices, String reason) throws IOException {
        return call(cp -> cp.setMode(new Dto.SetModeRequest(credential, requestId, expectedPolicyRevision, mode,
                pilotSources, pilotServices, reason)));
    }

    /** Detector: learning observations (spec §7.1). */
    public MutationResult recordObservations(String requestId, List<Dto.Observation> observations) throws IOException {
        return call(cp -> cp.recordObservations(new Dto.ObservationBatch(credential, requestId, observations)));
    }

    /** Detector: an action proposal; retry with the same {@code requestId} after a transport failure. */
    public MutationResult proposeAction(String requestId, Dto.ActionType action, List<Selector> selectors, Duration ttl,
            int score, List<String> signals, List<String> evidence) throws IOException {
        return call(cp -> cp.proposeAction(new Dto.ActionProposal(credential, requestId, action, selectors, ttl.toMillis(),
                score, signals, evidence)));
    }

    public MutationResult setLeaseDefaults(String requestId, long expectedPolicyRevision, Duration lease, String reason)
            throws IOException {
        return call(cp -> cp.setLeaseDefaults(new Dto.SetLeaseDefaultsRequest(credential, requestId,
                expectedPolicyRevision, lease.toMillis(), reason)));
    }
}
