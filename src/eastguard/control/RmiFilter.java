package eastguard.control;

import eastguard.common.Bytes;
import eastguard.common.Edge;
import eastguard.common.IpAddress;
import eastguard.common.PolicyMode;
import eastguard.common.Selector;
import eastguard.common.SelectorType;
import java.io.ObjectInputFilter;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

/**
 * Narrow allowlist deserialization filter for RMI (spec §7.1 hardening). Everything not listed is rejected,
 * and graph depth, references, array length and stream bytes are bounded.
 *
 * <ul>
 *   <li>{@link #arguments()}: what the control plane accepts as call arguments, i.e. the request DTOs and the
 *       value types inside them. Installed per exported object, so it applies to exactly those streams.</li>
 *   <li>{@link #client()}: the process-wide filter of an RMI client: additionally the response DTOs, the
 *       control-plane stub (a dynamic proxy for {@link ControlPlane} with this project's socket factory), and the
 *       JDK exception types that RMI uses to report remote failures.</li>
 * </ul>
 */
public final class RmiFilter implements ObjectInputFilter {
    private static final Logger LOG = Logger.getLogger(RmiFilter.class.getName());
    private static final AtomicLong REJECTED = new AtomicLong();

    private static final Set<Class<?>> VALUES = Set.of(
            Selector.class, SelectorType.class, Edge.class, IpAddress.class, Bytes.class, PolicyMode.class,
            String.class, Enum.class, Object.class,
            // List.copyOf() lists serialize as CollSer; the filter also sees what its readResolve returns.
            cls("java.util.CollSer"), cls("java.util.ImmutableCollections$List12"),
            cls("java.util.ImmutableCollections$ListN"));

    private static final Set<Class<?>> REQUESTS = Set.of(
            Dto.Credential.class, Dto.SyncRequest.class, Dto.DashboardRequest.class, Dto.PolicyRequest.class,
            Dto.QuarantineRequest.class, Dto.ReleaseRequest.class, Dto.ReplacePolicyRequest.class,
            Dto.SetModeRequest.class, Dto.SetLeaseDefaultsRequest.class, Dto.ObservationBatch.class,
            Dto.ActionProposal.class, Dto.FreezeRequest.class, Dto.Observation.class, Dto.ActionType.class);

    private static final Set<Class<?>> RESPONSES = Set.of(
            Dto.ErrorCode.class, Dto.SyncResponse.class, Dto.MutationResult.class, Dto.DashboardView.class,
            Dto.AuditEntry.class, Dto.RestrictionView.class, Dto.PolicyView.class, Dto.AlertView.class);

    private static final Set<Class<?>> STUB = Set.of(
            Proxy.class, java.rmi.server.RemoteObjectInvocationHandler.class, java.rmi.server.RemoteObject.class,
            TlsRmiClientSocketFactory.class, StackTraceElement.class,
            cls("java.util.Collections$EmptyList"),
            cls("java.util.Collections$UnmodifiableRandomAccessList"),
            cls("java.util.Collections$UnmodifiableList"),
            cls("java.util.Collections$UnmodifiableCollection"),
            java.util.ArrayList.class);

    /** Packages whose Throwable subclasses a client accepts (how RMI reports a remote failure). */
    private static final Set<String> EXCEPTION_PACKAGES = Set.of("java.lang", "java.io", "java.rmi", "java.rmi.server");

    private static Class<?> cls(String name) {
        try {
            return Class.forName(name, false, null);
        } catch (ClassNotFoundException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private final Set<Class<?>> allowed;
    private final boolean client;
    private final long maxDepth;
    private final long maxRefs;
    private final long maxArray;
    private final long maxBytes;

    private RmiFilter(Set<Class<?>> allowed, boolean client, long maxDepth, long maxRefs, long maxArray, long maxBytes) {
        this.allowed = Set.copyOf(allowed);
        this.client = client;
        this.maxDepth = maxDepth;
        this.maxRefs = maxRefs;
        this.maxArray = maxArray;
        this.maxBytes = maxBytes;
    }

    /** Server side: request DTOs only. Sized for the largest request (a 10 000-edge policy). */
    public static RmiFilter arguments() {
        Set<Class<?>> s = new HashSet<>(VALUES);
        s.addAll(REQUESTS);
        return new RmiFilter(s, false, 12, 50_000, Mutation.MAX_EDGES + 16, 2L << 20);
    }

    /** Client process: also responses, the stub, and RMI exception reports. Sized for a 1 MiB snapshot. */
    public static RmiFilter client() {
        Set<Class<?>> s = new HashSet<>(VALUES);
        s.addAll(REQUESTS);
        s.addAll(RESPONSES);
        s.addAll(STUB);
        return new RmiFilter(s, true, 20, 50_000, (2 << 20), 4L << 20);
    }

    /** Classes or limits rejected by any instance since startup. */
    public static long rejected() {
        return REJECTED.get();
    }

    @Override
    public Status checkInput(FilterInfo info) {
        if (info.depth() > maxDepth || info.references() > maxRefs || info.arrayLength() > maxArray
                || info.streamBytes() > maxBytes) {
            return reject("limits (depth " + info.depth() + ", refs " + info.references() + ", array "
                    + info.arrayLength() + ", bytes " + info.streamBytes() + ")");
        }
        Class<?> c = info.serialClass();
        if (c == null) {
            return Status.ALLOWED; // a limits-only check, already passed
        }
        while (c.isArray()) {
            c = c.getComponentType();
        }
        if (c.isPrimitive() || allowed.contains(c)) {
            return Status.ALLOWED;
        }
        if (client && Proxy.isProxyClass(c) && stubInterfaces(c)) {
            return Status.ALLOWED;
        }
        if (client && Throwable.class.isAssignableFrom(c) && EXCEPTION_PACKAGES.contains(c.getPackageName())) {
            return Status.ALLOWED;
        }
        if (client && (c == ControlPlane.class || c == Remote.class)) {
            return Status.ALLOWED; // interfaces of the stub proxy
        }
        return reject(c.getName());
    }

    private static boolean stubInterfaces(Class<?> proxy) {
        for (Class<?> i : proxy.getInterfaces()) {
            if (i != ControlPlane.class && i != Remote.class) {
                return false;
            }
        }
        return true;
    }

    private static Status reject(String what) {
        REJECTED.incrementAndGet();
        LOG.warning(() -> "deserialization rejected: " + what);
        return Status.REJECTED;
    }
}
