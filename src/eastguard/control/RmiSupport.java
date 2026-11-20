package eastguard.control;

import eastguard.common.Endpoint;
import eastguard.common.IpAddress;
import eastguard.tokensvc.TlsContextFactory;
import java.io.IOException;
import java.io.ObjectInputFilter;
import java.net.Socket;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;

/**
 * JVM-wide RMI hardening shared by the control plane and its clients (spec §7.1).
 *
 * <ul>
 *   <li>{@link #configureJvm}: no remote class loading ({@code useCodebaseOnly}), connect/handshake/response
 *       deadlines on client calls, a read timeout and a connection-thread cap on the server. The RMI transport
 *       reads these once, so call this before any RMI class is used.</li>
 *   <li>{@link #installClient}: the process's RMI client TLS context and the allowlist of control-plane
 *       endpoints. {@link TlsRmiClientSocketFactory} arrives inside stubs from the server, so it cannot carry an
 *       {@link SSLContext}; it looks the context up here. It refuses any host:port not on the allowlist (a stub
 *       may advertise an unexpected endpoint) and verifies the server certificate against that IP.</li>
 *   <li>The client side of the process also gets the narrow {@link RmiFilter#client()} deserialization filter.</li>
 * </ul>
 *
 * <p><b>One client TLS identity per process.</b> RMI pools connections per endpoint across callers, so a TLS
 * client certificate cannot identify the calling principal anyway; the per-call API credential does that. The
 * first installed context is kept; later installs only add endpoints. TLS still ensures that only holders of an
 * EastGuard-issued certificate reach the control plane at all.
 */
public final class RmiSupport {
    private static final Logger LOG = Logger.getLogger(RmiSupport.class.getName());
    public static final Duration CALL_TIMEOUT = Duration.ofSeconds(5);

    private static final AtomicReference<SSLContext> CLIENT_CONTEXT = new AtomicReference<>();
    private static final Set<Endpoint> ALLOWED = ConcurrentHashMap.newKeySet();
    private static boolean configured;
    private static boolean filterInstalled;

    private RmiSupport() {
    }

    /**
     * Sets the RMI system properties. {@code advertisedHost} (numeric) becomes {@code java.rmi.server.hostname},
     * the address servers put into their stubs; pass {@code null} in a pure client.
     */
    public static synchronized void configureJvm(String advertisedHost) {
        if (advertisedHost != null) {
            IpAddress.parse(advertisedHost); // numeric only: never resolve, never advertise a name
            String current = System.getProperty("java.rmi.server.hostname");
            if (current != null && !current.equals(advertisedHost)) {
                throw new IllegalStateException("java.rmi.server.hostname is already " + current);
            }
            System.setProperty("java.rmi.server.hostname", advertisedHost);
        }
        if (configured) {
            return;
        }
        String ms = Long.toString(CALL_TIMEOUT.toMillis());
        setDefault("java.rmi.server.useCodebaseOnly", "true");
        setDefault("sun.rmi.transport.tcp.responseTimeout", ms);
        setDefault("sun.rmi.transport.tcp.handshakeTimeout", ms);
        setDefault("sun.rmi.transport.tcp.readTimeout", "30000");
        setDefault("sun.rmi.transport.tcp.maxConnectionThreads", "64");
        configured = true;
    }

    private static void setDefault(String key, String value) {
        if (System.getProperty(key) == null) {
            System.setProperty(key, value);
        }
    }

    /**
     * Installs this process's RMI client TLS context (first one wins) and allows the given control-plane
     * endpoints (registry and object port). Also installs the process-wide client deserialization filter.
     */
    public static synchronized void installClient(SSLContext ctx, Set<Endpoint> endpoints) {
        configureJvm(null);
        Objects.requireNonNull(ctx, "ctx");
        if (!CLIENT_CONTEXT.compareAndSet(null, ctx)) {
            LOG.fine("RMI client TLS context already installed; keeping the first");
        }
        ALLOWED.addAll(endpoints);
        installProcessFilter();
    }

    /** Process-wide filter for everything this JVM deserializes outside streams with their own filter. */
    public static synchronized void installProcessFilter() {
        if (filterInstalled) {
            return;
        }
        ObjectInputFilter current = ObjectInputFilter.Config.getSerialFilter();
        if (current == null) {
            ObjectInputFilter.Config.setSerialFilter(RmiFilter.client());
        } else if (!(current instanceof RmiFilter)) {
            LOG.warning("a process-wide deserialization filter is already set; leaving it in place");
        }
        filterInstalled = true;
    }

    /** Called by {@link TlsRmiClientSocketFactory}. */
    static Socket clientSocket(String host, int port) throws IOException {
        SSLContext ctx = CLIENT_CONTEXT.get();
        if (ctx == null) {
            throw new IOException("RMI client TLS context not installed");
        }
        Endpoint target;
        try {
            target = new Endpoint(IpAddress.parse(host), port); // a host name in a stub is refused, not resolved
        } catch (IllegalArgumentException e) {
            throw new IOException("refusing RMI endpoint with a non-numeric host");
        }
        if (!ALLOWED.contains(target)) {
            throw new IOException("refusing unexpected RMI endpoint " + target);
        }
        // Server certificate must carry this IP as a SAN; connect and every read have deadlines.
        return TlsContextFactory.connect(ctx, target, host, CALL_TIMEOUT);
    }
}
