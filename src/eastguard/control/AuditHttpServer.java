package eastguard.control;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementSnapshot;
import eastguard.tokensvc.TlsContextFactory;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;

/**
 * Read-only HTTPS export on the control plane (spec §7.3, §9.3): {@code /audit} (paginated), {@code /metrics},
 * {@code /health/live} and {@code /health/ready}. Built on {@code jdk.httpserver}'s {@link HttpsServer}.
 *
 * <ul>
 *   <li>TLS 1.3 with a <b>required</b> client certificate (PKIX against the EastGuard trust store). A client
 *       without one fails the handshake.</li>
 *   <li>A trusted certificate is not enough: its URI SAN must be on {@code audit.allowedClients} (by default the
 *       operator console, {@code urn:eastguard:console:dashboard}). Anyone else gets 403 and no data.</li>
 *   <li>GET and HEAD only. Unknown paths 404, unknown or malformed query parameters 400. Nothing in a response
 *       is a secret: audit entries never hold credentials, tokens or keys, and metrics are counters.</li>
 *   <li>Two handler threads with a bounded queue; when it is full the dispatcher serves the request itself,
 *       which slows accepting instead of queueing without bound. Request and response times are capped
 *       through the {@code sun.net.httpserver.*} properties set by {@link #start}.</li>
 * </ul>
 *
 * Liveness means the HTTP server answers; readiness means the control plane is bootstrapped and its journal has
 * not failed ({@link ControlPlaneImpl#ready()}).
 */
public final class AuditHttpServer implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(AuditHttpServer.class.getName());
    public static final String CONSOLE_IDENTITY = "urn:eastguard:console:dashboard";
    private static final int SAN_URI = 6;

    /**
     * @param listen         numeric address and port ({@code audit.listen}, e.g. {@code 127.0.0.1:9443})
     * @param allowedClients certificate URI SANs allowed to read ({@code audit.allowedClients})
     */
    public record Settings(Endpoint listen, Set<String> allowedClients) {
        public Settings {
            Objects.requireNonNull(listen, "listen");
            allowedClients = Set.copyOf(allowedClients);
            if (allowedClients.isEmpty()) {
                throw new IllegalArgumentException("audit.allowedClients must name at least one client identity");
            }
            for (String c : allowedClients) {
                if (!c.matches("urn:eastguard:[a-z]+:[a-z0-9][a-z0-9._-]{0,63}")) {
                    throw new IllegalArgumentException("audit client must be an urn:eastguard:<kind>:<id> URI");
                }
            }
        }
    }

    private final ControlPlaneImpl cp;
    private final HttpsServer server;
    private final ThreadPoolExecutor executor;
    private final Set<String> allowed;
    private final AtomicLong requests = new AtomicLong();
    private final AtomicLong forbidden = new AtomicLong();

    private AuditHttpServer(ControlPlaneImpl cp, HttpsServer server, ThreadPoolExecutor executor, Set<String> allowed) {
        this.cp = cp;
        this.server = server;
        this.executor = executor;
        this.allowed = allowed;
    }

    public static AuditHttpServer start(ControlPlaneImpl cp, SSLContext ctx, Settings settings) throws IOException {
        Objects.requireNonNull(cp, "cp");
        Objects.requireNonNull(ctx, "ctx");
        setDefault("sun.net.httpserver.maxReqTime", "10");   // seconds to read a request, including the handshake
        setDefault("sun.net.httpserver.maxRspTime", "10");   // seconds to write a response
        setDefault("sun.net.httpserver.idleInterval", "30"); // seconds an idle keep-alive connection is kept
        HttpsServer server = HttpsServer.create(settings.listen().toSocketAddress(), 16);
        server.setHttpsConfigurator(new HttpsConfigurator(ctx) {
            @Override
            public void configure(HttpsParameters params) {
                params.setSSLParameters(TlsContextFactory.serverParameters(ctx)); // TLS 1.3, need client auth
            }
        });
        ThreadPoolExecutor executor = new ThreadPoolExecutor(2, 2, 30, TimeUnit.SECONDS, new ArrayBlockingQueue<>(32),
                r -> {
                    Thread t = new Thread(r, "audit-http");
                    t.setDaemon(true);
                    return t;
                }, new ThreadPoolExecutor.CallerRunsPolicy());
        server.setExecutor(executor);
        AuditHttpServer a = new AuditHttpServer(cp, server, executor, settings.allowedClients());
        server.createContext("/", a::handle);
        server.start();
        LOG.info(() -> "audit export on https://" + settings.listen().ip() + ":" + a.port() + " for "
                + settings.allowedClients());
        return a;
    }

    private static void setDefault(String key, String value) {
        if (System.getProperty(key) == null) {
            System.setProperty(key, value);
        }
    }

    public int port() {
        return server.getAddress().getPort();
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }

    // ---- request handling ----

    private record Response(int status, String contentType, String body) {
    }

    private void handle(HttpExchange ex) throws IOException {
        try (ex) {
            requests.incrementAndGet();
            Response r = route(ex);
            byte[] body = r.body().getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", r.contentType());
            ex.getResponseHeaders().set("Cache-Control", "no-store");
            ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
            if (r.status() == 405) {
                ex.getResponseHeaders().set("Allow", "GET, HEAD");
            }
            boolean head = "HEAD".equals(ex.getRequestMethod());
            ex.sendResponseHeaders(r.status(), head ? -1 : body.length == 0 ? -1 : body.length);
            if (!head && body.length > 0) {
                try (OutputStream out = ex.getResponseBody()) {
                    out.write(body);
                }
            }
        } catch (RuntimeException e) {
            LOG.warning(() -> "audit request failed: " + e);
        }
    }

    private Response route(HttpExchange ex) {
        String who = clientIdentity(ex);
        if (who == null || !allowed.contains(who)) {
            forbidden.incrementAndGet();
            String shown = who == null ? "<no identity>" : who;
            LOG.warning(() -> "audit export refused for " + shown);
            return json(403, "{\"error\":\"forbidden\"}");
        }
        String method = ex.getRequestMethod();
        if (!"GET".equals(method) && !"HEAD".equals(method)) {
            return json(405, "{\"error\":\"method not allowed\"}");
        }
        String path = ex.getRequestURI().getRawPath();
        String query = ex.getRequestURI().getRawQuery();
        return switch (path == null ? "" : path) {
            case "/audit" -> audit(query);
            case "/metrics" -> query != null ? json(400, "{\"error\":\"no parameters\"}") : metrics();
            case "/health/live" -> query != null ? json(400, "{\"error\":\"no parameters\"}")
                    : text(200, "live\n");
            case "/health/ready" -> query != null ? json(400, "{\"error\":\"no parameters\"}")
                    : cp.ready() ? text(200, "ready\n") : text(503, "not ready\n");
            default -> json(404, "{\"error\":\"not found\"}");
        };
    }

    /** The single {@code urn:eastguard:...} URI SAN of the verified client certificate, or {@code null}. */
    static String clientIdentity(HttpExchange ex) {
        if (!(ex instanceof HttpsExchange https)) {
            return null;
        }
        try {
            Certificate[] chain = https.getSSLSession().getPeerCertificates();
            if (chain.length == 0 || !(chain[0] instanceof X509Certificate leaf)) {
                return null;
            }
            return identity(leaf);
        } catch (SSLPeerUnverifiedException e) {
            return null;
        }
    }

    static String identity(X509Certificate leaf) {
        try {
            Collection<List<?>> sans = leaf.getSubjectAlternativeNames();
            String found = null;
            if (sans != null) {
                for (List<?> san : sans) {
                    if (san.size() >= 2 && san.get(0) instanceof Integer t && t == SAN_URI
                            && san.get(1) instanceof String uri && uri.startsWith("urn:eastguard:")) {
                        if (found != null) {
                            return null; // ambiguous
                        }
                        found = uri;
                    }
                }
            }
            return found;
        } catch (CertificateParsingException e) {
            return null;
        }
    }

    private Response audit(String rawQuery) {
        Map<String, String> q = new HashMap<>();
        if (rawQuery != null && !rawQuery.isEmpty()) {
            for (String part : rawQuery.split("&", -1)) {
                int eq = part.indexOf('=');
                String k = eq < 0 ? part : part.substring(0, eq);
                String v = eq < 0 ? "" : part.substring(eq + 1);
                if (!(k.equals("cursor") || k.equals("limit")) || q.put(k, v) != null) {
                    return json(400, "{\"error\":\"parameters: cursor, limit (each at most once)\"}");
                }
            }
        }
        long cursor;
        int limit;
        try {
            cursor = number(q.getOrDefault("cursor", "0"), Long.MAX_VALUE);
            limit = (int) number(q.getOrDefault("limit", "50"), ControlPlaneImpl.MAX_PAGE);
        } catch (IllegalArgumentException e) {
            return json(400, "{\"error\":\"cursor must be 0.." + Long.MAX_VALUE + ", limit 1.."
                    + ControlPlaneImpl.MAX_PAGE + "\"}");
        }
        if (limit < 1) {
            return json(400, "{\"error\":\"limit must be 1.." + ControlPlaneImpl.MAX_PAGE + "\"}");
        }
        if (!cp.ready()) {
            return json(503, "{\"error\":\"not ready\"}");
        }
        ControlPlaneImpl.AuditPage page = cp.auditPage(cursor, limit);
        StringBuilder b = new StringBuilder("{\"limit\":").append(limit).append(",\"nextCursor\":")
                .append(page.nextCursor()).append(",\"entries\":[");
        boolean first = true;
        for (Dto.AuditEntry e : page.entries()) {
            b.append(first ? "" : ",").append("{\"revision\":").append(e.revision())
                    .append(",\"at\":").append(str(Instant.ofEpochMilli(e.atMillis()).toString()))
                    .append(",\"actor\":").append(str(e.actor()))
                    .append(",\"role\":").append(str(e.role()))
                    .append(",\"operation\":").append(str(e.operation()))
                    .append(",\"requestId\":").append(str(e.requestId()))
                    .append(",\"detail\":").append(str(e.detail()))
                    .append(",\"reason\":").append(str(e.reason()))
                    .append(",\"outcome\":").append(str(e.outcome())).append('}');
            first = false;
        }
        return json(200, b.append("]}").toString());
    }

    /** Decimal digits only, no sign, at most {@code max}. */
    private static long number(String s, long max) {
        if (s.isEmpty() || s.length() > 19 || !s.chars().allMatch(c -> c >= '0' && c <= '9')) {
            throw new IllegalArgumentException("not a number");
        }
        long v = Long.parseLong(s);
        if (v > max) {
            throw new IllegalArgumentException("out of range");
        }
        return v;
    }

    private Response metrics() {
        EnforcementSnapshot s = cp.snapshot();
        ControlPlaneImpl.DraftStats d = cp.draftStats();
        StringBuilder b = new StringBuilder();
        metric(b, "eastguard_ready", cp.ready() ? 1 : 0);
        metric(b, "eastguard_enforcement_revision", s == null ? 0 : s.revision());
        metric(b, "eastguard_policy_revision", s == null ? 0 : s.policy().revision());
        metric(b, "eastguard_restrictions_active", s == null ? 0 : s.restrictions().size());
        metric(b, "eastguard_lease_reductions_active", s == null ? 0 : s.leaseReductions().size());
        metric(b, "eastguard_rmi_unauthorized_total", cp.unauthorizedCalls());
        metric(b, "eastguard_rmi_filter_rejected_total", RmiFilter.rejected());
        metric(b, "eastguard_learning_draft_version", d.version());
        metric(b, "eastguard_learning_candidates", d.candidates());
        metric(b, "eastguard_learning_dropped_total", d.dropped());
        metric(b, "eastguard_audit_http_requests_total", requests.get());
        metric(b, "eastguard_audit_http_forbidden_total", forbidden.get());
        return text(200, b.toString());
    }

    private static void metric(StringBuilder b, String name, long value) {
        b.append(name).append(' ').append(value).append('\n');
    }

    private static Response json(int status, String body) {
        return new Response(status, "application/json; charset=utf-8", body);
    }

    private static Response text(int status, String body) {
        return new Response(status, "text/plain; charset=utf-8", body);
    }

    /** A JSON string literal; also escapes {@code < > &} so the output is inert if ever shown in a page. */
    static String str(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder b = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                default -> {
                    if (c < 0x20 || c == '<' || c == '>' || c == '&' || c > 0x7e) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
                }
            }
        }
        return b.append('"').toString();
    }

    /** Settings from {@code audit.*}, or {@code null} when {@code audit.listen} is not set. */
    static Settings from(eastguard.common.Config c) {
        if (c.optional("audit.listen") == null) {
            return null;
        }
        List<String> clients = c.optional("audit.allowedClients") == null ? List.of(CONSOLE_IDENTITY)
                : java.util.Arrays.stream(c.string("audit.allowedClients").split(",")).map(String::strip)
                        .filter(x -> !x.isEmpty()).toList();
        return new Settings(c.endpoint("audit.listen"), Set.copyOf(clients));
    }
}
