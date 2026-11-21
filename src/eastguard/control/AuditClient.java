package eastguard.control;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

/**
 * Reads the control plane's HTTPS audit export with {@link HttpsURLConnection} (spec §7.3). The connection uses
 * this client's own TLS context (its console certificate and the EastGuard trust store) and the JDK's
 * <b>normal hostname verification</b>: the server certificate must carry the URL's host (here the IP SAN
 * {@code 127.0.0.1}). No {@code HostnameVerifier} is replaced and nothing is trusted globally.
 */
public final class AuditClient {
    /** Bodies above this are refused rather than buffered. */
    public static final int MAX_BODY = 1 << 20;

    public record Response(int status, String contentType, String body) {
    }

    private final SSLContext ctx;
    private final Duration timeout;

    public AuditClient(SSLContext ctx, Duration timeout) {
        this.ctx = Objects.requireNonNull(ctx, "ctx");
        this.timeout = Objects.requireNonNull(timeout, "timeout");
    }

    public Response get(URI uri) throws IOException {
        if (!"https".equals(uri.getScheme())) {
            throw new IOException("only https is allowed");
        }
        URL url = uri.toURL();
        HttpsURLConnection c = (HttpsURLConnection) url.openConnection();
        try {
            c.setSSLSocketFactory(ctx.getSocketFactory()); // per connection; the JVM default is untouched
            c.setConnectTimeout(Math.toIntExact(timeout.toMillis()));
            c.setReadTimeout(Math.toIntExact(timeout.toMillis()));
            c.setUseCaches(false);
            c.setInstanceFollowRedirects(false);
            c.setRequestMethod("GET");
            int status = c.getResponseCode();
            InputStream in = status >= 400 ? c.getErrorStream() : c.getInputStream();
            String body = "";
            if (in != null) {
                try (in) {
                    byte[] b = in.readNBytes(MAX_BODY + 1);
                    if (b.length > MAX_BODY) {
                        throw new IOException("response body over " + MAX_BODY + " bytes");
                    }
                    body = new String(b, StandardCharsets.UTF_8);
                }
            }
            return new Response(status, c.getContentType(), body);
        } finally {
            c.disconnect();
        }
    }
}
