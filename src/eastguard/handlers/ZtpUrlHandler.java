package eastguard.handlers;

import eastguard.common.Ids;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.Objects;

/**
 * Explicit {@link URLStreamHandler} for {@code ztp://policy/<serviceId>} (spec §7.3). It is never registered
 * globally; callers pass it in:
 *
 * <pre>
 * URL u = URL.of(URI.create("ztp://policy/app-02"), new ZtpUrlHandler(controlClient::getPolicy));
 * PolicyView p = (PolicyView) u.getContent();
 * </pre>
 *
 * The only accepted form is the fixed authority {@code policy} (no user info, no port, case-sensitive) and a
 * path of exactly one valid service ID, with no query and no fragment. The URL therefore cannot choose an RMI
 * host, a filesystem path or any other endpoint: reads always go to the {@link PolicySource} this handler was
 * built with. A bad URL is rejected when it is constructed ({@link MalformedURLException} from {@code URL.of})
 * and again when opened.
 */
public final class ZtpUrlHandler extends URLStreamHandler {
    public static final String PROTOCOL = "ztp";
    public static final String AUTHORITY = "policy";

    private final PolicySource source;

    public ZtpUrlHandler(PolicySource source) {
        this.source = Objects.requireNonNull(source, "source");
    }

    @Override
    protected void parseURL(URL u, String spec, int start, int limit) {
        super.parseURL(u, spec, start, limit);
        try {
            serviceId(u); // the URL constructor turns this into a MalformedURLException
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    @Override
    protected URLConnection openConnection(URL u) throws IOException {
        return new PolicyURLConnection(u, serviceId(u), source);
    }

    @Override
    protected URLConnection openConnection(URL u, Proxy p) throws IOException {
        throw new IOException("ztp:// URLs take no proxy");
    }

    /** The service ID of a valid {@code ztp://policy/<serviceId>} URL. */
    public static String serviceId(URL u) throws MalformedURLException {
        if (!PROTOCOL.equals(u.getProtocol())) {
            throw new MalformedURLException("not a ztp URL");
        }
        if (!AUTHORITY.equals(u.getAuthority()) || !AUTHORITY.equals(u.getHost()) || u.getPort() != -1
                || u.getUserInfo() != null) {
            throw new MalformedURLException("ztp URLs must use the fixed authority '" + AUTHORITY + "'");
        }
        if (u.getQuery() != null || u.getRef() != null) {
            throw new MalformedURLException("ztp URLs take no query or fragment");
        }
        String path = u.getPath();
        if (path == null || !path.startsWith("/")) {
            throw new MalformedURLException("ztp URLs need a service ID: ztp://policy/<serviceId>");
        }
        String id = path.substring(1);
        if (!Ids.isValid(id)) { // also excludes '/', '%', '..' and empty IDs
            throw new MalformedURLException("not a valid service ID");
        }
        return id;
    }
}
