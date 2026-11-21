package eastguard.handlers;

import eastguard.control.Dto;
import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Read-only connection for {@code ztp://policy/<serviceId>} (spec §7.3). {@link #connect} reads the service's
 * policy from the handler's {@link PolicySource}. Output is refused. {@link #getContent()} goes through
 * {@link PolicyContentHandler} and returns a typed {@link PolicyView}; {@link #getInputStream()} gives the same
 * data as {@code key=value} text.
 */
public final class PolicyURLConnection extends URLConnection {
    public static final String CONTENT_TYPE = "application/vnd.eastguard.policy";

    private final String serviceId;
    private final PolicySource source;
    private PolicyView policy;

    PolicyURLConnection(URL url, String serviceId, PolicySource source) {
        super(url);
        this.serviceId = Objects.requireNonNull(serviceId, "serviceId");
        this.source = Objects.requireNonNull(source, "source");
        setDoOutput(false);
        setUseCaches(false);
    }

    @Override
    public synchronized void connect() throws IOException {
        if (connected) {
            return;
        }
        Dto.PolicyView v = source.policy(serviceId);
        if (v != null && v.error() == Dto.ErrorCode.INVALID) {
            throw new FileNotFoundException("no policy for service " + serviceId + ": " + v.message());
        }
        policy = PolicyView.from(serviceId, v);
        connected = true;
    }

    /** The typed policy; connects first if needed. */
    public synchronized PolicyView policy() throws IOException {
        connect();
        return policy;
    }

    public String serviceId() {
        return serviceId;
    }

    @Override
    public void setDoOutput(boolean dooutput) {
        if (dooutput) {
            throw new IllegalArgumentException("ztp:// connections are read-only");
        }
        super.setDoOutput(false);
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return new ByteArrayInputStream(policy().toText().getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public String getContentType() {
        return CONTENT_TYPE;
    }

    @Override
    public Object getContent() throws IOException {
        return new PolicyContentHandler().getContent(this);
    }

    @Override
    @SuppressWarnings("rawtypes")
    public Object getContent(Class[] classes) throws IOException {
        return new PolicyContentHandler().getContent(this, classes);
    }
}
