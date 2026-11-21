package eastguard.handlers;

import java.io.IOException;
import java.net.ContentHandler;
import java.net.URLConnection;

/**
 * {@link ContentHandler} for {@link PolicyURLConnection#CONTENT_TYPE} (spec §7.3): returns the typed
 * {@link PolicyView} that the connection read from its configured control-plane client. It is used directly by
 * {@link PolicyURLConnection}, never installed as a JVM-wide content handler factory.
 */
public final class PolicyContentHandler extends ContentHandler {
    @Override
    public PolicyView getContent(URLConnection c) throws IOException {
        if (!(c instanceof PolicyURLConnection p)) {
            throw new IOException("not a ztp:// policy connection");
        }
        return p.policy();
    }

    /** The policy if {@link PolicyView} (or {@code Object}) is among {@code classes}, else {@code null}. */
    @Override
    @SuppressWarnings("rawtypes")
    public Object getContent(URLConnection c, Class[] classes) throws IOException {
        for (Class<?> k : classes) {
            if (k == PolicyView.class || k == Object.class) {
                return getContent(c);
            }
        }
        return null;
    }
}
