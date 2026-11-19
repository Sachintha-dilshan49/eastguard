package eastguard.client;

import eastguard.common.ReplyStatus;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.time.Duration;
import java.util.Objects;
import javax.net.ssl.SSLSocket;

/**
 * Result of presenting a lease to a gateway (spec §4.2 step 2). The application streams exist only after
 * {@link ReplyStatus#SUCCESS}; for any other status the connection is already closed and {@link #input()} /
 * {@link #output()} throw. No automatic retry, and nothing was sent after the preamble.
 */
public final class GatewaySession implements Closeable {
    private final ReplyStatus status;
    private final SSLSocket socket;

    GatewaySession(ReplyStatus status, SSLSocket socket) {
        this.status = Objects.requireNonNull(status, "status");
        if ((status == ReplyStatus.SUCCESS) != (socket != null)) {
            throw new IllegalArgumentException("a socket exists exactly when admitted");
        }
        this.socket = socket;
    }

    public ReplyStatus status() {
        return status;
    }

    public boolean allowed() {
        return status == ReplyStatus.SUCCESS;
    }

    /** Bytes from the protected backend. */
    public InputStream input() throws IOException {
        return requireAllowed().getInputStream();
    }

    /** Bytes to the protected backend. */
    public OutputStream output() throws IOException {
        return requireAllowed().getOutputStream();
    }

    /** Ends our direction cleanly (TLS 1.3 {@code close_notify}); the gateway half-closes the backend. */
    public void shutdownOutput() throws IOException {
        requireAllowed().shutdownOutput();
    }

    /** Read timeout for {@link #input()}; zero means none (the default after admission). */
    public void setReadTimeout(Duration timeout) throws IOException {
        requireAllowed().setSoTimeout(Math.toIntExact(timeout.toMillis()));
    }

    private SSLSocket requireAllowed() {
        if (socket == null) {
            throw new IllegalStateException("gateway did not admit the connection: " + status);
        }
        return socket;
    }

    @Override
    public void close() throws IOException {
        if (socket != null) {
            socket.close();
        }
    }
}
