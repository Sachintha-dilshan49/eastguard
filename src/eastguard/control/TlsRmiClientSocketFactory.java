package eastguard.control;

import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.net.Socket;
import java.rmi.server.RMIClientSocketFactory;

/**
 * RMI client socket factory for the registry and the control-plane object (spec §7.1). Unlike
 * {@code javax.rmi.ssl.SslRMIClientSocketFactory}, it never uses the JVM default {@code SSLContext}: it uses the
 * context installed with {@link RmiSupport#installClient}, TLS 1.3 with this process's EastGuard certificate,
 * server certificate verification against the target IP, and connect/read deadlines. It refuses endpoints
 * that are not on the installed allowlist, including an unexpected host or port advertised in a stub.
 *
 * <p>Stateless and serializable, because the server embeds it in the stubs it hands out. All instances are
 * equal so RMI can pool connections.
 */
public final class TlsRmiClientSocketFactory implements RMIClientSocketFactory, Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return RmiSupport.clientSocket(host, port);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof TlsRmiClientSocketFactory;
    }

    @Override
    public int hashCode() {
        return TlsRmiClientSocketFactory.class.hashCode();
    }
}
