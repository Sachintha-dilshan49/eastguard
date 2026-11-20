package eastguard.control;

import eastguard.tokensvc.TlsContextFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.rmi.server.RMIServerSocketFactory;
import java.util.Objects;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

/**
 * RMI server sockets for the registry and the control-plane object: TLS 1.3, client certificate required
 * (PKIX against the EastGuard trust store), bound to one configured address. Server side only; never serialized.
 */
final class TlsRmiServerSocketFactory implements RMIServerSocketFactory {
    private final SSLContext ctx;
    private final InetAddress bind;

    TlsRmiServerSocketFactory(SSLContext ctx, InetAddress bind) {
        this.ctx = Objects.requireNonNull(ctx, "ctx");
        this.bind = Objects.requireNonNull(bind, "bind");
    }

    @Override
    public ServerSocket createServerSocket(int port) throws IOException {
        SSLServerSocket s = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket();
        try {
            s.setSSLParameters(TlsContextFactory.serverParameters(ctx)); // TLS 1.3, need client auth
            s.setReuseAddress(true);
            s.bind(new InetSocketAddress(bind, port), 64);
            return s;
        } catch (IOException | RuntimeException e) {
            s.close();
            throw e;
        }
    }
}
