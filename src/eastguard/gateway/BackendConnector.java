package eastguard.gateway;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.StandardSocketOptions;
import java.nio.channels.SocketChannel;

/**
 * Starts the non-blocking connection to the gateway's fixed backend (spec §4.2 step 4). An adapter (spec §8) so
 * tests can stand in for a slow network: on loopback a real connect completes or is refused at once.
 *
 * <p>Called on the selector thread; must not block. The returned channel is non-blocking and either connected,
 * connecting, or (for test doubles) about to start connecting. The gateway waits for {@code OP_CONNECT} and then
 * calls {@link SocketChannel#finishConnect()}; it owns and closes the channel.
 */
@FunctionalInterface
public interface BackendConnector {
    SocketChannel open(InetSocketAddress backend) throws IOException;

    BackendConnector DIRECT = backend -> {
        SocketChannel ch = SocketChannel.open();
        try {
            ch.configureBlocking(false);
            ch.setOption(StandardSocketOptions.TCP_NODELAY, true);
            ch.connect(backend); // numeric address: no DNS lookup
            return ch;
        } catch (IOException | RuntimeException e) {
            ch.close();
            throw e;
        }
    };
}
