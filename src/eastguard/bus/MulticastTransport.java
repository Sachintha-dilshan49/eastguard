package eastguard.bus;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.StandardSocketOptions;
import java.util.Objects;

/**
 * Real IP multicast for control notices (spec §9.1): {@link MulticastSocket}, an explicit interface for both
 * sending and joining, {@code joinGroup(SocketAddress, NetworkInterface)}, and the configured TTL (1). Loopback
 * delivery is enabled so receivers on the sending host (the single-machine demo) get the notices too.
 *
 * <p>Each {@link #join()} opens its own socket bound to the wildcard address and the group port, with address
 * reuse, so several receivers on one host can share the port.
 */
public final class MulticastTransport implements NoticeTransport, AutoCloseable {
    private final MulticastSettings settings;
    private final NetworkInterface nif;
    private final InetSocketAddress target;
    private final Object sendLock = new Object();
    private MulticastSocket sender; // guarded by sendLock; opened on first send

    public MulticastTransport(MulticastSettings settings) throws IOException {
        this.settings = Objects.requireNonNull(settings, "settings");
        this.nif = settings.resolveInterface();
        InetAddress group = settings.group().toInetAddress();
        this.target = new InetSocketAddress(group, settings.port());
    }

    public NetworkInterface networkInterface() {
        return nif;
    }

    @Override
    public void send(byte[] datagram) throws IOException {
        if (datagram.length > MAX_DATAGRAM) {
            throw new IOException("datagram over " + MAX_DATAGRAM + " bytes");
        }
        synchronized (sendLock) {
            if (sender == null) {
                MulticastSocket s = new MulticastSocket(0);
                try {
                    s.setNetworkInterface(nif);
                    s.setTimeToLive(settings.ttl());
                    s.setOption(StandardSocketOptions.IP_MULTICAST_LOOP, true);
                } catch (IOException | RuntimeException e) {
                    s.close();
                    throw e;
                }
                sender = s;
            }
            sender.send(new DatagramPacket(datagram, datagram.length, target));
        }
    }

    @Override
    public Receiver join() throws IOException {
        MulticastSocket s = new MulticastSocket(settings.port()); // SO_REUSEADDR is set before the bind
        try {
            s.joinGroup(new InetSocketAddress(target.getAddress(), 0), nif);
        } catch (IOException | RuntimeException e) {
            s.close();
            throw e;
        }
        return new SocketReceiver(s);
    }

    @Override
    public void close() {
        synchronized (sendLock) {
            if (sender != null) {
                sender.close();
                sender = null;
            }
        }
    }

    private static final class SocketReceiver implements Receiver {
        private final MulticastSocket socket;
        private final byte[] scratch = new byte[MAX_DATAGRAM + 1]; // one extra byte reveals oversize datagrams

        SocketReceiver(MulticastSocket socket) {
            this.socket = socket;
        }

        @Override
        public int receive(byte[] buf, int timeoutMillis) throws IOException {
            if (socket.isClosed()) {
                return -1;
            }
            DatagramPacket p = new DatagramPacket(scratch, scratch.length);
            try {
                socket.setSoTimeout(Math.max(1, timeoutMillis));
                socket.receive(p);
            } catch (SocketTimeoutException e) {
                return 0;
            } catch (SocketException e) {
                if (socket.isClosed()) {
                    return -1;
                }
                throw e;
            }
            int n = p.getLength();
            System.arraycopy(scratch, 0, buf, 0, Math.min(n, buf.length));
            return n; // MAX_DATAGRAM + 1 means "oversize"; the notice decoder rejects it
        }

        @Override
        public void close() {
            socket.close(); // leaves the group
        }
    }
}
