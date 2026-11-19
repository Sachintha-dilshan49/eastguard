package eastguard.demos;

import eastguard.common.Endpoint;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Protected backend fixture for demos and tests: a plain TCP echo server on a fixed loopback port (spec §2:
 * {@code 127.0.0.1:7002}, private to the gateway's isolation boundary). Tests bind port 0.
 *
 * <p>Blocking sockets, one virtual thread per connection, a bound on concurrent connections (excess connections
 * are closed at once). Each connection echoes until the peer half-closes, then half-closes its own output, which
 * lets a gateway propagate a clean end of stream in both directions.
 *
 * <pre>
 * java -cp out eastguard.demos.EchoBackend [127.0.0.1:7002]
 * </pre>
 */
public final class EchoBackend implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(EchoBackend.class.getName());
    public static final Endpoint DEFAULT_LISTEN = Endpoint.parse("127.0.0.1:7002");

    private final InetSocketAddress bind;
    private final Semaphore permits;
    private final ExecutorService workers =
            Executors.newThreadPerTaskExecutor(Thread.ofVirtual().name("echo-backend-", 0).factory());
    private final AtomicLong accepted = new AtomicLong();
    private final AtomicLong bytesEchoed = new AtomicLong();
    private final AtomicLong rejected = new AtomicLong();
    private volatile ServerSocket server;

    public EchoBackend(InetSocketAddress bind, int maxConnections) {
        this.bind = Objects.requireNonNull(bind, "bind");
        if (maxConnections < 1) {
            throw new IllegalArgumentException("maxConnections must be positive");
        }
        this.permits = new Semaphore(maxConnections);
    }

    public synchronized EchoBackend start() throws IOException {
        if (server != null) {
            throw new IllegalStateException("already started");
        }
        ServerSocket ss = new ServerSocket();
        try {
            ss.setReuseAddress(false);
            ss.bind(bind, 1_024);
        } catch (IOException e) {
            ss.close();
            throw new IOException("echo backend cannot bind " + bind + ": " + e.getMessage(), e);
        }
        server = ss;
        Thread.ofPlatform().daemon().name("echo-backend-accept").start(this::acceptLoop);
        return this;
    }

    public int port() {
        return server.getLocalPort();
    }

    public long accepted() {
        return accepted.get();
    }

    public long bytesEchoed() {
        return bytesEchoed.get();
    }

    public long rejected() {
        return rejected.get();
    }

    private void acceptLoop() {
        ServerSocket ss = server;
        while (!ss.isClosed()) {
            Socket s;
            try {
                s = ss.accept();
            } catch (IOException e) {
                if (!ss.isClosed()) {
                    LOG.log(Level.WARNING, "echo backend accept failed", e);
                }
                continue;
            }
            accepted.incrementAndGet();
            if (!permits.tryAcquire()) {
                rejected.incrementAndGet();
                closeQuietly(s);
                continue;
            }
            try {
                workers.execute(() -> echo(s));
            } catch (RejectedExecutionException e) {
                permits.release();
                closeQuietly(s);
            }
        }
    }

    private void echo(Socket s) {
        try (s) {
            s.setTcpNoDelay(true);
            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();
            byte[] buf = new byte[16 * 1024];
            int n;
            while ((n = in.read(buf)) >= 0) {
                out.write(buf, 0, n);
                bytesEchoed.addAndGet(n);
            }
            s.shutdownOutput();
        } catch (IOException e) {
            LOG.fine(() -> "echo connection ended: " + e);
        } finally {
            permits.release();
        }
    }

    @Override
    public void close() {
        ServerSocket ss = server;
        if (ss != null) {
            closeQuietly(ss);
        }
        workers.shutdownNow();
        try {
            workers.awaitTermination(2, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void closeQuietly(AutoCloseable c) {
        try {
            c.close();
        } catch (Exception ignored) {
            // best effort
        }
    }

    public static void main(String[] args) throws Exception {
        Endpoint listen = args.length > 0 ? Endpoint.parse(args[0]) : DEFAULT_LISTEN;
        EchoBackend backend = new EchoBackend(listen.toSocketAddress(), 4_096).start();
        Runtime.getRuntime().addShutdownHook(new Thread(backend::close, "echo-backend-shutdown"));
        System.out.println("echo backend listening on " + listen);
        Thread.currentThread().join();
    }
}
