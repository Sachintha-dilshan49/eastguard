package eastguard.control;

import eastguard.common.IpAddress;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.rmi.NoSuchObjectException;
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;

/**
 * Exposes a {@link ControlPlaneImpl} over RMI (spec §7.1): a registry on a fixed port and the remote object on a
 * second fixed port, both bound to one numeric address, both TLS 1.3 with client authentication through
 * {@link TlsRmiServerSocketFactory}. Call arguments pass the {@link RmiFilter#arguments()} filter. Stubs advertise
 * the bind address and carry {@link TlsRmiClientSocketFactory}.
 *
 * <p>A maintenance thread commits quarantine expiry ({@link ControlPlaneImpl#expireDue}) once a second and
 * reloads the credential file when it changes (rotation and revocation without a restart).
 */
public final class ControlServer implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(ControlServer.class.getName());

    private final ControlPlaneImpl impl;
    private final Registry registry;
    private final ScheduledExecutorService maintenance;
    private final Path credentialsFile;
    private FileTime credentialsStamp;

    private ControlServer(ControlPlaneImpl impl, Registry registry, Path credentialsFile) {
        this.impl = impl;
        this.registry = registry;
        this.credentialsFile = credentialsFile;
        this.maintenance = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "control-maintenance");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * @param bindHost        numeric address for both listeners, also advertised in stubs
     * @param credentialsFile reloaded when its modification time changes; {@code null} for fixed credentials
     */
    public static ControlServer start(ControlPlaneImpl impl, SSLContext ctx, String bindHost, int registryPort,
            int objectPort, Path credentialsFile) throws IOException {
        Objects.requireNonNull(impl, "impl");
        RmiSupport.configureJvm(bindHost);
        InetAddress bind = IpAddress.parse(bindHost).toInetAddress();
        TlsRmiClientSocketFactory csf = new TlsRmiClientSocketFactory();
        TlsRmiServerSocketFactory ssf = new TlsRmiServerSocketFactory(ctx, bind);
        Registry registry = LocateRegistry.createRegistry(registryPort, csf, ssf);
        try {
            Remote stub = UnicastRemoteObject.exportObject(impl, objectPort, csf, ssf, RmiFilter.arguments());
            registry.rebind(ControlPlane.NAME, stub);
        } catch (IOException | RuntimeException e) {
            unexport(impl);
            unexport(registry);
            throw e;
        }
        ControlServer server = new ControlServer(impl, registry, credentialsFile);
        server.credentialsStamp = stamp(credentialsFile);
        server.maintenance.scheduleWithFixedDelay(server::maintain, 1, 1, TimeUnit.SECONDS);
        LOG.info(() -> "control plane on " + bindHost + ": registry " + registryPort + ", object " + objectPort
                + (impl.ready() ? ", revision " + impl.snapshot().revision() : ", NOT bootstrapped"));
        return server;
    }

    private void maintain() {
        try {
            int expired = impl.expireDue();
            if (expired > 0) {
                LOG.info(() -> "committed expiry of " + expired + " quarantine selector(s)");
            }
            FileTime now = stamp(credentialsFile);
            if (now != null && !now.equals(credentialsStamp)) {
                impl.setCredentials(Credentials.load(credentialsFile));
                credentialsStamp = now;
                LOG.info("API credentials reloaded");
            }
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, "control-plane maintenance failed", e);
        }
    }

    private static FileTime stamp(Path f) {
        try {
            return f == null ? null : Files.getLastModifiedTime(f);
        } catch (IOException e) {
            return null;
        }
    }

    public ControlPlaneImpl impl() {
        return impl;
    }

    /** Stops serving: unexports the object and the registry (closing their listeners) and stops maintenance. */
    @Override
    public void close() {
        maintenance.shutdownNow();
        unexport(impl);
        unexport(registry);
    }

    private static void unexport(Remote r) {
        try {
            UnicastRemoteObject.unexportObject(r, true);
        } catch (NoSuchObjectException ignored) {
            // not exported
        }
    }
}
