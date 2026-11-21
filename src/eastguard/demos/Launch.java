package eastguard.demos;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * Process wrapper used by {@code scripts\run-demo.ps1}. It runs one EastGuard component's {@code main} in this JVM
 * and ends the JVM through {@link System#exit}, so the component's shutdown hooks run (journal closed, sockets
 * closed, telemetry flushed), when either:
 * <ul>
 *   <li>the stop file appears (the launcher's clean-stop signal on Ctrl+C or on a failed start), or</li>
 *   <li>the watched launcher process ends without creating it (its window was closed): no orphaned JVMs.</li>
 * </ul>
 * Windows has no portable way to send a console interrupt to one child process; a file both sides can see is
 * the simplest reliable signal. The launcher passes its own PID because the JVM's direct parent may be a
 * {@code java.exe} shim (Oracle's {@code javapath}) rather than the launcher.
 *
 * <pre>
 * java -cp out eastguard.demos.Launch --stop-file logs/x.stop --watch-pid 1234 eastguard.gateway.NioGateway --config ...
 * </pre>
 */
public final class Launch {
    private static final long POLL_MILLIS = 200;

    private Launch() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 5 || !"--stop-file".equals(args[0]) || !"--watch-pid".equals(args[2])
                || !args[4].startsWith("eastguard.")) {
            System.err.println("usage: java -cp out eastguard.demos.Launch --stop-file <path> --watch-pid <pid>"
                    + " eastguard.<Main> [args...]");
            System.exit(2);
        }
        Path stop = Path.of(args[1]);
        ProcessHandle launcher = ProcessHandle.of(Long.parseLong(args[3])).orElse(null);
        if (launcher == null) {
            System.err.println("launch: launcher process " + args[3] + " is not running");
            System.exit(2);
        }
        String target = args[4];
        String[] rest = Arrays.copyOfRange(args, 5, args.length);
        Thread.ofPlatform().daemon().name("launch-watch").start(() -> watch(stop, launcher));

        Method main = Class.forName(target).getMethod("main", String[].class);
        try {
            main.invoke(null, (Object) rest);
        } catch (InvocationTargetException e) {
            // A component that fails to start must not linger half-started: report and exit non-zero.
            System.err.println("launch: " + target + " failed to start");
            e.getCause().printStackTrace();
            System.exit(1);
        }
    }

    private static void watch(Path stop, ProcessHandle launcher) {
        while (true) {
            try {
                Thread.sleep(POLL_MILLIS);
            } catch (InterruptedException e) {
                return;
            }
            if (Files.exists(stop)) {
                System.err.println("launch: stop file " + stop + " found, shutting down");
                System.exit(0);
            }
            if (!launcher.isAlive()) {
                System.err.println("launch: launcher process " + launcher.pid() + " ended, shutting down");
                System.exit(0);
            }
        }
    }
}
