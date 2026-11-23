package eastguard.test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * JDK-only test runner. Every public no-arg method named {@code test*} on a listed class runs on a fresh
 * instance. Exits non-zero if any test fails.
 *
 * <pre>
 * java -ea -cp out eastguard.test.AllTests            # all tests
 * java -ea -cp out eastguard.test.AllTests LeaseCodec # only classes whose simple name contains the filter
 * </pre>
 */
public final class AllTests {
    /** Register new test classes here. */
    private static final List<Class<?>> TEST_CLASSES = List.of(
            SmokeTest.class,
            WireTest.class,
            CodesTest.class,
            CidrTest.class,
            CryptoTest.class,
            DomainTest.class,
            LeaseCodecTest.class,
            HandshakeCodecTest.class,
            TelemetryCodecTest.class,
            NoticeCodecTest.class,
            PolicyEvaluatorTest.class,
            WorkloadIdentityTest.class,
            TlsTest.class,
            LeaseIssuerTest.class,
            TokenConfigTest.class,
            TokenServerTest.class,
            SessionIndexTest.class,
            GatewayConfigTest.class,
            GatewayTest.class,
            JournalTest.class,
            ControlPlaneImplTest.class,
            RmiTest.class,
            StateSyncTest.class,
            ControlE2ETest.class,
            TelemetryProducerTest.class,
            TelemetryVerifierTest.class,
            RiskEngineTest.class,
            DetectorControlTest.class,
            DetectorPipelineTest.class,
            CredentialsTest.class,
            LearningFreezeTest.class,
            AuditHttpTest.class,
            ZtpHandlerTest.class,
            DashboardControllerTest.class,
            QuarantineBusTest.class,
            DemoConfigTest.class,
            IsolationTest.class,
            SimulatorTest.class,
            ClientTest.class,
            DetectorComponentsTest.class,
            SnapshotCodecTest.class,
            BusMoreTest.class,
            GatewayMoreTest.class,
            ControlMoreTest.class,
            DashboardComponentsTest.class,
            CommonMoreTest.class,
            DemoComponentsTest.class);

    /** Strong reference: java.util.logging only holds loggers weakly, which would drop the level. */
    private static final Logger QUIET = Logger.getLogger("eastguard");

    private AllTests() {
    }

    public static void main(String[] args) throws Exception {
        boolean assertionsEnabled = false;
        assert assertionsEnabled = true;
        if (!assertionsEnabled) {
            System.err.println("WARNING: run with -ea so production assert statements are checked");
        }
        // Integration tests start real servers; keep their INFO logs out of the report unless asked for.
        if (!Boolean.getBoolean("eastguard.testLog")) {
            QUIET.setLevel(Level.WARNING);
        }
        String filter = args.length > 0 ? args[0] : "";
        int passed = 0;
        List<String> failures = new ArrayList<>();
        for (Class<?> cls : TEST_CLASSES) {
            if (!cls.getSimpleName().contains(filter)) {
                continue;
            }
            List<Method> methods = new ArrayList<>();
            for (Method m : cls.getDeclaredMethods()) {
                if (m.getName().startsWith("test") && m.getParameterCount() == 0
                        && Modifier.isPublic(m.getModifiers()) && !Modifier.isStatic(m.getModifiers())) {
                    methods.add(m);
                }
            }
            methods.sort(Comparator.comparing(Method::getName));
            for (Method m : methods) {
                String name = cls.getSimpleName() + "." + m.getName();
                try {
                    Object instance = cls.getDeclaredConstructor().newInstance();
                    m.invoke(instance);
                    passed++;
                } catch (ReflectiveOperationException e) {
                    // Test body or constructor threw (InvocationTargetException), or the class is not
                    // instantiable. Either way record it and keep running the remaining tests.
                    Throwable cause = e instanceof InvocationTargetException ite && ite.getCause() != null
                            ? ite.getCause() : e;
                    failures.add(name);
                    System.out.println("FAIL " + name);
                    cause.printStackTrace(System.out);
                }
            }
        }
        System.out.println();
        System.out.println(passed + " passed, " + failures.size() + " failed");
        for (String f : failures) {
            System.out.println("  failed: " + f);
        }
        if (passed + failures.size() == 0) {
            System.out.println("no tests ran" + (filter.isEmpty() ? "" : " (filter '" + filter + "' matched nothing)"));
            System.exit(1);
        }
        System.exit(failures.isEmpty() ? 0 : 1);
    }
}
