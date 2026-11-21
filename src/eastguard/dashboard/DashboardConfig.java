package eastguard.dashboard;

import eastguard.common.Config;
import eastguard.common.SecretSource;
import eastguard.control.ControlClient;
import eastguard.tokensvc.TlsContextFactory;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Dashboard configuration, see {@code config/dashboard.properties.example}.
 *
 * @param profile {@link Profile#LIVE}: the control plane over RMI; {@link Profile#DEMO}: labeled fixtures only,
 *                no network at all
 * @param control the console's RMI client settings and API credential (VIEWER, OPERATOR or ADMIN principal)
 * @param tls     the console certificate ({@code keys/console.p12}) and the EastGuard trust store
 */
public record DashboardConfig(Profile profile, DashboardController.Timing timing, ControlClient.Settings control,
        TlsContextFactory.Material tls) {
    public enum Profile { LIVE, DEMO }

    public DashboardConfig {
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(timing, "timing");
        if (profile == Profile.LIVE) {
            Objects.requireNonNull(control, "control");
            Objects.requireNonNull(tls, "tls");
        }
    }

    public static DashboardConfig load(Path file) {
        Config c = Config.load(file);
        Profile profile = c.enumValue("dashboard.profile", Profile.class, Profile.LIVE);
        DashboardController.Timing timing = new DashboardController.Timing(
                c.millis("dashboard.pollMillis", 2_000, 200, 60_000),
                c.millis("dashboard.staleAfterMillis", 6_000, 500, 300_000));
        ControlClient.Settings control = null;
        TlsContextFactory.Material tls = null;
        if (profile == Profile.LIVE) {
            control = ControlClient.Settings.from(c);
            tls = new TlsContextFactory.Material(c.path("tls.keyStore"), c.path("tls.trustStore"),
                    new SecretSource(c.string("tls.passwordEnv", "EASTGUARD_STORE_PASS"),
                            c.path("tls.passwordFile", "keys/store.pass")));
        }
        DashboardConfig cfg = new DashboardConfig(profile, timing, control, tls);
        if (profile == Profile.LIVE) {
            c.requireNoUnknownKeys();
        }
        return cfg;
    }
}
