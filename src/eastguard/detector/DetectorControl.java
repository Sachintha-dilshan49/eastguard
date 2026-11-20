package eastguard.detector;

import eastguard.common.Selector;
import eastguard.control.ControlClient;
import eastguard.control.ControlPlane;
import eastguard.control.Dto;
import eastguard.control.Dto.MutationResult;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * What the detector may ask of the control plane (spec §7.1, role DETECTOR): record learning observations and
 * propose an action. Nothing else: no release, no signing, no broadcast. An adapter so tests and demos can call an
 * in-process control plane instead of RMI.
 */
public interface DetectorControl {
    MutationResult recordObservations(String requestId, List<Dto.Observation> observations) throws IOException;

    MutationResult proposeAction(String requestId, Dto.ActionType action, List<Selector> selectors, Duration ttl,
            int score, List<String> signals, List<String> evidence) throws IOException;

    /** Over secured RMI. */
    static DetectorControl of(ControlClient client) {
        Objects.requireNonNull(client, "client");
        return new DetectorControl() {
            @Override
            public MutationResult recordObservations(String id, List<Dto.Observation> obs) throws IOException {
                return client.recordObservations(id, obs);
            }

            @Override
            public MutationResult proposeAction(String id, Dto.ActionType a, List<Selector> sel, Duration ttl, int score,
                    List<String> signals, List<String> evidence) throws IOException {
                return client.proposeAction(id, a, sel, ttl, score, signals, evidence);
            }
        };
    }

    /** Direct calls on a control plane (same JVM), with this detector's credential. */
    static DetectorControl direct(ControlPlane cp, Dto.Credential credential) {
        Objects.requireNonNull(cp, "cp");
        Objects.requireNonNull(credential, "credential");
        return new DetectorControl() {
            @Override
            public MutationResult recordObservations(String id, List<Dto.Observation> obs) throws IOException {
                return cp.recordObservations(new Dto.ObservationBatch(credential, id, obs));
            }

            @Override
            public MutationResult proposeAction(String id, Dto.ActionType a, List<Selector> sel, Duration ttl, int score,
                    List<String> signals, List<String> evidence) throws IOException {
                return cp.proposeAction(new Dto.ActionProposal(credential, id, a, sel, ttl.toMillis(), score, signals,
                        evidence));
            }
        };
    }
}
