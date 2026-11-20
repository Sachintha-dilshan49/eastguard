package eastguard.control;

import eastguard.control.Dto.ActionProposal;
import eastguard.control.Dto.DashboardRequest;
import eastguard.control.Dto.DashboardView;
import eastguard.control.Dto.FreezeRequest;
import eastguard.control.Dto.MutationResult;
import eastguard.control.Dto.ObservationBatch;
import eastguard.control.Dto.PolicyRequest;
import eastguard.control.Dto.PolicyView;
import eastguard.control.Dto.QuarantineRequest;
import eastguard.control.Dto.ReleaseRequest;
import eastguard.control.Dto.ReplacePolicyRequest;
import eastguard.control.Dto.SetLeaseDefaultsRequest;
import eastguard.control.Dto.SetModeRequest;
import eastguard.control.Dto.SyncRequest;
import eastguard.control.Dto.SyncResponse;
import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * Control-plane RMI API (spec §7.1). Every request carries the caller's API credential; every call is
 * authenticated and authorized by role. Failures are typed results ({@link Dto.ErrorCode}), never application
 * exceptions; {@link RemoteException} only reports transport problems.
 *
 * <pre>
 * sync                                 GATEWAY, ISSUER
 * getDashboard, getPolicy              VIEWER, OPERATOR, ADMIN
 * quarantine, release                  OPERATOR, ADMIN
 * replacePolicy, setMode,
 * setLeaseDefaults, freezeBaseline     ADMIN
 * recordObservations, proposeAction    DETECTOR
 * </pre>
 */
public interface ControlPlane extends Remote {
    /** Registry name of the exported control plane. */
    String NAME = "eastguard-control";

    SyncResponse sync(SyncRequest request) throws RemoteException;

    DashboardView getDashboard(DashboardRequest request) throws RemoteException;

    PolicyView getPolicy(PolicyRequest request) throws RemoteException;

    MutationResult quarantine(QuarantineRequest request) throws RemoteException;

    MutationResult release(ReleaseRequest request) throws RemoteException;

    MutationResult replacePolicy(ReplacePolicyRequest request) throws RemoteException;

    MutationResult setMode(SetModeRequest request) throws RemoteException;

    MutationResult setLeaseDefaults(SetLeaseDefaultsRequest request) throws RemoteException;

    /** Learning observations from the detector. Implemented in Task 7. */
    MutationResult recordObservations(ObservationBatch request) throws RemoteException;

    /** Detector quarantine proposal. Implemented in Task 7. */
    MutationResult proposeAction(ActionProposal request) throws RemoteException;

    /** Commit a reviewed learning draft as the allow-list and switch to ENFORCE. Implemented in Task 9. */
    MutationResult freezeBaseline(FreezeRequest request) throws RemoteException;
}
