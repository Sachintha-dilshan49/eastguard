package eastguard.common;

/** Lifecycle of an alert's proposed action. */
public enum AlertStatus {
    /** Alert only; no action proposed. */
    OPEN,
    /** Action proposed to the control plane, not yet committed. */
    PROPOSED,
    /** Control plane committed the action. */
    COMMITTED,
    /** Control plane rejected the proposal or an operator dismissed the alert. */
    DISMISSED
}
