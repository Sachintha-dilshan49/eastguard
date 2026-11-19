package eastguard.common;

/** Policy mode (spec §3.2). Not on the wire. */
public enum PolicyMode {
    /** Admit only explicitly approved edges. */
    ENFORCE,
    /** Also admit authenticated traffic inside the explicit pilot scope and record it as candidate edges. */
    LEARN
}
