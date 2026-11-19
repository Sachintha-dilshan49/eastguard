package eastguard.common;

/**
 * Untrusted wire input was rejected: truncated, oversized, trailing bytes, unknown version or enum value,
 * bad signature/MAC, or a field outside its allowed range.
 *
 * <p>Messages describe the failure only; they never include token, key, or payload bytes.
 */
public final class CodecException extends Exception {
    private static final long serialVersionUID = 1L;

    public CodecException(String message) {
        super(message);
    }
}
