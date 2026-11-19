package eastguard.common;

/** Validation for wire identifiers: 1..64 ASCII bytes matching {@code [a-z0-9][a-z0-9._-]{0,63}} (spec §5). */
public final class Ids {
    public static final int MAX_LENGTH = 64;

    private Ids() {
    }

    public static boolean isValid(String s) {
        if (s == null) {
            return false;
        }
        int n = s.length();
        if (n < 1 || n > MAX_LENGTH) {
            return false;
        }
        for (int i = 0; i < n; i++) {
            if (!isIdChar(s.charAt(i), i == 0)) {
                return false;
            }
        }
        return true;
    }

    static boolean isIdChar(int c, boolean first) {
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
            return true;
        }
        return !first && (c == '.' || c == '_' || c == '-');
    }

    /** Returns {@code s} or throws {@link IllegalArgumentException}; for constructing trusted values. */
    public static String require(String s, String field) {
        if (!isValid(s)) {
            throw new IllegalArgumentException("invalid id: " + field);
        }
        return s;
    }

    /** Like {@link #require} but also accepts {@code null} (an absent {@code optId}). */
    public static String requireOptional(String s, String field) {
        return s == null ? null : require(s, field);
    }
}
