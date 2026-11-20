package eastguard.common;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;

/**
 * Validated bootstrap configuration (spec §9.1). Rejects duplicate keys, missing required keys, out-of-range
 * values, and — via {@link #requireNoUnknownKeys()} — keys nobody read, so a typo fails at startup instead of
 * silently falling back to a default. Error messages name the key and file, never the value: configuration
 * should not hold secrets, but a misplaced one must not end up in a log.
 */
public final class Config {
    private final Properties props;
    private final String source;
    private final Set<String> used = new HashSet<>();

    private Config(Properties props, String source) {
        this.props = props;
        this.source = source;
    }

    public static Config load(Path file) {
        Properties p = new Properties() {
            private static final long serialVersionUID = 1L;

            @Override
            public synchronized Object put(Object key, Object value) {
                if (containsKey(key)) {
                    throw new IllegalArgumentException("duplicate config key '" + key + "' in " + file);
                }
                return super.put(key, value);
            }
        };
        try (Reader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            p.load(r);
        } catch (IOException e) {
            throw new IllegalArgumentException("cannot read config " + file + ": " + e.getMessage(), e);
        }
        return new Config(p, file.toString());
    }

    /** Wraps a copy of {@code p}; {@code source} names it in error messages. */
    public static Config of(Properties p, String source) {
        Properties copy = new Properties();
        copy.putAll(p);
        return new Config(copy, Objects.requireNonNull(source, "source"));
    }

    public String source() {
        return source;
    }

    private IllegalArgumentException invalid(String key, String why) {
        return new IllegalArgumentException("config " + source + ": " + key + " " + why);
    }

    /** Trimmed value, or {@code null} when absent or blank. Marks the key as known. */
    public String optional(String key) {
        used.add(key);
        String v = props.getProperty(key);
        if (v == null) {
            return null;
        }
        v = v.strip();
        return v.isEmpty() ? null : v;
    }

    public String string(String key) {
        String v = optional(key);
        if (v == null) {
            throw invalid(key, "is required");
        }
        return v;
    }

    public String string(String key, String defaultValue) {
        String v = optional(key);
        return v == null ? defaultValue : v;
    }

    public String id(String key) {
        String v = string(key);
        if (!Ids.isValid(v)) {
            throw invalid(key, "must match [a-z0-9][a-z0-9._-]{0,63}");
        }
        return v;
    }

    /** Comma-separated IDs; absent or blank means empty. Duplicates are rejected. */
    public List<String> idList(String key) {
        String v = optional(key);
        List<String> out = new ArrayList<>();
        if (v == null) {
            return out;
        }
        Set<String> seen = new HashSet<>();
        for (String part : v.split(",", -1)) {
            String id = part.strip();
            if (!Ids.isValid(id)) {
                throw invalid(key, "has an invalid id in its list");
            }
            if (!seen.add(id)) {
                throw invalid(key, "lists '" + id + "' twice");
            }
            out.add(id);
        }
        return out;
    }

    public long longIn(String key, long defaultValue, long min, long max) {
        String v = optional(key);
        if (v == null) {
            return defaultValue;
        }
        long n;
        try {
            n = Long.parseLong(v);
        } catch (NumberFormatException e) {
            throw invalid(key, "must be an integer");
        }
        if (n < min || n > max) {
            throw invalid(key, "must be in [" + min + ", " + max + "]");
        }
        return n;
    }

    public int intIn(String key, int defaultValue, int min, int max) {
        return (int) longIn(key, defaultValue, min, max);
    }

    public Duration millis(String key, long defaultMillis, long minMillis, long maxMillis) {
        return Duration.ofMillis(longIn(key, defaultMillis, minMillis, maxMillis));
    }

    public boolean bool(String key, boolean defaultValue) {
        String v = optional(key);
        if (v == null) {
            return defaultValue;
        }
        return switch (v) {
            case "true" -> true;
            case "false" -> false;
            default -> throw invalid(key, "must be true or false");
        };
    }

    public <E extends Enum<E>> E enumValue(String key, Class<E> type, E defaultValue) {
        String v = optional(key);
        if (v == null) {
            return defaultValue;
        }
        try {
            return Enum.valueOf(type, v);
        } catch (IllegalArgumentException e) {
            throw invalid(key, "must be one of " + java.util.Arrays.toString(type.getEnumConstants()));
        }
    }

    /** Numeric {@code ip:port} (no host names, so no DNS). */
    public Endpoint endpoint(String key) {
        String v = string(key);
        try {
            return Endpoint.parse(v);
        } catch (IllegalArgumentException e) {
            throw invalid(key, "must be a numeric ip:port");
        }
    }

    public Path path(String key) {
        return Path.of(string(key));
    }

    public Path path(String key, String defaultValue) {
        return Path.of(string(key, defaultValue));
    }

    public Cidr cidr(String key) {
        String v = optional(key);
        if (v == null) {
            return null;
        }
        try {
            return Cidr.parse(v);
        } catch (IllegalArgumentException e) {
            throw invalid(key, "must be a CIDR such as 10.0.0.0/24");
        }
    }

    /** Comma-separated CIDRs; absent or blank means empty. */
    public List<Cidr> cidrList(String key) {
        String v = optional(key);
        List<Cidr> out = new ArrayList<>();
        if (v == null) {
            return out;
        }
        for (String part : v.split(",", -1)) {
            try {
                out.add(Cidr.parse(part.strip()));
            } catch (IllegalArgumentException e) {
                throw invalid(key, "must be comma-separated CIDRs such as 10.0.0.0/24");
            }
        }
        return out;
    }

    /** Fails if the file has keys that no accessor asked for. Call after reading everything. */
    public void requireNoUnknownKeys() {
        Set<String> unknown = new TreeSet<>(props.stringPropertyNames());
        unknown.removeAll(used);
        if (!unknown.isEmpty()) {
            throw new IllegalArgumentException("config " + source + ": unknown key(s) " + new LinkedHashSet<>(unknown));
        }
    }
}
