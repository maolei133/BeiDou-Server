package org.gms.server.logging;

import org.apache.logging.log4j.ThreadContext;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Unified runtime log context for normal server logs and audit logs.
 *
 * <p>The context is thread-local and mirrored into Log4j2 {@link ThreadContext},
 * so log4j patterns can print fields such as traceId/accountId/characterId while
 * legacy {@link AuditLogger} can continue to read the same values via
 * {@link AuditContext}.</p>
 */
public final class LogContext {
    public static final String TRACE_ID = "traceId";
    public static final String MODULE = "module";
    public static final String ACTION = "action";
    public static final String RESULT = "result";
    public static final String ACCOUNT_ID = "accountId";
    public static final String CHARACTER_ID = "characterId";
    public static final String WORLD = "world";
    public static final String CHANNEL = "channel";
    public static final String MAP_ID = "mapId";
    public static final String OPCODE = "opcode";
    public static final String SCRIPT_PATH = "scriptPath";
    public static final String WZ_PATH = "wzPath";
    public static final String COST_MS = "costMs";
    public static final String EXCEPTION_CLASS = "exceptionClass";

    private static final int MAX_VALUE_LENGTH = 512;
    private static final Set<String> MANAGED_KEYS = Set.of(
            TRACE_ID,
            MODULE,
            ACTION,
            RESULT,
            ACCOUNT_ID,
            CHARACTER_ID,
            WORLD,
            CHANNEL,
            MAP_ID,
            OPCODE,
            SCRIPT_PATH,
            WZ_PATH,
            COST_MS,
            EXCEPTION_CLASS
    );

    private static final ThreadLocal<Map<String, String>> CONTEXT = ThreadLocal.withInitial(LinkedHashMap::new);

    private LogContext() {
    }

    public static LogContextScope scope() {
        return new LogContextScope(getCopy(), ThreadContext.getImmutableContext(), AuditContext.get());
    }

    public static LogContextScope scope(String module, String action, String result) {
        return scope()
                .module(module)
                .action(action)
                .result(result);
    }

    public static void put(String key, Object value) {
        if (key == null || key.isBlank() || value == null || !MANAGED_KEYS.contains(key)) {
            return;
        }
        putString(key, String.valueOf(value));
    }

    public static void putAll(Map<String, ?> values) {
        if (values == null || values.isEmpty()) {
            return;
        }
        for (Map.Entry<String, ?> entry : values.entrySet()) {
            put(entry.getKey(), entry.getValue());
        }
    }

    public static String get(String key) {
        if (key == null) {
            return null;
        }
        return CONTEXT.get().get(key);
    }

    public static Map<String, String> getCopy() {
        return new LinkedHashMap<>(CONTEXT.get());
    }

    public static Map<String, String> snapshot() {
        return Collections.unmodifiableMap(getCopy());
    }

    public static boolean contains(String key) {
        return key != null && CONTEXT.get().containsKey(key);
    }

    public static String ensureTraceId() {
        String traceId = get(TRACE_ID);
        if (traceId == null || traceId.isBlank()) {
            traceId = TraceIdGenerator.nextTraceId();
            put(TRACE_ID, traceId);
        }
        return traceId;
    }

    public static void remove(String key) {
        if (key == null) {
            return;
        }
        CONTEXT.get().remove(key);
        ThreadContext.remove(key);
        AuditContext.remove(key);
        removeLegacyAuditKey(key);
    }

    public static void clear() {
        CONTEXT.remove();
        ThreadContext.clearMap();
        AuditContext.clear();
    }

    static void restore(Map<String, String> previousLogContext, Map<String, String> previousThreadContext, Map<String, String> previousAuditContext) {
        Map<String, String> data = CONTEXT.get();
        data.clear();
        if (previousLogContext != null && !previousLogContext.isEmpty()) {
            data.putAll(previousLogContext);
        }

        ThreadContext.clearMap();
        if (previousThreadContext != null && !previousThreadContext.isEmpty()) {
            ThreadContext.putAll(previousThreadContext);
        }

        AuditContext.replace(previousAuditContext);
    }

    private static void putString(String key, String value) {
        if (value == null) {
            return;
        }
        String sanitizedValue = sanitize(value);
        CONTEXT.get().put(key, sanitizedValue);
        ThreadContext.put(key, sanitizedValue);
        AuditContext.put(key, sanitizedValue);
        mirrorLegacyAuditKey(key, sanitizedValue);
    }

    private static void mirrorLegacyAuditKey(String key, String value) {
        switch (key) {
            case ACCOUNT_ID -> AuditContext.put("aid", value);
            case CHARACTER_ID -> AuditContext.put("cid", value);
            case MAP_ID -> AuditContext.put("map", value);
            default -> {
                // No legacy alias needed.
            }
        }
    }

    private static void removeLegacyAuditKey(String key) {
        switch (key) {
            case ACCOUNT_ID -> AuditContext.remove("aid");
            case CHARACTER_ID -> AuditContext.remove("cid");
            case MAP_ID -> AuditContext.remove("map");
            default -> {
                // No legacy alias needed.
            }
        }
    }

    private static String sanitize(String value) {
        StringBuilder sanitized = new StringBuilder(Math.min(value.length(), MAX_VALUE_LENGTH));
        for (int i = 0; i < value.length() && sanitized.length() < MAX_VALUE_LENGTH; i++) {
            char ch = value.charAt(i);
            if (ch == '\n' || ch == '\r' || Character.isISOControl(ch)) {
                sanitized.append(' ');
            } else {
                sanitized.append(ch);
            }
        }
        return sanitized.toString();
    }
}
