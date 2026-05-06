package org.gms.server.logging;

import java.util.Map;

/**
 * AutoCloseable scope for temporary log context values.
 *
 * <p>Use with try-with-resources to guarantee context cleanup/restoration on
 * normal return and exceptions:</p>
 *
 * <pre>{@code
 * try (LogContextScope ignored = LogContext.scope("NET", "PACKET", "START")
 *         .accountId(client.getAccID())
 *         .characterId(player.getId())
 *         .ensureTraceId()) {
 *     // business logic and logs
 * }
 * }</pre>
 */
public final class LogContextScope implements AutoCloseable {
    private final Map<String, String> previousLogContext;
    private final Map<String, String> previousThreadContext;
    private final Map<String, String> previousAuditContext;
    private boolean closed;

    LogContextScope(Map<String, String> previousLogContext, Map<String, String> previousThreadContext, Map<String, String> previousAuditContext) {
        this.previousLogContext = previousLogContext;
        this.previousThreadContext = previousThreadContext;
        this.previousAuditContext = previousAuditContext;
    }

    public LogContextScope put(String key, Object value) {
        ensureOpen();
        LogContext.put(key, value);
        return this;
    }

    public LogContextScope putAll(Map<String, ?> values) {
        ensureOpen();
        LogContext.putAll(values);
        return this;
    }

    public String get(String key) {
        ensureOpen();
        return LogContext.get(key);
    }

    public LogContextScope ensureTraceId() {
        ensureOpen();
        LogContext.ensureTraceId();
        return this;
    }

    public LogContextScope traceId(String traceId) {
        return put(LogContext.TRACE_ID, traceId);
    }

    public LogContextScope module(String module) {
        return put(LogContext.MODULE, module);
    }

    public LogContextScope action(String action) {
        return put(LogContext.ACTION, action);
    }

    public LogContextScope result(String result) {
        return put(LogContext.RESULT, result);
    }

    public LogContextScope accountId(Object accountId) {
        return put(LogContext.ACCOUNT_ID, accountId);
    }

    public LogContextScope characterId(Object characterId) {
        return put(LogContext.CHARACTER_ID, characterId);
    }

    public LogContextScope world(Object world) {
        return put(LogContext.WORLD, world);
    }

    public LogContextScope channel(Object channel) {
        return put(LogContext.CHANNEL, channel);
    }

    public LogContextScope mapId(Object mapId) {
        return put(LogContext.MAP_ID, mapId);
    }

    public LogContextScope opcode(String opcode) {
        return put(LogContext.OPCODE, opcode);
    }

    public LogContextScope scriptPath(String scriptPath) {
        return put(LogContext.SCRIPT_PATH, scriptPath);
    }

    public LogContextScope wzPath(String wzPath) {
        return put(LogContext.WZ_PATH, wzPath);
    }

    public LogContextScope costMs(Object costMs) {
        return put(LogContext.COST_MS, costMs);
    }

    public LogContextScope exceptionClass(Throwable throwable) {
        if (throwable == null) {
            return this;
        }
        return exceptionClass(throwable.getClass().getSimpleName());
    }

    public LogContextScope exceptionClass(String exceptionClass) {
        return put(LogContext.EXCEPTION_CLASS, exceptionClass);
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        LogContext.restore(previousLogContext, previousThreadContext, previousAuditContext);
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("LogContextScope is already closed");
        }
    }
}
