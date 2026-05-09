package org.gms.server.logging;

import org.apache.logging.log4j.ThreadContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class LogContextTest {

    @AfterEach
    void tearDown() {
        LogContext.clear();
        AuditContext.clear();
        ThreadContext.clearAll();
    }

    @Test
    void putStoresValueInSnapshotAuditContextAndThreadContext() {
        LogContext.put("traceId", "trace-001");
        LogContext.put("module", "LOGIN");
        LogContext.put("action", "AUTH");
        LogContext.put("result", "SUCCESS");

        Map<String, String> snapshot = LogContext.getCopy();

        assertEquals("trace-001", snapshot.get("traceId"));
        assertEquals("LOGIN", snapshot.get("module"));
        assertEquals("AUTH", snapshot.get("action"));
        assertEquals("SUCCESS", snapshot.get("result"));
        assertEquals("trace-001", AuditContext.get().get("traceId"));
        assertEquals("trace-001", ThreadContext.get("traceId"));
    }

    @Test
    void scopeRestoresPreviousContextWhenClosed() {
        LogContext.put("traceId", "outer");
        LogContext.put("accountId", "1001");
        AuditContext.put("ip", "127.0.0.1");
        AuditContext.put("aid", "legacy-aid");
        Map<String, String> previousAudit = AuditContext.get();
        ThreadContext.put("external", "keep-me");

        try (LogContextScope ignored = LogContext.scope()
                .put("traceId", "inner")
                .put("characterId", "2002")) {
            assertEquals("inner", LogContext.get("traceId"));
            assertEquals("1001", LogContext.get("accountId"));
            assertEquals("2002", ThreadContext.get("characterId"));
            assertEquals("2002", AuditContext.get().get("cid"));
        }

        assertEquals("outer", LogContext.get("traceId"));
        assertEquals("1001", LogContext.get("accountId"));
        assertNull(LogContext.get("characterId"));
        assertNull(ThreadContext.get("characterId"));
        assertEquals(previousAudit, AuditContext.get());
        assertEquals("keep-me", ThreadContext.get("external"));
    }

    @Test
    void namedScopeSetsStandardFieldsAndOutcomeCanBeUpdated() {
        try (LogContextScope scope = LogContext.scope("GAME", "ENTER_MAP", "START")) {
            scope.traceId("trace-xyz")
                    .accountId(10)
                    .characterId(20)
                    .world(0)
                    .channel(1)
                    .mapId(100000000)
                    .opcode("MOVE_PLAYER")
                    .scriptPath("npc/9000000.js")
                    .wzPath("Map/Map0/100000000.img")
                    .costMs(35)
                    .exceptionClass("IllegalStateException")
                    .result("FAIL");

            assertEquals("GAME", LogContext.get("module"));
            assertEquals("ENTER_MAP", LogContext.get("action"));
            assertEquals("FAIL", LogContext.get("result"));
            assertEquals("trace-xyz", LogContext.get("traceId"));
            assertEquals("10", LogContext.get("accountId"));
            assertEquals("20", LogContext.get("characterId"));
            assertEquals("0", LogContext.get("world"));
            assertEquals("1", LogContext.get("channel"));
            assertEquals("100000000", LogContext.get("mapId"));
            assertEquals("MOVE_PLAYER", LogContext.get("opcode"));
            assertEquals("npc/9000000.js", LogContext.get("scriptPath"));
            assertEquals("Map/Map0/100000000.img", LogContext.get("wzPath"));
            assertEquals("35", LogContext.get("costMs"));
            assertEquals("IllegalStateException", LogContext.get("exceptionClass"));
        }

        assertTrue(LogContext.getCopy().isEmpty());
        assertTrue(AuditContext.get().isEmpty());
        assertNull(ThreadContext.get("traceId"));
    }

    @Test
    void generatedTraceIdIsStableInsideScope() {
        try (LogContextScope scope = LogContext.scope("NET", "PACKET", "START").ensureTraceId()) {
            String traceId = LogContext.get("traceId");

            assertNotNull(traceId);
            assertFalse(traceId.isBlank());
            assertEquals(traceId, scope.ensureTraceId().get("traceId"));
        }
    }

    @Test
    void removeClearsLegacyAuditAliases() {
        LogContext.put("accountId", 1001);
        LogContext.put("characterId", 2002);
        LogContext.put("mapId", 100000000);

        LogContext.remove("accountId");
        LogContext.remove("characterId");
        LogContext.remove("mapId");

        Map<String, String> audit = AuditContext.get();
        assertNull(audit.get("accountId"));
        assertNull(audit.get("aid"));
        assertNull(audit.get("characterId"));
        assertNull(audit.get("cid"));
        assertNull(audit.get("mapId"));
        assertNull(audit.get("map"));
    }

    @Test
    void valuesAreSanitizedBeforeEnteringThreadContext() {
        String longValue = "line1\nline2\r" + "x".repeat(600);

        LogContext.put("scriptPath", longValue);

        String value = ThreadContext.get("scriptPath");
        assertFalse(value.contains("\n"));
        assertFalse(value.contains("\r"));
        assertEquals(512, value.length());
    }
}
