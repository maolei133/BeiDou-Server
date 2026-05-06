package org.gms.server.logging;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Locale;

final class TraceIdGenerator {
    private static final SecureRandom RANDOM = new SecureRandom();

    private TraceIdGenerator() {
    }

    static String nextTraceId() {
        long now = Instant.now().toEpochMilli();
        long random = RANDOM.nextLong();
        return Long.toUnsignedString(now, 36).toLowerCase(Locale.ROOT)
                + '-'
                + Long.toUnsignedString(random, 36).toLowerCase(Locale.ROOT);
    }
}
