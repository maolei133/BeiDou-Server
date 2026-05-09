package org.gms.service.monitor;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JdkSystemMetricsCollectorTest {

    @Test
    void collectsCrossPlatformMetricsWithoutLinuxWarnings() {
        SystemMetricsSample sample = new JdkSystemMetricsCollector().collect();

        assertFalse(sample.isPartial());
        assertTrue(sample.getWarnings().stream().noneMatch(warning -> warning.contains("/proc") || warning.contains("cgroup")));
        if (sample.getSystemCpuLoad() != null) {
            assertTrue(sample.getSystemCpuLoad() >= 0D && sample.getSystemCpuLoad() <= 1D);
        }
        if (sample.getSystemMemory() != null) {
            assertNotNull(sample.getSystemMemory().getMax());
            assertTrue(sample.getSystemMemory().getMax() > 0L);
            assertNotNull(sample.getSystemMemory().getUsed());
            assertTrue(sample.getSystemMemory().getUsed() >= 0L);
            assertNotNull(sample.getSystemMemory().getUsage());
            assertTrue(sample.getSystemMemory().getUsage() >= 0D && sample.getSystemMemory().getUsage() <= 1D);
        }
        assertNull(sample.getNetworkRxBytesPerSecond());
        assertNull(sample.getNetworkTxBytesPerSecond());
        assertNotNull(sample.getDiskIo());
        assertFalse(sample.getDiskIo().getAvailable());
        assertNotNull(sample.getDiskIo().getNote());
        assertFalse(sample.getDiskIo().getNote().contains("/proc"));
    }
}
