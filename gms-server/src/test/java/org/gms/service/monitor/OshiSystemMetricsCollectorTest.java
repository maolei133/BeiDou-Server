package org.gms.service.monitor;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OshiSystemMetricsCollectorTest {

    @Test
    void collectsCrossPlatformIoRatesAfterSecondSample() throws Exception {
        OshiSystemMetricsCollector collector = new OshiSystemMetricsCollector();
        SystemMetricsSample first = collector.collect();
        Thread.sleep(20L);
        SystemMetricsSample second = collector.collect();

        assertFalse(first.isPartial());
        assertFalse(second.isPartial());
        assertTrue(second.getWarnings().stream().noneMatch(warning -> warning.contains("/proc") || warning.contains("cgroup")));
        if (second.getSystemCpuLoad() != null) {
            assertTrue(second.getSystemCpuLoad() >= 0D && second.getSystemCpuLoad() <= 1D);
        }
        if (second.getSystemMemory() != null) {
            assertNotNull(second.getSystemMemory().getMax());
            assertTrue(second.getSystemMemory().getMax() > 0L);
            assertNotNull(second.getSystemMemory().getUsed());
            assertTrue(second.getSystemMemory().getUsed() >= 0L);
            assertNotNull(second.getSystemMemory().getUsage());
            assertTrue(second.getSystemMemory().getUsage() >= 0D && second.getSystemMemory().getUsage() <= 1D);
        }
        assertNotNull(second.getDiskIo());
        assertFalse(second.getDiskIo().getNote() != null && second.getDiskIo().getNote().contains("/proc"));
    }

    @Test
    void exposesProcessCpuAndProcessorModelWithoutThrowing() {
        OshiSystemMetricsCollector collector = new OshiSystemMetricsCollector();
        Double processCpuLoad = collector.getProcessCpuLoad();
        if (processCpuLoad != null) {
            assertTrue(processCpuLoad >= 0D && processCpuLoad <= 1D);
        }
        collector.getProcessorModel();
    }
}
