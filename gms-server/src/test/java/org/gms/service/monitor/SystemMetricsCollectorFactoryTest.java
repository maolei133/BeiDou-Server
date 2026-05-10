package org.gms.service.monitor;

import org.gms.model.dto.monitor.DiskIoInfoDTO;
import org.gms.model.dto.monitor.MemoryInfoDTO;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SystemMetricsCollectorFactoryTest {

    @Test
    void selectsLinuxProcCollectorOnLinux() {
        assertInstanceOf(LinuxProcMonitorCollector.class, SystemMetricsCollectorFactory.create());
        assertSame(LinuxProcMonitorCollector.class, SystemMetricsCollectorFactory.collectorTypeForOsName("Linux"));
    }

    @Test
    void selectsJdkCollectorOnWindows() {
        assertSame(JdkSystemMetricsCollector.class, SystemMetricsCollectorFactory.collectorTypeForOsName("Windows Server 2022"));
    }

    @Test
    void selectsJdkCollectorOnOtherSystems() {
        assertSame(JdkSystemMetricsCollector.class, SystemMetricsCollectorFactory.collectorTypeForOsName("Mac OS X"));
    }

    @Test
    void jdkCollectorBackfillsZeroOshiCpuOnWindows() {
        SystemMetricsCollector delegate = () -> {
            SystemMetricsSample sample = new SystemMetricsSample();
            sample.setSystemCpuLoad(0D);
            sample.setSystemMemory(MemoryInfoDTO.builder()
                    .used(1L)
                    .max(2L)
                    .usage(0.5D)
                    .build());
            sample.setDiskIo(DiskIoInfoDTO.builder().available(false).build());
            return sample;
        };
        JdkSystemMetricsCollector fallback = new JdkSystemMetricsCollector(new FixedOsMetricsProvider(0.42D, 0.1D, 8L, 2L));
        SystemMetricsCollector collector = SystemMetricsCollectorFactory.create("Windows Server 2022", delegate, fallback);

        SystemMetricsSample sample = collector.collect();

        assertEquals(0.42D, sample.getSystemCpuLoad());
        assertFalse(sample.isPartial());
        assertTrue(sample.getWarnings().isEmpty());
        assertNotNull(sample.getSystemMemory());
        assertEquals(0.5D, sample.getSystemMemory().getUsage());
    }

    @Test
    void keepsRealOshiCpuOnWindowsWhenAvailable() {
        SystemMetricsCollector delegate = () -> {
            SystemMetricsSample sample = new SystemMetricsSample();
            sample.setSystemCpuLoad(0.33D);
            return sample;
        };
        JdkSystemMetricsCollector fallback = new JdkSystemMetricsCollector(new FixedOsMetricsProvider(0.42D, 0.1D, 8L, 2L));
        SystemMetricsCollector collector = SystemMetricsCollectorFactory.create("Windows Server 2022", delegate, fallback);

        SystemMetricsSample sample = collector.collect();

        assertEquals(0.33D, sample.getSystemCpuLoad());
    }

    @Test
    void keepsLinuxCollectorWithoutJdkBackfill() {
        SystemMetricsCollector delegate = () -> {
            SystemMetricsSample sample = new SystemMetricsSample();
            sample.setSystemCpuLoad(0D);
            return sample;
        };
        JdkSystemMetricsCollector fallback = new JdkSystemMetricsCollector(new FixedOsMetricsProvider(0.42D, 0.1D, 8L, 2L));
        SystemMetricsCollector collector = SystemMetricsCollectorFactory.create("Linux", delegate, fallback);

        SystemMetricsSample sample = collector.collect();

        assertEquals(0D, sample.getSystemCpuLoad());
    }

    private static void assertInstanceOf(Class<?> expectedType, Object actual) {
        org.junit.jupiter.api.Assertions.assertInstanceOf(expectedType, actual);
    }

    private record FixedOsMetricsProvider(Double systemCpuLoad, Double processCpuLoad, Long totalMemory, Long freeMemory)
            implements JdkSystemMetricsCollector.OsMetricsProvider {
    }
}
