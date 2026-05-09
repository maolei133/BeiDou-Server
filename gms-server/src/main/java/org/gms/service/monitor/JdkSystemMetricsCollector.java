package org.gms.service.monitor;

import com.sun.management.OperatingSystemMXBean;
import org.gms.model.dto.monitor.DiskIoInfoDTO;
import org.gms.model.dto.monitor.MemoryInfoDTO;

import java.lang.management.ManagementFactory;
import java.util.List;

/**
 * Cross-platform JVM-backed metrics collector used on Windows and other non-Linux systems.
 */
public class JdkSystemMetricsCollector implements SystemMetricsCollector {
    private static final String DISK_IO_UNAVAILABLE_NOTE = "Disk IO rate counters are not available on this platform.";

    @Override
    public SystemMetricsSample collect() {
        SystemMetricsSample sample = new SystemMetricsSample();
        java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();

        if (osBean instanceof OperatingSystemMXBean extendedOsBean) {
            sample.setSystemCpuLoad(normalizeLoad(extendedOsBean.getCpuLoad()));
            sample.setSystemMemory(buildSystemMemory(extendedOsBean));
        }
        sample.setDiskIo(DiskIoInfoDTO.builder()
                .available(false)
                .note(DISK_IO_UNAVAILABLE_NOTE)
                .build());
        sample.setWarnings(List.of());
        sample.setPartial(false);
        return sample;
    }

    private MemoryInfoDTO buildSystemMemory(OperatingSystemMXBean osBean) {
        long total = osBean.getTotalMemorySize();
        long free = osBean.getFreeMemorySize();
        if (total <= 0 || free < 0) {
            return null;
        }
        long used = Math.max(0L, total - free);
        return MemoryInfoDTO.builder()
                .used(used)
                .max(total)
                .usage((double) used / total)
                .build();
    }

    private Double normalizeLoad(double value) {
        return value >= 0 ? value : null;
    }
}
