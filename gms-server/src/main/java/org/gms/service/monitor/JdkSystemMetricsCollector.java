package org.gms.service.monitor;

import com.sun.management.OperatingSystemMXBean;
import org.gms.model.dto.monitor.DiskIoInfoDTO;
import org.gms.model.dto.monitor.MemoryInfoDTO;

import java.lang.management.ManagementFactory;
import java.util.List;

/**
 * 基于 JVM 的跨平台指标采集器，用于 Windows 与其他非 Linux 系统。
 */
public class JdkSystemMetricsCollector implements SystemMetricsCollector {
    private static final String DISK_IO_UNAVAILABLE_NOTE = "当前平台无法采集磁盘 IO 速率。";

    private final OsMetricsProvider osMetricsProvider;

    public JdkSystemMetricsCollector() {
        this(new ManagementFactoryOsMetricsProvider());
    }

    JdkSystemMetricsCollector(OsMetricsProvider osMetricsProvider) {
        this.osMetricsProvider = osMetricsProvider;
    }

    @Override
    public SystemMetricsSample collect() {
        SystemMetricsSample sample = new SystemMetricsSample();

        sample.setSystemCpuLoad(normalizeLoad(osMetricsProvider.systemCpuLoad()));
        sample.setSystemMemory(buildSystemMemory(osMetricsProvider));
        sample.setDiskIo(DiskIoInfoDTO.builder()
                .available(false)
                .note(DISK_IO_UNAVAILABLE_NOTE)
                .build());
        sample.setWarnings(List.of());
        sample.setPartial(false);
        return sample;
    }

    Double getProcessCpuLoad() {
        return normalizeLoad(osMetricsProvider.processCpuLoad());
    }

    private MemoryInfoDTO buildSystemMemory(OsMetricsProvider provider) {
        Long total = provider.totalMemory();
        Long free = provider.freeMemory();
        if (total == null || free == null || total <= 0 || free < 0) {
            return null;
        }
        long used = Math.max(0L, total - free);
        return MemoryInfoDTO.builder()
                .used(used)
                .max(total)
                .usage((double) used / total)
                .build();
    }

    private Double normalizeLoad(Double value) {
        return value != null && value >= 0D && value <= 1D && Double.isFinite(value) ? value : null;
    }

    interface OsMetricsProvider {
        Double systemCpuLoad();
        Double processCpuLoad();
        Long totalMemory();
        Long freeMemory();
    }

    private static class ManagementFactoryOsMetricsProvider implements OsMetricsProvider {
        private final java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();

        @Override
        public Double systemCpuLoad() {
            if (osBean instanceof OperatingSystemMXBean extendedOsBean) {
                return extendedOsBean.getCpuLoad();
            }
            return null;
        }

        @Override
        public Double processCpuLoad() {
            if (osBean instanceof OperatingSystemMXBean extendedOsBean) {
                return extendedOsBean.getProcessCpuLoad();
            }
            return null;
        }

        @Override
        public Long totalMemory() {
            if (osBean instanceof OperatingSystemMXBean extendedOsBean) {
                return extendedOsBean.getTotalMemorySize();
            }
            return null;
        }

        @Override
        public Long freeMemory() {
            if (osBean instanceof OperatingSystemMXBean extendedOsBean) {
                return extendedOsBean.getFreeMemorySize();
            }
            return null;
        }
    }
}
