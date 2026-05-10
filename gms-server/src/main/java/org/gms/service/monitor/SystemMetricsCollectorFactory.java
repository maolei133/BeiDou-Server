package org.gms.service.monitor;

import org.gms.model.dto.monitor.DiskIoInfoDTO;
import org.gms.model.dto.monitor.MemoryInfoDTO;

import java.util.List;
import java.util.Locale;

public final class SystemMetricsCollectorFactory {
    private SystemMetricsCollectorFactory() {
    }

    public static SystemMetricsCollector create() {
        return create(System.getProperty("os.name", ""), new LinuxProcMonitorCollector(), new OshiSystemMetricsCollector(), new JdkSystemMetricsCollector());
    }

    static SystemMetricsCollector create(String osName, SystemMetricsCollector primaryCollector, JdkSystemMetricsCollector jdkCollector) {
        return create(osName, primaryCollector, primaryCollector, jdkCollector);
    }

    static SystemMetricsCollector create(String osName, SystemMetricsCollector linuxCollector,
                                         SystemMetricsCollector nonLinuxCollector, JdkSystemMetricsCollector jdkCollector) {
        if (collectorTypeForOsName(osName) == LinuxProcMonitorCollector.class) {
            return linuxCollector;
        }
        return new JdkBackfilledSystemMetricsCollector(nonLinuxCollector, jdkCollector);
    }

    static boolean isLinux() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("linux");
    }

    static Class<? extends SystemMetricsCollector> collectorTypeForOsName(String osName) {
        if (osName != null && osName.toLowerCase(Locale.ROOT).contains("linux")) {
            return LinuxProcMonitorCollector.class;
        }
        return JdkSystemMetricsCollector.class;
    }

    public static class JdkBackfilledSystemMetricsCollector implements SystemMetricsCollector {
        private final SystemMetricsCollector primary;
        private final JdkSystemMetricsCollector fallback;

        JdkBackfilledSystemMetricsCollector(SystemMetricsCollector primary, JdkSystemMetricsCollector fallback) {
            this.primary = primary;
            this.fallback = fallback;
        }

        @Override
        public SystemMetricsSample collect() {
            return collect(null);
        }

        @Override
        public SystemMetricsSample collect(String networkInterfaceName) {
            SystemMetricsSample sample = primary.collect(networkInterfaceName);
            SystemMetricsSample fallbackSample = fallback.collect();
            if (shouldBackfillCpu(sample.getSystemCpuLoad(), fallbackSample.getSystemCpuLoad())) {
                sample.setSystemCpuLoad(fallbackSample.getSystemCpuLoad());
            }
            if (sample.getSystemMemory() == null) {
                sample.setSystemMemory(fallbackSample.getSystemMemory());
            }
            if (sample.getWarnings() == null) {
                sample.setWarnings(List.of());
            }
            return sample;
        }

        public Double getProcessCpuLoad() {
            if (primary instanceof OshiSystemMetricsCollector oshiCollector) {
                Double processCpuLoad = oshiCollector.getProcessCpuLoad();
                if (processCpuLoad != null && processCpuLoad > 0D) {
                    return processCpuLoad;
                }
            }
            return fallback.getProcessCpuLoad();
        }

        public String getProcessorModel() {
            if (primary instanceof OshiSystemMetricsCollector oshiCollector) {
                return oshiCollector.getProcessorModel();
            }
            return null;
        }

        private boolean shouldBackfillCpu(Double primaryCpuLoad, Double fallbackCpuLoad) {
            return fallbackCpuLoad != null && (primaryCpuLoad == null || primaryCpuLoad <= 0D);
        }
    }
}
