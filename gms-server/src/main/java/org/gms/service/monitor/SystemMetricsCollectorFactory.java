package org.gms.service.monitor;

import java.util.Locale;

public final class SystemMetricsCollectorFactory {
    private SystemMetricsCollectorFactory() {
    }

    public static SystemMetricsCollector create() {
        if (collectorTypeForOsName(System.getProperty("os.name", "")) == LinuxProcMonitorCollector.class) {
            return new LinuxProcMonitorCollector();
        }
        return new OshiSystemMetricsCollector();
    }

    static boolean isLinux() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("linux");
    }

    static Class<? extends SystemMetricsCollector> collectorTypeForOsName(String osName) {
        if (osName != null && osName.toLowerCase(Locale.ROOT).contains("linux")) {
            return LinuxProcMonitorCollector.class;
        }
        return OshiSystemMetricsCollector.class;
    }
}
