package org.gms.service.monitor;

import java.util.Locale;

public final class SystemMetricsCollectorFactory {
    private SystemMetricsCollectorFactory() {
    }

    public static SystemMetricsCollector create() {
        if (isLinux()) {
            return new LinuxProcMonitorCollector();
        }
        return new JdkSystemMetricsCollector();
    }

    static boolean isLinux() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("linux");
    }
}
