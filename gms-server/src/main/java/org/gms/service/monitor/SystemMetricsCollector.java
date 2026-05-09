package org.gms.service.monitor;

public interface SystemMetricsCollector {
    SystemMetricsSample collect();

    default SystemMetricsSample collect(String networkInterfaceName) {
        return collect();
    }
}
