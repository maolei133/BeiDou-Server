package org.gms.service.monitor;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;

class SystemMetricsCollectorFactoryTest {

    @Test
    void selectsLinuxProcCollectorOnLinux() {
        assertInstanceOf(LinuxProcMonitorCollector.class, SystemMetricsCollectorFactory.create());
        assertSame(LinuxProcMonitorCollector.class, SystemMetricsCollectorFactory.collectorTypeForOsName("Linux"));
    }

    @Test
    void selectsOshiCollectorOnWindows() {
        assertSame(OshiSystemMetricsCollector.class, SystemMetricsCollectorFactory.collectorTypeForOsName("Windows Server 2022"));
    }

    @Test
    void selectsOshiCollectorOnOtherSystems() {
        assertSame(OshiSystemMetricsCollector.class, SystemMetricsCollectorFactory.collectorTypeForOsName("Mac OS X"));
    }
}
