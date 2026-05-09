package org.gms.service.monitor;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class SystemMetricsCollectorFactoryTest {

    @Test
    void selectsLinuxProcCollectorOnLinux() {
        withOsName("Linux", () -> assertInstanceOf(LinuxProcMonitorCollector.class, SystemMetricsCollectorFactory.create()));
    }

    @Test
    void selectsJdkCollectorOnWindows() {
        withOsName("Windows Server 2022", () -> assertInstanceOf(JdkSystemMetricsCollector.class, SystemMetricsCollectorFactory.create()));
    }

    @Test
    void selectsJdkCollectorOnOtherSystems() {
        withOsName("Mac OS X", () -> assertInstanceOf(JdkSystemMetricsCollector.class, SystemMetricsCollectorFactory.create()));
    }

    private void withOsName(String osName, Runnable assertion) {
        String previous = System.getProperty("os.name");
        try {
            System.setProperty("os.name", osName);
            assertion.run();
        } finally {
            if (previous == null) {
                System.clearProperty("os.name");
            } else {
                System.setProperty("os.name", previous);
            }
        }
    }
}
