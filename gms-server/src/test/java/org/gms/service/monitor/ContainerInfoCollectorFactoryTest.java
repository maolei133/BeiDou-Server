package org.gms.service.monitor;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContainerInfoCollectorFactoryTest {

    @Test
    void selectsLinuxCgroupCollectorOnLinux() {
        withOsName("Linux", () -> assertInstanceOf(ContainerRuntimeDetector.class, ContainerInfoCollectorFactory.create()));
    }

    @Test
    void selectsNoopCollectorOnWindows() {
        withOsName("Windows Server 2022", () -> {
            ContainerInfoCollector collector = ContainerInfoCollectorFactory.create();
            var warnings = new ArrayList<String>();

            var container = collector.detect(warnings);

            assertInstanceOf(NoopContainerInfoCollector.class, collector);
            assertFalse(container.getDetected());
            assertEquals("none", container.getRuntime());
            assertTrue(warnings.isEmpty());
        });
    }

    @Test
    void selectsNoopCollectorOnOtherSystems() {
        withOsName("Mac OS X", () -> {
            ContainerInfoCollector collector = ContainerInfoCollectorFactory.create();
            var warnings = new ArrayList<String>();

            var container = collector.detect(warnings);

            assertInstanceOf(NoopContainerInfoCollector.class, collector);
            assertFalse(container.getDetected());
            assertEquals("none", container.getRuntime());
            assertTrue(warnings.isEmpty());
        });
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
