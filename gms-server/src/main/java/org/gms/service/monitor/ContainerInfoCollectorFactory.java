package org.gms.service.monitor;

import java.util.Locale;

public final class ContainerInfoCollectorFactory {
    private ContainerInfoCollectorFactory() {
    }

    public static ContainerInfoCollector create() {
        if (isLinux()) {
            return new ContainerRuntimeDetector();
        }
        return new NoopContainerInfoCollector();
    }

    static boolean isLinux() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("linux");
    }
}
