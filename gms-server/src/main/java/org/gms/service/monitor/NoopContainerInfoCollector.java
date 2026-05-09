package org.gms.service.monitor;

import org.gms.model.dto.monitor.ContainerInfoDTO;

import java.util.List;

/**
 * Non-Linux fallback: no container/cgroup metrics are expected, so no warning is emitted.
 */
public class NoopContainerInfoCollector implements ContainerInfoCollector {
    @Override
    public ContainerInfoDTO detect(List<String> warnings) {
        return ContainerInfoDTO.builder()
                .runtime("none")
                .detected(false)
                .build();
    }
}
