package org.gms.service.monitor;

import org.gms.model.dto.monitor.ContainerInfoDTO;

import java.util.List;

public interface ContainerInfoCollector {
    ContainerInfoDTO detect(List<String> warnings);
}
