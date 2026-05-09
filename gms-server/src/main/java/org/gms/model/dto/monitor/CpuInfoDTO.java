package org.gms.model.dto.monitor;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CpuInfoDTO {
    private String osName;
    private String osVersion;
    private String osArch;
    private String processorModel;
    private Integer availableProcessors;
    private Double systemLoadAverage;
    private Double processCpuLoad;
    private Double systemCpuLoad;
    private MemoryInfoDTO systemMemory;
}
