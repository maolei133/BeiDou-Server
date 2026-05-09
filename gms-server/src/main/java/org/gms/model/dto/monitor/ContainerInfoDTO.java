package org.gms.model.dto.monitor;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ContainerInfoDTO {
    private Boolean detected;
    private String runtime;
    private Boolean dockerEnv;
    private String cgroupPath;
    private MemoryInfoDTO memory;
}
