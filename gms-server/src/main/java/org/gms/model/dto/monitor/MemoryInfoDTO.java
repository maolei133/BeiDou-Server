package org.gms.model.dto.monitor;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MemoryInfoDTO {
    private Long init;
    private Long used;
    private Long committed;
    private Long max;
    private Double usage;
}
