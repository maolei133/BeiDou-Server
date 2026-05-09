package org.gms.model.dto.monitor;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DiskInfoDTO {
    private String path;
    private Long total;
    private Long free;
    private Long usable;
    private Long used;
    private Double usage;
}
