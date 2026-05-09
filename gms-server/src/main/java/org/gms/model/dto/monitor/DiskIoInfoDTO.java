package org.gms.model.dto.monitor;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DiskIoInfoDTO {
    private Boolean available;
    private String note;
    private Double readBytesPerSecond;
    private Double writeBytesPerSecond;
    private Double readOpsPerSecond;
    private Double writeOpsPerSecond;
}
