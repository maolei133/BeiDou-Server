package org.gms.model.dto.monitor;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JvmInfoDTO {
    private String javaVersion;
    private String javaVendor;
    private String vmName;
    private String vmVersion;
    private MemoryInfoDTO heap;
    private MemoryInfoDTO nonHeap;
    private Integer threadCount;
    private Integer daemonThreadCount;
    private Integer peakThreadCount;
    private Long totalStartedThreadCount;
    private Long gcCount;
    private Long gcTimeMs;
}
