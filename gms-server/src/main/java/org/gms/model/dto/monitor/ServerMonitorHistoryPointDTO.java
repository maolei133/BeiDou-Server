package org.gms.model.dto.monitor;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ServerMonitorHistoryPointDTO {
    private Long sampledAt;
    private String sampledAtIso;
    private Double systemCpuLoad;
    private Double processCpuLoad;
    private Double systemLoadAverage;
    private Double systemMemoryUsage;
    private Double jvmHeapUsage;
    private Double jvmNonHeapUsage;
    private Integer threadCount;
    private Long gcCount;
    private Long gcTimeMs;
    private Double diskUsageMax;
    private Double networkRxBytesPerSecond;
    private Double networkTxBytesPerSecond;
    private Double diskReadBytesPerSecond;
    private Double diskWriteBytesPerSecond;
    private Boolean cpuAnomaly;
    private String cpuAnomalyLevel;
    private String cpuAnomalyReason;
    private Double cpuAnomalyBaseline;
    private Boolean partial;
    private List<String> warnings;
}
