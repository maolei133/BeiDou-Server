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
public class ServerMonitorHistoryDTO {
    private Long from;
    private Long to;
    private Integer minutes;
    private Integer intervalSeconds;
    private List<ServerMonitorHistoryPointDTO> points;
    private List<ServerMonitorEventDTO> events;
}
