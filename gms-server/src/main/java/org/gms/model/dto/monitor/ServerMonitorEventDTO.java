package org.gms.model.dto.monitor;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ServerMonitorEventDTO {
    private Long occurredAt;
    private String occurredAtIso;
    private String type;
    private String level;
    private String message;
    private Double value;
    private Double baseline;
}
