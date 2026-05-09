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
public class SampleInfoDTO {
    private Long sampledAt;
    private String sampledAtIso;
    private Boolean partial;
    private List<String> warnings;
}
