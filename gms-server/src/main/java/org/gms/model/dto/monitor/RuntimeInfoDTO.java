package org.gms.model.dto.monitor;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RuntimeInfoDTO {
    private Long pid;
    private Long uptimeMs;
    private Long startedAt;
    private String startedAtIso;
    private String userDir;
    private String environment;
    private String[] activeProfiles;
}
