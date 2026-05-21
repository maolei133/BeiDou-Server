package org.gms.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ChannelListRtnDTO {
    private Integer id;
    private Integer worldId;
    private Integer playerCount;
    private Integer mapCount;
    private Long estimatedMapMemoryBytes;
    private Integer disposedMapCount;
}
