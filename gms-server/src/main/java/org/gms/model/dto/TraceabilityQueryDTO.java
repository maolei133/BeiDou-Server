package org.gms.model.dto;

import com.mybatisflex.core.paginate.Page;
import lombok.Data;
import lombok.EqualsAndHashCode;

@EqualsAndHashCode(callSuper = true)
@Data
public class TraceabilityQueryDTO extends Page<Object> {
    private String uid; // [FIXED] Changed from Long to String
    private Integer itemId;
    private Integer characterId;
    private String actionType;
    private String actionSource;
    private Long startTime;
    private Long endTime;
}
