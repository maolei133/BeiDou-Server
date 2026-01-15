package org.gms.model.dto;

import lombok.Data;
import lombok.EqualsAndHashCode;

@EqualsAndHashCode(callSuper = true)
@Data
public class DueySearchReqDTO extends BasePageDTO {
    private String receiverName;
    private String senderName;
    private Long startTime;
    private Long endTime;
    private Integer itemType;
    private Integer checked;
}
