package org.gms.model.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.*;
import lombok.experimental.SuperBuilder;

@EqualsAndHashCode(callSuper = true)
@Data
@AllArgsConstructor
@NoArgsConstructor
@SuperBuilder
@JsonIgnoreProperties(ignoreUnknown = true) // 反序列化时忽略未知字段
public class InventorySearchReqDTO extends BasePageDTO {
    private Byte inventoryType;
    private Integer characterId;
    private String characterName;
    private boolean onlineStatus;
}
