package org.gms.model.dto;

import lombok.Data;

@Data
public class MonsterBookUpdateItemDTO {
    private Integer oldCharId;
    private Integer oldCardId;
    private Integer newCardId;
    private Integer newLevel;
}
