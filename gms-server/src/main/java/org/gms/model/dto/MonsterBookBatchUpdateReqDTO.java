package org.gms.model.dto;

import lombok.Data;
import java.util.List;

@Data
public class MonsterBookBatchUpdateReqDTO {
    private List<MonsterBookUpdateItemDTO> items;
}
