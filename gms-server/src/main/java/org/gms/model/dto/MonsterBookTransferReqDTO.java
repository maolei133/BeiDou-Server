package org.gms.model.dto;

import lombok.Data;
import org.gms.dao.entity.MonsterbookDO;
import java.util.List;

@Data
public class MonsterBookTransferReqDTO {
    private List<MonsterbookDO> items;
    private Integer newCharId;
}
