package org.gms.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import org.gms.dao.entity.MonsterbookDO;

import java.util.List;

@Data
public class MonsterBookDTO {

    @EqualsAndHashCode(callSuper = true)
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SearchReq extends BasePageDTO {
        private List<Integer> charIds;
        private List<Integer> cardIds;
    }

    @Data
    public static class BatchDeleteReq {
        private List<MonsterbookDO> items;
    }

    @Data
    public static class BatchAddReq {
        private List<MonsterbookDO> items;
    }

    @Data
    public static class BatchUpdateReq {
        private List<UpdateItem> items;
    }

    @Data
    public static class UpdateItem {
        private Integer oldCharId;
        private Integer oldCardId;
        private Integer newCardId;
        private Integer newLevel;
    }

    @Data
    public static class TransferReq {
        private List<MonsterbookDO> items;
        private Integer newCharId;
    }

    @Data
    public static class Rtn {
        private Integer charid;
        private Integer cardid;
        private Integer level;
        private String cardName;
    }
}
