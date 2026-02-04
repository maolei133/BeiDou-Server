package org.gms.dao.entity;

import com.mybatisflex.annotation.Id;
import com.mybatisflex.annotation.KeyType;
import com.mybatisflex.annotation.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("item_trace_logs")
public class ItemTraceLogsDO implements Serializable {
    @Id(keyType = KeyType.Auto)
    private Long id;
    private Long uid;
    private Integer accountId;
    private Integer characterId;
    private String actionType;
    private String actionSource;
    private Integer mapId;
    private Integer itemId;
    private Integer quantityChange;
    private String targetInfo;
    private String itemSnapshot;
    private Long timestamp;
    private String memo;
}
