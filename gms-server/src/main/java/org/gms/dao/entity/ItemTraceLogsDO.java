package org.gms.dao.entity;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;
import com.mybatisflex.annotation.Column;
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

    @JsonSerialize(using = ToStringSerializer.class) // [FIXED] Serialize Long to String for frontend
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
    private Boolean isValuable;

    // 非数据库字段，用于在Service层填充
    @Column(ignore = true)
    private String itemName;
    @Column(ignore = true)
    private String characterName;
    @Column(ignore = true)
    private String mapName;
}
