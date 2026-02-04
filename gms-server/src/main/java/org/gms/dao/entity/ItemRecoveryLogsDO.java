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
@Table("item_recovery_logs")
public class ItemRecoveryLogsDO implements Serializable {
    @Id(keyType = KeyType.Auto)
    private Long id;
    private Integer characterId;
    private Long uid;
    private Integer itemId;
    private String itemData;
    private String disposalType;
    private Long disposalTime;
    private Long recoveryDeadline;
    private String status;
}
