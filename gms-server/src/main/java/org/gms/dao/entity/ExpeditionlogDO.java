package org.gms.dao.entity;

import com.mybatisflex.annotation.Id;
import com.mybatisflex.annotation.KeyType;
import com.mybatisflex.annotation.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.sql.Timestamp;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("expeditionlog")
public class ExpeditionlogDO implements Serializable {
    @Id(keyType = KeyType.Auto)
    private Long id;
    private Integer characterid;
    private String bosstype;
    private Timestamp attempttime;
}
