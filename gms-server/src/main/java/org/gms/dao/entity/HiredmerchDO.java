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
@Table("hiredmerch")
public class HiredmerchDO implements Serializable {
    @Id(keyType = KeyType.Auto)
    private Integer packageid;
    private Integer characterid;
    private Integer accountid;
    private Integer mesos;
    private Long time;
}
