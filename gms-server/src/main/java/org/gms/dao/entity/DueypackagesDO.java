package org.gms.dao.entity;

import com.mybatisflex.annotation.Id;
import com.mybatisflex.annotation.KeyType;
import com.mybatisflex.annotation.Table;
import java.io.Serializable;
import java.sql.Timestamp;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.io.Serial;

/**
 *  实体类。
 *
 * @author sleep
 * @since 2024-05-24
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("dueypackages")
public class DueypackagesDO implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Id(keyType = KeyType.Auto)
    private Long packageid;

    private Long receiverid;

    private String sendername;
    
    /** 发件人ID，-1表示系统/管理员 */
    private Long senderid;

    private Long mesos;

    private Timestamp timestamp;

    private String message;

    private Integer checked;

    private Integer type;
    
    private Timestamp expireDate;

    private String itemData;

    private Timestamp statusTime;

    private Timestamp deliveryTime;

    private Long uid;

}
