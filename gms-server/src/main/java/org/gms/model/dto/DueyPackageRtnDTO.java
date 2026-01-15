package org.gms.model.dto;

import lombok.Data;
import java.sql.Timestamp;
import java.util.List;

@Data
public class DueyPackageRtnDTO {
    private Long packageId;
    private Long receiverId;
    private String receiverName;
    private String senderName;
    private Long mesos;
    private Timestamp timestamp;
    private String message;
    private Integer checked;
    private Integer type;
    private List<ItemInfoRtnDTO> items;
    
    // 新增字段
    private Timestamp expireTime;
    private Timestamp deliveryTime;
}
