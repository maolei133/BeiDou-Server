package org.gms.model.dto;

import lombok.Data;
import java.sql.Timestamp;
import java.util.List;

/**
 * 快递包裹返回DTO
 */
@Data
public class DueyPackageRtnDTO {
    /** 包裹ID */
    private Long packageId;
    /** 收件人ID */
    private Long receiverId;
    /** 收件人名称 */
    private String receiverName;
    /** 发件人名称 */
    private String senderName;
    /** 金币 */
    private Long mesos;
    /** 发送时间 */
    private Timestamp timestamp;
    /** 留言 */
    private String message;
    /** 状态 */
    private Integer checked;
    /** 类型 */
    private Integer type;
    /** 物品列表 */
    private List<ItemInfoRtnDTO> items;
    
    // 新增字段
    /** 过期时间 */
    private Timestamp expireTime;
    /** 送达时间 */
    private Timestamp deliveryTime;
}
