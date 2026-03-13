package org.gms.model.dto;

import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * 快递查询请求DTO
 */
@EqualsAndHashCode(callSuper = true)
@Data
public class DueySearchReqDTO extends BasePageDTO {
    /** 收件人名称 */
    private String receiverName;
    /** 发件人名称 */
    private String senderName;
    /** 开始时间 */
    private Long startTime;
    /** 结束时间 */
    private Long endTime;
    /** 物品类型 */
    private Integer itemType;
    /** 状态 */
    private Integer checked;
    /** 物品ID */
    private Integer itemId;
}
