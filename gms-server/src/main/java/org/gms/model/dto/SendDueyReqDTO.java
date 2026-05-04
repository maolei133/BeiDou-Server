package org.gms.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import java.util.List;

/**
 * 发送快递请求DTO
 */
@Data
public class SendDueyReqDTO {
    /** 包裹ID */
    private Long packageId; // 新增：用于更新包裹
    /** 收件人ID列表 */
    private List<Integer> receiverIds; // 支持多选角色ID
    /** 收件人名称 */
    private String receiverName; // 兼容旧逻辑，支持按名称发送
    /** 是否全服发送 */
    private Boolean isAll; // 保留全服选项，作为特殊的多选情况
    /** 金币 */
    private Integer mesos;
    /** 留言 */
    private String message;
    /** 是否快速配送 */
    private Boolean quick;
    /** 发件人名称 */
    private String senderName;
    /** 过期时间戳 */
    private Long expireTime;
    /** 过期天数 */
    private Integer expireDays;
    /** 送达时间戳 */
    private Long deliveryTime;

    /** 批量物品列表 */
    private List<DueyItemReqDTO> items;

    // 兼容旧字段（单个物品发送）
    /** 物品ID */
    private Integer itemId;
    /** 数量 */
    private Integer quantity;
    /** 拥有者 */
    private String owner;
    /** 物品过期时间 */
    private Long itemExpiration;
    /** 力量 */
    private Integer str;
    /** 敏捷 */
    private Integer dex;
    /** 智力 */
    @JsonProperty("int")
    private Integer int_;
    /** 运气 */
    private Integer luk;
    /** HP */
    private Integer hp;
    /** MP */
    private Integer mp;
    /** 物理攻击力 */
    private Integer watk;
    /** 魔法攻击力 */
    private Integer matk;
    /** 物理防御力 */
    private Integer wdef;
    /** 魔法防御力 */
    private Integer mdef;
    /** 命中率 */
    private Integer acc;
    /** 回避率 */
    private Integer avoid;
    /** 手技 */
    private Integer hands;
    /** 移动速度 */
    private Integer speed;
    /** 跳跃力 */
    private Integer jump;
    /** 可升级次数 */
    private Integer upgradeSlots;
    /** 强化等级 */
    private Integer level;
    /** 道具等级 */
    private Integer itemLevel;
    /** 物品标识 */
    private Integer flag;
    /** 金锤子次数 */
    private Integer vicious;
}
