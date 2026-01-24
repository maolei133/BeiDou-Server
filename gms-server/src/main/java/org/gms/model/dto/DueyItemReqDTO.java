package org.gms.model.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * 快递物品请求DTO
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class DueyItemReqDTO {
    /** 物品ID */
    private Integer itemId;
    /** 数量 */
    private Integer quantity;
    /** 拥有者 */
    private String owner;
    /** 过期时间 */
    private Long expiration;
    /** 物品名称 */
    private String name; // 前端可能传名称，虽然后端逻辑主要靠ID，但接收一下避免报错

    // Equipment attributes
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
