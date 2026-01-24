package org.gms.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import java.util.List;

@Data
public class SendDueyReqDTO {
    private Long packageId; // 新增：用于更新包裹
    private List<Integer> receiverIds; // 支持多选角色ID
    private String receiverName; // 兼容旧逻辑，支持按名称发送
    private Boolean isAll; // 保留全服选项，作为特殊的多选情况
    private Integer mesos;
    private String message;
    private Integer itemId;
    private Integer quantity;
    private Boolean quick;
    private String senderName;
    private Long expireTime;
    private Integer expireDays;
    private Long deliveryTime;
    
    // 物品属性
    private String owner;
    private Long itemExpiration;

    // 装备自定义属性
    // 使用 Integer 接收以避免反序列化时的范围溢出，并在 Service 层进行截断处理
    private Integer str;
    private Integer dex;
    @JsonProperty("int")
    private Integer int_;
    private Integer luk;
    private Integer hp;
    private Integer mp;
    private Integer watk;
    private Integer matk;
    private Integer wdef;
    private Integer mdef;
    private Integer acc;
    private Integer avoid;
    private Integer hands;
    private Integer speed;
    private Integer jump;
    private Integer upgradeSlots;
    private Integer level;
    private Integer itemLevel;
    private Integer flag;
    private Integer vicious;
}
