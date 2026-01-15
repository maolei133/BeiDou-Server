package org.gms.model.dto;

import lombok.Data;
import java.util.List;

@Data
public class SendDueyReqDTO {
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
    
    // 装备自定义属性
    private Short str;
    private Short dex;
    private Short int_;
    private Short luk;
    private Short hp;
    private Short mp;
    private Short watk;
    private Short matk;
    private Short wdef;
    private Short mdef;
    private Short acc;
    private Short avoid;
    private Short hands;
    private Short speed;
    private Short jump;
    private Byte upgradeSlots;
    private Byte level;
    private Byte itemLevel;
    private Integer flag;
}
