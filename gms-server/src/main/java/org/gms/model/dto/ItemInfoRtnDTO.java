package org.gms.model.dto;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class ItemInfoRtnDTO {
    private Integer itemId;
    private Integer quantity;
    private String owner;
    private Long expiration;
    private String name;
    private String desc;
    private Long sn; // 预留SN码
    
    // 装备属性
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
    private Byte flag;
}
