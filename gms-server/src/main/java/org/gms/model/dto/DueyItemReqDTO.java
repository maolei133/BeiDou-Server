package org.gms.model.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class DueyItemReqDTO {
    private Integer itemId;
    private Integer quantity;
    private String owner;
    private Long expiration;
    private String name; // 前端可能传名称，虽然后端逻辑主要靠ID，但接收一下避免报错

    // Equipment attributes
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
