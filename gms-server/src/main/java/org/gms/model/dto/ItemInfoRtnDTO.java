package org.gms.model.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class ItemInfoRtnDTO {
    /**
     * 物品ID
     * 根据规范，在返回给前端的JSON中，此字段的键为 "id"。
     */
    @JsonProperty("id")
    private Integer itemId;

    /**
     * 物品数量
     * 根据规范，在返回给前端的JSON中，此字段的键为 "qty"。
     */
    @JsonProperty("qty")
    private Integer quantity;

    @JsonProperty("own")
    private String owner;
    @JsonProperty("exp")
    private Long expiration;
    @JsonProperty("nm")
    private String name;
    @JsonIgnore
    private String desc;
    @JsonProperty("sn")
    private Long sn;
    @JsonProperty("pid")
    private Integer petId;
    
    // 装备属性
    @JsonProperty("s")
    private Short str;
    @JsonProperty("d")
    private Short dex;
    @JsonProperty("i")
    private Short int_;
    @JsonProperty("l")
    private Short luk;
    @JsonProperty("h")
    private Short hp;
    @JsonProperty("m")
    private Short mp;
    @JsonProperty("wa")
    private Short watk;
    @JsonProperty("ma")
    private Short matk;
    @JsonProperty("wd")
    private Short wdef;
    @JsonProperty("md")
    private Short mdef;
    @JsonProperty("ac")
    private Short acc;
    @JsonProperty("av")
    private Short avoid;
    @JsonProperty("hd")
    private Short hands;
    @JsonProperty("sp")
    private Short speed;
    @JsonProperty("jp")
    private Short jump;
    @JsonProperty("us")
    private Integer upgradeSlots;
    @JsonProperty("lv")
    private Short level;
    @JsonProperty("il")
    private Short itemLevel;
    @JsonProperty("f")
    private Short flag;
    @JsonProperty("vc")
    private Short vicious;
}
