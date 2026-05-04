package org.gms.model.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
// 忽略在JSON中存在但在Java对象中不存在的属性，防止因前端发送未知字段而导致解析错误
@JsonIgnoreProperties(ignoreUnknown = true)
public class GiveResourceReqDTO {
    // 恢复默认映射，让Jackson自动处理驼峰命名 (e.g., "playerId" -> playerId)
    private Integer worldId;
    private Integer playerId;
    private String player;
    private Byte type;
    private Integer id;
    private Integer quantity;
    private Float rate;
    private Short str;
    private Short dex;
    @JsonProperty("int")
    private Short _int;
    private Short luk;
    private Short hp;
    private Short mp;
    @JsonProperty("pAtk")
    private Short pAtk;
    @JsonProperty("mAtk")
    private Short mAtk;
    @JsonProperty("pDef")
    private Short pDef;
    @JsonProperty("mDef")
    private Short mDef;
    private Short acc;
    private Short avoid;
    private Short hands;
    private Short speed;
    private Short jump;
    private Byte upgradeSlot;
    private Short level;
    private Short itemLevel;
    private Long expire;
    private String owner;
    private Short flag;
}
