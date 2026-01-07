package org.gms.model.dto;

import lombok.Data;

@Data
public class UpdateCharacterReqDTO {
    private Integer id;
    private String name;
    private Integer level;
    private Integer exp;
    private Integer job;
    private Integer str;
    private Integer dex;
    private Integer intAttr; // 'int' is a keyword
    private Integer luk;
    private Integer hp;
    private Integer maxHp;
    private Integer mp;
    private Integer maxMp;
    private Integer ap;
    private String sp; // SP usually stored as string "1,0,0..." for different job books
    private Integer fame;
    private Integer meso;
    private Integer gm;
    private Integer face;
    private Integer hair;
    private Integer skinColor;
    private Integer gender;

    // Account currencies
    private Integer nxCredit;
    private Integer maplePoint;
    private Integer nxPrepaid;
}
