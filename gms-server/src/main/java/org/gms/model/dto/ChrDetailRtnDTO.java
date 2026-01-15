package org.gms.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ChrDetailRtnDTO {
    private Integer id;
    private String name;
    private Integer level;
    private Integer exp;
    private Integer job;
    private String jobName;
    private Integer str;
    private Integer dex;
    private Integer intAttr;
    private Integer luk;
    private Integer hp;
    private Integer maxHp;
    private Integer mp;
    private Integer maxMp;
    private Integer ap;
    private String sp;
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

    // Inventory Slots
    private Integer equipSlots;
    private Integer useSlots;
    private Integer setupSlots;
    private Integer etcSlots;

    // Social
    private Integer buddyCapacity;

    // Assets
    private Integer merchantMesos;
    private Integer gachaExp;

    // Location
    private Integer map;
    private Integer spawnPoint;

    // Mount
    private Integer mountLevel;
    private Integer mountExp;
    private Integer mountTiredness;
}
