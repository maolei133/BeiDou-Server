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
    private Integer face;
    private Integer hair;
    private Integer skinColor;
    private Integer gender;
}
