package org.gms.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ChrOnlineListRtnDTO {
    private int world;
    private int accountId;
    private String accountName;
    private int id;
    private String name;
    private int map;
    private String mapName;
    private int job;
    private String jobName;
    private int level;
    private int gm;
    private int maxHp;
    private int maxMp;
    private String guildName;
    private int guildId;
    private int gender;
    private int partyId;
    private int channel;
    private int fame;
    private String loginTime;
    private String lastLogoutTime;
    private int str;
    private int dex;
    private int intAttr;
    private int luk;
    private int hp;
    private int mp;
    private int ap;
    private String sp;
    private int face;
    private int hair;
    private int skinColor;
    private boolean banned;
}
