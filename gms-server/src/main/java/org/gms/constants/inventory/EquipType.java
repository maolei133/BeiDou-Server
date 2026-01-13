/*
    This file is part of the HeavenMS MapleStory Server
    Copyleft (L) 2016 - 2019 RonanLana

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation version 3 as published by
    the Free Software Foundation. You may not use, modify or distribute
    this program under any other version of the GNU Affero General Public
    License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package org.gms.constants.inventory;

import java.util.HashMap;
import java.util.Map;

/**
 * @author RonanLana
 */
public enum EquipType {
    UNDEFINED(-1, "未知"),
    ACCESSORY(0, "饰品"),
    CAP(100, "帽子"),
    CAPE(110, "披风"),
    COAT(104, "上衣"),
    FACE(2, "脸型"),
    GLOVES(108, "手套"),
    HAIR(3, "发型"),
    LONGCOAT(105, "套服"),
    PANTS(106, "裤子"),
    PET_EQUIP(180, "宠物装备"),
    PET_EQUIP_FIELD(181, "宠物装备(Field)"),
    PET_EQUIP_LABEL(182, "宠物装备(Label)"),
    PET_EQUIP_QUOTE(183, "宠物装备(Quote)"),
    RING(111, "戒指"),
    SHIELD(109, "盾牌"),
    SHOES(107, "鞋子"),
    TAMING(190, "骑宠"),
    TAMING_SADDLE(191, "骑宠鞍"),
    SWORD(1302, "单手剑"),
    AXE(1312, "单手斧"),
    MACE(1322, "单手钝器"),
    DAGGER(1332, "短刀"),
    WAND(1372, "短杖"),
    STAFF(1382, "长杖"),
    SWORD_2H(1402, "双手剑"),
    AXE_2H(1412, "双手斧"),
    MACE_2H(1422, "双手钝器"),
    SPEAR(1432, "枪"),
    POLEARM(1442, "矛"),
    BOW(1452, "弓"),
    CROSSBOW(1462, "弩"),
    CLAW(1472, "拳套"),
    KNUCKLER(1482, "指虎"),
    PISTOL(1492, "手铳"),
    
    // 饰品细分
    FACE_ACCESSORY(101, "脸饰"),
    EYE_ACCESSORY(102, "眼饰"),
    EARRINGS(103, "耳环"),
    PENDANT(112, "项链"),
    BELT(113, "腰带"),
    MEDAL(114, "勋章"),
    SHOULDER(115, "肩饰");

    private final int i;
    private final String name;
    private static final Map<Integer, EquipType> map = new HashMap(34);

    EquipType(int val, String name) {
        this.i = val;
        this.name = name;
    }

    public int getValue() {
        return i;
    }

    public String getName() {
        return name;
    }

    static {
        for (EquipType eqEnum : EquipType.values()) {
            map.put(eqEnum.i, eqEnum);
        }
    }

    public static EquipType getEquipTypeById(int itemid) {
        EquipType ret;
        int val = itemid / 100000;

        if (val == 13 || val == 14) {
            ret = map.get(itemid / 1000);
        } else {
            ret = map.get(itemid / 10000);
        }

        return (ret != null) ? ret : EquipType.UNDEFINED;
    }
}