/*
	This file is part of the OdinMS Maple Story Server
    Copyright (C) 2008 Patrick Huy <patrick.huy@frz.cc>
		       Matthias Butz <matze@odinms.de>
		       Jan Christian Meyer <vimes@odinms.de>

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
package org.gms.client.status;

public enum MonsterStatus {
    WATK(0x1, "物攻"),
    WDEF(0x2, "物防"),
    NEUTRALISE(0x2, "中和", true),
    PHANTOM_IMPRINT(0x4, "幻影印记", true), // needs testing
    MATK(0x4, "魔攻"),
    MDEF(0x8, "魔防"),
    ACC(0x10, "命中"),
    AVOID(0x20, "回避"),
    SPEED(0x40, "速度"),
    STUN(0x80, "眩晕"),
    FREEZE(0x100, "冰冻"),
    POISON(0x200, "中毒"),
    SEAL(0x400, "封印"),
    SHOWDOWN(0x800, "挑衅"),
    WEAPON_ATTACK_UP(0x1000, "武器攻击提升"),
    WEAPON_DEFENSE_UP(0x2000, "武器防御提升"),
    MAGIC_ATTACK_UP(0x4000, "魔法攻击提升"),
    MAGIC_DEFENSE_UP(0x8000, "魔法防御提升"),
    DOOM(0x10000, "厄运"),
    SHADOW_WEB(0x20000, "影网"),
    WEAPON_IMMUNITY(0x40000, "物理免疫"),
    MAGIC_IMMUNITY(0x80000, "魔法免疫"),
    HARD_SKIN(0x200000, "硬皮"), // just added
    NINJA_AMBUSH(0x400000, "忍术伏击"),
    ELEMENTAL_ATTRIBUTE(0x800000, "元素属性"), // just added
    VENOMOUS_WEAPON(0x1000000, "涂毒"),
    BLIND(0x2000000, "致盲"), // just added
    SEAL_SKILL(0x4000000, "技能封印"),
    INERTMOB(0x10000000, "呆滞"),
    WEAPON_REFLECT(0x20000000, "物理反伤", true),
    MAGIC_REFLECT(0x40000000, "魔法反伤", true);

    private final int i;
    private final String chineseName;
    private final boolean first;

    MonsterStatus(int i, String chineseName) {
        this.i = i;
        this.chineseName = chineseName;
        this.first = false;
    }

    MonsterStatus(int i, String chineseName, boolean first) {
        this.i = i;
        this.chineseName = chineseName;
        this.first = first;
    }

    public boolean isFirst() {
        return first;
    }

    public int getValue() {
        return i;
    }

    public String getChineseName() {
        return chineseName;
    }
}
