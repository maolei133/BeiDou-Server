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
package org.gms.server.life;

public enum ElementalEffectiveness {
    NORMAL("普通", 0),
    IMMUNE("免疫", 1),
    STRONG("抵抗", 2),
    WEAK("弱点", 3),
    NEUTRAL("中和", 4);

    private final String chineseName;
    private final int value;

    ElementalEffectiveness(String chineseName, int value) {
        this.chineseName = chineseName;
        this.value = value;
    }

    public String getChineseName() {
        return chineseName;
    }

    public int getValue() {
        return value;
    }

    public static ElementalEffectiveness getByNumber(int num) {
        for (ElementalEffectiveness e : values()) {
            if (e.getValue() == num) {
                return e;
            }
        }
        throw new IllegalArgumentException("Unkown effectiveness: " + num);
    }
}
