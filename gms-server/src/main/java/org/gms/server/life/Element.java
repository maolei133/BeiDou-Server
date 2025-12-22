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

public enum Element {
    NEUTRAL(0, "无", 'N'),
    PHYSICAL(1, "物理", 'P'),
    FIRE(2, "火", 'F', true),
    ICE(3, "冰", 'I', true),
    LIGHTING(4, "雷", 'L'),
    POISON(5, "毒", 'S'),
    HOLY(6, "神圣", 'H', true),
    DARKNESS(7, "暗", 'D');

    private final int value;
    private final String chineseName;
    private final char elemChar;
    private boolean special = false;

    Element(int v, String chineseName, char elemChar) {
        this.value = v;
        this.chineseName = chineseName;
        this.elemChar = elemChar;
    }

    Element(int v, String chineseName, char elemChar, boolean special) {
        this.value = v;
        this.chineseName = chineseName;
        this.elemChar = elemChar;
        this.special = special;
    }

    public boolean isSpecial() {
        return special;
    }

    public static Element getFromChar(char c) {
        for (Element e : values()) {
            if (e.elemChar == Character.toUpperCase(c)) {
                return e;
            }
        }
        throw new IllegalArgumentException("unknown element char " + c);
    }

    public int getValue() {
        return value;
    }

    public String getChineseName() {
        return chineseName;
    }

    public char getChar() {
        return elemChar;
    }
}
