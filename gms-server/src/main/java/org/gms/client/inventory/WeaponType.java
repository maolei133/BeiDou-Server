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
package org.gms.client.inventory;

/**
 * 武器类型枚举，定义了不同武器的伤害系数。
 * <p>
 * 支持通过 Setter 方法进行热更新。
 *
 * @author 86157
 * @version 3.3
 * @since 2024/8/3
 */
public enum WeaponType {
    /** 非武器 (0.0, 0.0) */
    NOT_A_WEAPON("非武器", 0.0, 0.0),
    /** 单手斧/单手钝器 (4.2, 4.4) - 挥动 */
    GENERAL1H_SWING("单手斧/单手钝器(挥)", 4.2, 4.4),
    /** 单手剑 (3.0, 3.2) - 刺击 */
    GENERAL1H_STAB("单手剑(刺)", 3.0, 3.2),
    /** 双手斧/双手钝器 (4.6, 4.8) - 挥动 */
    GENERAL2H_SWING("双手斧/双手钝器(挥)", 4.6, 4.8),
    /** 双手剑 (3.2, 3.4) - 刺击 */
    GENERAL2H_STAB("双手剑(刺)", 3.2, 3.4),
    /** 弓 (3.2, 3.4) */
    BOW("弓", 3.2, 3.4),
    /** 拳套 (3.4, 3.6) */
    CLAW("拳套", 3.4, 3.6),
    /** 弩 (3.4, 3.6) */
    CROSSBOW("弩", 3.4, 3.6),
    /** 短刀(飞侠) (3.4, 3.6) */
    DAGGER_THIEVES("短刀(飞侠)", 3.4, 3.6),
    /** 短刀(非飞侠) (3.8, 4.0) */
    DAGGER_OTHER("短刀(非飞侠)", 3.8, 4.0),
    /** 手枪 (3.4, 3.6) */
    GUN("手枪", 3.4, 3.6),
    /** 拳甲 (4.6, 4.8) */
    KNUCKLE("拳甲", 4.6, 4.8),
    /** 枪 (4.8, 5.0) - 挥动 */
    POLE_ARM_SWING("枪(挥)", 4.8, 5.0),
    /** 枪 (2.8, 3.0) - 刺击 */
    POLE_ARM_STAB("枪(刺)", 2.8, 3.0),
    /** 矛 (4.8, 5.0) - 刺击 */
    SPEAR_STAB("矛(刺)", 4.8, 5.0),
    /** 矛 (2.8, 3.0) - 挥动 */
    SPEAR_SWING("矛(挥)", 2.8, 3.0),
    /** 魔杖 (3.4, 3.6) */
    STAFF("魔杖", 3.4, 3.6),
    /** 单手剑 (3.8, 4.0) */
    SWORD1H("单手剑", 3.8, 4.0),
    /** 双手剑 (4.4, 4.6) */
    SWORD2H("双手剑", 4.4, 4.6),
    /** 短杖 (3.4, 3.6) */
    WAND("短杖", 3.4, 3.6);

    /** 武器名称 */
    private final String name;
    /** 最小伤害系数 (非final，支持热更新) */
    private double minDamageMultiplier;
    /** 最大伤害系数 (非final，支持热更新) */
    private double maxDamageMultiplier;

    /**
     * 武器类型构造函数。
     *
     * @param name 武器中文名称
     * @param minDamageMultiplier 最小伤害系数，用于计算角色的最小攻击力。
     * @param maxDamageMultiplier 最大伤害系数，用于计算角色的最大攻击力。
     */
    WeaponType(String name, double minDamageMultiplier, double maxDamageMultiplier) {
        this.name = name;
        this.minDamageMultiplier = minDamageMultiplier;
        this.maxDamageMultiplier = maxDamageMultiplier;
    }

    /**
     * 获取武器名称。
     *
     * @return 武器的中文名称。
     */
    public String getName() {
        return name;
    }

    /**
     * 获取当前武器类型的最小伤害系数。
     *
     * @return 代表最小伤害计算的倍率。
     */
    public double getMinDamageMultiplier() {
        return minDamageMultiplier;
    }

    /**
     * 设置当前武器类型的最小伤害系数。
     * <p>
     * 用于热更新伤害公式参数。
     *
     * @param minDamageMultiplier 新的最小伤害系数
     */
    public void setMinDamageMultiplier(double minDamageMultiplier) {
        this.minDamageMultiplier = minDamageMultiplier;
    }

    /**
     * 获取当前武器类型的最大伤害系数。
     *
     * @return 代表最大伤害计算的倍率。
     */
    public double getMaxDamageMultiplier() {
        return maxDamageMultiplier;
    }

    /**
     * 设置当前武器类型的最大伤害系数。
     * <p>
     * 用于热更新伤害公式参数。
     *
     * @param maxDamageMultiplier 新的最大伤害系数
     */
    public void setMaxDamageMultiplier(double maxDamageMultiplier) {
        this.maxDamageMultiplier = maxDamageMultiplier;
    }
}
