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
package org.gms.net.server.channel.handlers;

import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.Skill;
import org.gms.client.SkillFactory;
import org.gms.client.autoban.AutobanFactory;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.WeaponType;
import org.gms.client.status.MonsterStatusEffect;
import org.gms.constants.skills.Outlaw;
import org.gms.net.packet.InPacket;
import org.gms.server.ItemInformationProvider;
import org.gms.server.StatEffect;
import org.gms.server.life.Monster;
import org.gms.server.maps.Summon;
import org.gms.util.PacketCreator;

import java.util.ArrayList;
import java.util.List;

public final class SummonDamageHandler extends AbstractDealDamageHandler {

    public final class SummonAttackEntry {

        private final int monsterOid;
        private final int damage;

        public SummonAttackEntry(int monsterOid, int damage) {
            this.monsterOid = monsterOid;
            this.damage = damage;
        }

        public int getMonsterOid() {
            return monsterOid;
        }

        public int getDamage() {
            return damage;
        }

    }

    @Override
    public void handlePacket(InPacket p, Client c) {
        int oid = p.readInt();
        Character player = c.getPlayer();
        if (!player.isAlive()) {
            return;
        }
        Summon summon = null;
        for (Summon sum : player.getSummonsValues()) {
            if (sum.getObjectId() == oid) {
                summon = sum;
            }
        }
        if (summon == null) {
            return;
        }
        Skill summonSkill = SkillFactory.getSkill(summon.getSkill());
        StatEffect summonEffect = summonSkill.getEffect(summon.getSkillLevel());
        p.skip(4);
        List<SummonAttackEntry> allDamage = new ArrayList<>();
        byte direction = p.readByte();
        int numAttacked = p.readByte();
        p.skip(8); // I failed lol (mob x,y and summon x,y), Thanks Gerald
        for (int x = 0; x < numAttacked; x++) {
            int monsterOid = p.readInt(); // attacked oid
            p.skip(18);
            int damage = p.readInt();
            allDamage.add(new SummonAttackEntry(monsterOid, damage));
        }
        player.getMap().broadcastMessage(player, PacketCreator.summonAttack(player.getId(), summon.getObjectId(), direction, allDamage), summon.getPosition());

        if (player.getMap().isOwnershipRestricted(player)) {
            return;
        }

        boolean isMagicAttack = summonEffect.getWatk() == 0;

        for (SummonAttackEntry attackEntry : allDamage) {
            int damage = attackEntry.getDamage();
            Monster target = player.getMap().getMonsterByOid(attackEntry.getMonsterOid());
            if (target != null) {
                // 构造一个临时的AttackInfo以复用基类方法
                AttackInfo attack = new AttackInfo();
                attack.skill = summon.getSkill();
                attack.skilllevel = summon.getSkillLevel();
                attack.magic = isMagicAttack;

                long baseDamage;
                // 1. 区分并计算基础伤害
                if (isMagicAttack) {
                    // 魔法召唤兽：完全复用玩家的魔法伤害计算流程
                    baseDamage = (long) player.calculateMagicMaxDamage(summonSkill, summon.getSkillLevel());
//                    baseDamage = calculateMagicMaxDamage(player, summonSkill, summon.getSkillLevel()) * 1;
//                    baseDamage = calcMaxDamage(summonEffect, player, isMagicAttack);
//                    baseDamage = Math.max(player.getTotalMagic(), 14) * summonEffect.getMatk() / 100.0;
                } else {
                    // 物理召唤兽：使用玩家的物理面板攻击力
//                    baseDamage = player.calculatePhysicalMaxBaseAttack(player.getTotalWatk());
                    //备用公式：基于文档的物理召唤兽伤害公式
                    baseDamage = (long) ((player.getTotalDex() * 2.5 + player.getTotalStr()) * summonEffect.getWatk() / 100.0);
                }

                // 2. 应用技能百分比、BUFF等通用加成
                baseDamage = applyBullseyeDamage(player, target, attack.skill, baseDamage);
                baseDamage = applySkillSpecificDamageFormula(player, attack, summonSkill, summonEffect, baseDamage);
                baseDamage = applyBuffAndEnergyBarEffects(player, attack, baseDamage);

                // 3. 应用元素克制和充能效果
                baseDamage = applyChargeAndElementalEffects(player, attack, target, baseDamage);

                // 4. 应用防御减伤
//                int mobDef = isMagicAttack ? target.getStats().getMDDamage() : target.getStats().getPDDamage();
//                baseDamage = (long) calculateDamageAfterDefense(baseDamage, target.getStats().getLevel(), player.getLevel(), mobDef);

                // 5. 作弊检测
                if (damage > baseDamage * 1.05) { // 允许5%的浮动误差
                    String alertMessage = String.format(
                            "召唤兽伤害异常. 召唤兽ID: %d, 怪物: %s(OID: %d), 客户端伤害: %d, 服务端最大伤害: %d",
                            summon.getSkill(), target.getStats().getName(), target.getObjectId(), damage, baseDamage
                    );
//                    System.out.println(alertMessage);
                    AutobanFactory.DAMAGE_HACK.alert(player, alertMessage);
                    damage = (int) baseDamage;
                }

                // 6. 应用伤害和状态效果
                if (damage > 0 && summonEffect.getMonsterStati().size() > 0) {
                    if (summonEffect.makeChanceResult()) {
                        target.applyStatus(player, new MonsterStatusEffect(summonEffect.getMonsterStati(), summonSkill, null, false), summonEffect.isPoison(), 4000);
                    }
                }
                player.getMap().damageMonsterBySummon(player, target, damage);
            }
        }

        if (summon.getSkill() == Outlaw.GAVIOTA) {  // thanks Periwinks for noticing Gaviota not cancelling after grenade toss
            player.cancelEffect(summonEffect, false, -1);
        }
    }
    /**
     * 计算召唤兽的最大魔法伤害。
     * <p>
     * 公式: ((魔法力^2 / 1000 + 魔法力) / 30 + 智力 / 200) * 技能攻击力
     *
     * @param skill 技能对象
     * @param skillLevel 技能等级
     * @return 最大魔法伤害
     */
    public double calculateMagicMaxDamage(Character player,Skill skill, int skillLevel) {
        double magic = Math.min(player.getTotalMagic(), 1999);  //应该是召唤兽计算上限没有突破1999，导致客户端最多也只能打15万左右
        double intel = player.getTotalInt();
        double skillAtk = skill.getEffect(skillLevel).getMatk();

        double damage = ((magic * magic / 1000.0) + magic) / 40. + (intel / 200.0);
        return damage * skillAtk;
    }
    /**
     * 计算召唤兽的最大伤害（旧方案，已弃用）
     */
    private static int calcMaxDamage(StatEffect summonEffect, Character player, boolean magic) {
        double maxDamage;

        if (magic) {
            int matk = Math.max(player.getTotalMagic(), 14);
            maxDamage = player.calculateMaxBaseMagicDamage(matk) * (0.05 * summonEffect.getMatk());
        } else {
            int watk = Math.max(player.getTotalWatk(), 14);
            Item weapon_item = player.getInventory(InventoryType.EQUIPPED).getItem((short) -11);

            int maxBaseDmg;  // thanks Conrad, Atoot for detecting some summons legitimately hitting over the calculated limit
            if (weapon_item != null) {
                maxBaseDmg = player.calculateMaxBaseDamage(watk, ItemInformationProvider.getInstance().getWeaponType(weapon_item.getItemId()));
            } else {
                maxBaseDmg = player.calculateMaxBaseDamage(watk, WeaponType.SWORD1H);
            }

            float summonDmgMod = (maxBaseDmg >= 438) ? 0.054f : 0.077f;
            maxDamage = maxBaseDmg * (summonDmgMod * summonEffect.getWatk());
        }

        return (int) maxDamage;
    }
}
