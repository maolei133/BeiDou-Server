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

import org.gms.client.BuffStat;
import org.gms.client.Character;
import org.gms.client.Job;
import org.gms.client.Skill;
import org.gms.client.SkillFactory;
import org.gms.client.autoban.AutobanFactory;
import org.gms.client.status.MonsterStatus;
import org.gms.client.status.MonsterStatusEffect;
import org.gms.config.GameConfig;
import org.gms.constants.game.GameConstants;
import org.gms.constants.id.ItemId;
import org.gms.constants.id.MapId;
import org.gms.constants.id.MobId;
import org.gms.constants.skills.*;
import org.gms.net.AbstractPacketHandler;
import org.gms.net.packet.InPacket;
import org.gms.net.server.PlayerBuffValueHolder;
import org.gms.scripting.AbstractPlayerInteraction;
import org.gms.server.StatEffect;
import org.gms.server.TimerManager;
import org.gms.server.life.Element;
import org.gms.server.life.ElementalEffectiveness;
import org.gms.server.life.MobSkill;
import org.gms.server.life.MobSkillFactory;
import org.gms.server.life.MobSkillId;
import org.gms.server.life.MobSkillType;
import org.gms.server.life.Monster;
import org.gms.server.life.MonsterDropEntry;
import org.gms.server.life.MonsterInformationProvider;
import org.gms.server.maps.MapItem;
import org.gms.server.maps.MapObject;
import org.gms.server.maps.MapObjectType;
import org.gms.server.maps.MapleMap;
import org.gms.util.PacketCreator;
import org.gms.util.Randomizer;

import java.awt.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * @author kevintjuh93
 * @version 1.5
 * @description 抽象伤害处理类，提供处理玩家攻击伤害的通用逻辑。
 *              此类经过重构，将作弊检测逻辑迁移到 AutobanManager，并使用Map和函数式接口优化了内部的if-else结构，
 *              同时恢复并修正了所有中文注释，并将硬编码ID替换为常量。
 * @since 2024/07/31
 */
public abstract class AbstractDealDamageHandler extends AbstractPacketHandler {

    // 使用函数式接口来定义技能效果的应用逻辑
    @FunctionalInterface
    private interface SkillEffectApplicator {
        void apply(AbstractDealDamageHandler handler, Character player, Monster monster, AttackInfo attack, int attackCount, int totDamage, Skill theSkill, int job, MapleMap map);
    }

    // 使用静态Map来注册和分发技能效果
    private static final Map<Integer, SkillEffectApplicator> SKILL_EFFECT_APPLICATORS = new HashMap<>();

    static {
        // 侠客 - 神通术
        SKILL_EFFECT_APPLICATORS.put(Bandit.STEAL, (h, p, m, atk, ac, td, sk, j, mp) -> h.handleStealSkill(p, m, mp));
        // 火毒 - 火凤球
        SKILL_EFFECT_APPLICATORS.put(FPArchMage.FIRE_DEMON, (h, p, m, atk, ac, td, sk, j, mp) -> {
            long duration = SECONDS.toMillis(SkillFactory.getSkill(FPArchMage.FIRE_DEMON).getEffect(p.getSkillLevel(FPArchMage.FIRE_DEMON)).getDuration());
            m.setTempEffectiveness(Element.ICE, ElementalEffectiveness.WEAK, duration);
        });
        // 冰雷 - 冰凤球
        SKILL_EFFECT_APPLICATORS.put(ILArchMage.ICE_DEMON, (h, p, m, atk, ac, td, sk, j, mp) -> {
            long duration = SECONDS.toMillis(SkillFactory.getSkill(ILArchMage.ICE_DEMON).getEffect(p.getSkillLevel(ILArchMage.ICE_DEMON)).getDuration());
            m.setTempEffectiveness(Element.FIRE, ElementalEffectiveness.WEAK, duration);
        });
        // 海盗（神枪手） - 导航
        SKILL_EFFECT_APPLICATORS.put(Outlaw.HOMING_BEACON, (h, p, m, atk, ac, td, sk, j, mp) -> {
            StatEffect beacon = SkillFactory.getSkill(atk.skill).getEffect(p.getSkillLevel(atk.skill));
            beacon.applyBeaconBuff(p, m.getObjectId());
        });
        // 船长 - 导航辅助
        SKILL_EFFECT_APPLICATORS.put(Corsair.BULLSEYE, (h, p, m, atk, ac, td, sk, j, mp) -> {
            StatEffect beacon = SkillFactory.getSkill(atk.skill).getEffect(p.getSkillLevel(atk.skill));
            beacon.applyBeaconBuff(p, m.getObjectId());
        });
        // 神枪手 - 烈焰喷射
        SKILL_EFFECT_APPLICATORS.put(Outlaw.FLAME_THROWER, (h, p, m, atk, ac, td, sk, j, mp) -> h.handleFlameThrowerSkill(p, m));
    }


    /**
     * @author kevintjuh93
     * @version 1.0
     * @description 攻击信息内部类，用于封装一次攻击的所有相关数据。
     * @since 2024/07/29
     */
    public static class AttackInfo {

        /** 被攻击的怪物数量 */
        public int numAttacked;
        /** 伤害段数 */
        public int numDamage;
        /** 被攻击和伤害信息的组合值，高4位表示被攻击数量，低4位表示伤害段数 */
        public int numAttackedAndDamage;
        /** 技能ID */
        public int skill;
        /** 技能等级 */
        public int skilllevel;
        /** 攻击姿势/动作 */
        public int stance;
        /** 攻击方向 */
        public int direction;
        /** 远程攻击方向 */
        public int rangedirection;
        /** 充能值（用于某些需要蓄力的技能） */
        public int charge;
        /** 技能显示ID（用于动画显示） */
        public int display;
        /** 所有伤害数据映射，键为怪物对象ID，值为对该怪物各段伤害列表 */
        public Map<Integer, List<Integer>> allDamage;
        /** 是否为远程攻击 */
        public boolean ranged;
        /** 是否为魔法攻击 */
        public boolean magic;
        /** 攻击速度 */
        public int speed = 4;
        /** 攻击位置坐标 */
        public Point position = new Point();

        /**
         * @param chr 角色对象
         * @param theSkill 技能对象
         * @return 技能效果对象
         * @description 获取攻击技能的效果。
         */
        public StatEffect getAttackEffect(Character chr, Skill theSkill) {
            Skill mySkill = theSkill;
            if (mySkill == null) {
                mySkill = SkillFactory.getSkill(skill);
            }

            int skillLevel = chr.getSkillLevel(mySkill);
            if (skillLevel == 0 && GameConstants.isPqSkillMap(chr.getMapId()) && GameConstants.isPqSkill(mySkill.getId())) {
                skillLevel = 1;
            }

            if (skillLevel == 0) {
                return null;
            }
            // WZ编辑；为技能添加动作检测
            if (chr.getAutoBanManager().useAntiCheat() && display > 80) {
                if (!mySkill.getAction()) {
                    AutobanFactory.FAST_ATTACK.autoban(chr, "WZ编辑；为技能添加动作：" + display);
                    return null;
                }
            }
            return mySkill.getEffect(skillLevel);
        }
    }

    /**
     * @param attack 攻击信息
     * @param player 玩家角色
     * @param attackCount 攻击次数
     * @description 应用攻击伤害到怪物。
     */
    protected void applyAttack(AttackInfo attack, final Character player, int attackCount) {
        int mobCount = 1;
        final MapleMap map = player.getMap();
        if (map.isOwnershipRestricted(player)) {
            return;
        }

        Skill theSkill = null;
        StatEffect attackEffect = null;
        final int job = player.getJob().getId();
        try {
            if (player.isBanned()) {
                return;
            }
            if (attack.skill != 0) {
                theSkill = SkillFactory.getSkill(attack.skill);
                attackEffect = attack.getAttackEffect(player, theSkill);
                if (attackEffect == null) {
                    player.sendPacket(PacketCreator.enableActions());
                    return;
                }

                // 作弊检测：MP消耗
                if (player.getAutoBanManager().checkMpCon(attackEffect, attack.skill, attack.skilllevel)) {
                    player.sendPacket(PacketCreator.enableActions());
                    return;
                }

                mobCount = attackEffect.getMobCount();
                if (attack.skill != Cleric.HEAL) {
                    if (player.isAlive()) {
                        // 特殊技能处理，不应用效果或修改怪物数量
                        if (attack.skill == Aran.BODY_PRESSURE || attack.skill == Marauder.ENERGY_CHARGE || attack.skill == ThunderBreaker.ENERGY_CHARGE) {
                            // 防止触碰伤害技能刷新
                        } else if (attack.skill == DawnWarrior.FINAL_ATTACK || attack.skill == WindArcher.FINAL_ATTACK) {
                            // 防止席格诺斯最终攻击技能刷新
                            mobCount = 15;
                        } else if (attack.skill == NightWalker.POISON_BOMB) { // 奇袭者 - 毒炸弹
                            attackEffect.applyTo(player, new Point(attack.position.x, attack.position.y));
                        } else {
                            attackEffect.applyTo(player);

                            if (attack.skill == Page.FINAL_ATTACK_BW || attack.skill == Page.FINAL_ATTACK_SWORD || attack.skill == Fighter.FINAL_ATTACK_SWORD
                                    || attack.skill == Fighter.FINAL_ATTACK_AXE || attack.skill == Spearman.FINAL_ATTACK_SPEAR || attack.skill == Spearman.FINAL_ATTACK_POLEARM
                                    || attack.skill == Hunter.FINAL_ATTACK || attack.skill == Crossbowman.FINAL_ATTACK) {
                                mobCount = 15;
                            } else if (attack.skill == Aran.HIDDEN_FULL_DOUBLE || attack.skill == Aran.HIDDEN_FULL_TRIPLE || attack.skill == Aran.HIDDEN_OVER_DOUBLE || attack.skill == Aran.HIDDEN_OVER_TRIPLE) {
                                mobCount = 12;
                            }
                        }
                    } else {
                        player.sendPacket(PacketCreator.enableActions());
                    }
                }

                // 作弊检测：攻击怪物数量
                if (player.getAutoBanManager().checkMobCount(attackEffect, attack.numAttacked, attack.skill, attack.skilllevel)) {
                    return;
                }
            }
            if (!player.isAlive()) {
                return;
            }

            //WTF IS THIS F3,1
            /*if (attackCount != attack.numDamage && attack.skill != ChiefBandit.MESO_EXPLOSION && attack.skill != NightWalker.VAMPIRE && attack.skill != WindArcher.WIND_SHOT && attack.skill != Aran.COMBO_SMASH && attack.skill != Aran.COMBO_FENRIR && attack.skill != Aran.COMBO_TEMPEST && attack.skill != NightLord.NINJA_AMBUSH && attack.skill != Shadower.NINJA_AMBUSH) {
                return;
            }*/

            // 根据配置决定使用技能最大目标数还是实际伤害目标数
            int targetCount = GameConfig.getServerBoolean("use_skill_max_target_count") ? mobCount : attack.allDamage.size();

            // 处理金钱炸弹技能
            if (attack.skill == ChiefBandit.MESO_EXPLOSION) { // 侠盗 - 金钱炸弹
                handleMesoExplosion(attack, map);
                return;
            }

            for (Integer oned : attack.allDamage.keySet()) {
                final Monster monster = map.getMonsterByOid(oned);
                if (monster != null) {
                    // 作弊检测：吸怪
                    if (player.getAutoBanManager().detectMonsterVac(monster)) {
                        continue;
                    }

                    // 作弊检测：攻击距离
                    if (player.getAutoBanManager().checkDistanceHack(monster, attack)) {
                        continue;
                    }

                    int totDamageToOneMonster = 0;
                    List<Integer> onedList = attack.allDamage.get(oned);

                    // 处理怪物免疫状态
                    handleMonsterImmunity(monster, attack, onedList);

                    // 处理武陵道场Boss伤害限制
                    if (MobId.isDojoBoss(monster.getId())) {
                        handleDojoBossDamageLimit(attack, monster, onedList);
                    }

                    for (Integer eachd : onedList) {
                        if (eachd < 0) {
                            eachd += Integer.MAX_VALUE;
                        }
                        totDamageToOneMonster += eachd;
                    }
                    monster.aggroMonsterDamage(player, totDamageToOneMonster);

                    // 应用各种技能效果（偷窃、吸血、元素效果等）
                    applySkillEffects(player, monster, attack, attackCount, totDamageToOneMonster, theSkill, job, map);

                    // 作弊检测：固定伤害
                    if (attack.skill != 0 && attackEffect != null) {
                        if (player.getAutoBanManager().checkFixedDamage(totDamageToOneMonster, attackEffect, attack.skill, attack.skilllevel, monster)) {
                            return;
                        }
                    }

                    // 应用怪物状态效果
                    if (totDamageToOneMonster > 0 && attackEffect != null) {
                        applyMonsterStatusEffects(monster, player, attackEffect, theSkill);
                    }

                    // 在伤害应用前更新怪物最后受到的技能ID和技能目标数，避免怪物被秒杀导致无法正确设置
                    monster.setLastSkillId(attack.skill);
                    monster.setLastSkillTargetCount(targetCount);

                    // 实际造成伤害
                    dealFinalDamage(player, map, monster, attack, totDamageToOneMonster);

                    // 处理怪物反伤
                    handleMonsterReflect(player, map, monster, attack);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * @param p 输入包
     * @param chr 角色对象
     * @param ranged 是否为远程攻击
     * @param magic 是否为魔法攻击
     * @return 攻击信息对象
     * @description 解析客户端发送的伤害数据包，并进行初步的作弊检测。
     */
    protected AttackInfo parseDamage(InPacket p, Character chr, boolean ranged, boolean magic) {
        boolean shadowPartner = chr.getBuffEffect(BuffStat.SHADOWPARTNER) != null;
        AttackInfo ret = new AttackInfo();
        p.readByte(); // 总是为1，作用未知
        ret.numAttackedAndDamage = p.readByte();
        ret.numAttacked = (ret.numAttackedAndDamage >>> 4) & 0xF;
        ret.numDamage = ret.numAttackedAndDamage & 0xF;
        ret.allDamage = new HashMap<>();
        ret.skill = p.readInt();
        ret.ranged = ranged;
        ret.magic = magic;

        if (ret.skill > 0) {
            ret.skilllevel = chr.getSkillLevel(ret.skill);
            if (ret.skilllevel == 0 && GameConstants.isPqSkillMap(chr.getMapId()) && GameConstants.isPqSkill(ret.skill)) {
                ret.skilllevel = 1;
            }
        }

        // 作弊检测：快速攻击
        if (chr.getAutoBanManager().Detection_FastAttack(ret.skill, ret.skilllevel)) {
            return null;
        }

        // 读取充能值
        if (ret.skill == Evan.ICE_BREATH || ret.skill == Evan.FIRE_BREATH || ret.skill == FPArchMage.BIG_BANG || ret.skill == ILArchMage.BIG_BANG || ret.skill == Bishop.BIG_BANG || ret.skill == Gunslinger.GRENADE || ret.skill == Brawler.CORKSCREW_BLOW || ret.skill == ThunderBreaker.CORKSCREW_BLOW || ret.skill == NightWalker.POISON_BOMB) {
            ret.charge = p.readInt();
        } else {
            ret.charge = 0;
        }

        p.skip(8);
        ret.display = p.readByte();
        ret.direction = p.readByte();
        ret.stance = p.readByte();

        // 处理金钱炸弹技能的特殊解析
        if (ret.skill == ChiefBandit.MESO_EXPLOSION) { // 侠盗 - 金钱炸弹
            return parseMesoExplosionDamage(p, ret);
        }

        // 读取攻击速度和方向
        if (ranged) {
            p.readByte();
            ret.speed = p.readByte();
            p.readByte();
            ret.rangedirection = p.readByte();
            p.skip(7);
            if (ret.skill == Bowmaster.HURRICANE || ret.skill == Marksman.PIERCING_ARROW || ret.skill == Corsair.RAPID_FIRE || ret.skill == WindArcher.HURRICANE) {
                p.skip(4);
            }
        } else {
            p.readByte();
            ret.speed = p.readByte();
            p.skip(4);
        }

        // 计算最大伤害
        long calcDmgMax = calculateMaxDamage(chr, ret);

        StatEffect effect = null;
        if (ret.skill != 0) {
            Skill skill = SkillFactory.getSkill(ret.skill);
            effect = skill.getEffect(ret.skilllevel);
            calcDmgMax = applySkillSpecificDamageFormula(chr, ret, skill, effect, calcDmgMax);
        }

        // 应用Buff和能量条效果
        calcDmgMax = applyBuffAndEnergyBarEffects(chr, ret, calcDmgMax);

        boolean canCrit = chr.getJob().isA((Job.BOWMAN)) || chr.getJob().isA(Job.THIEF) || chr.getJob().isA(Job.NIGHTWALKER1) || chr.getJob().isA(Job.WINDARCHER1) || chr.getJob() == Job.ARAN3 || chr.getJob() == Job.ARAN4 || chr.getJob() == Job.MARAUDER || chr.getJob() == Job.BUCCANEER;
        StatEffect sharpEyesEffect = chr.getBuffEffect(BuffStat.SHARP_EYES);
        if (sharpEyesEffect != null) {
            canCrit = true;
            calcDmgMax = (long) Math.ceil(sharpEyesEffect.getY() / 100.0 * calcDmgMax);
        }

        if (ret.skill != 0) {
            int fixed = ret.getAttackEffect(chr, SkillFactory.getSkill(ret.skill)).getFixDamage();
            if (fixed > 0) {
                calcDmgMax = fixed;
            }
        }

        for (int i = 0; i < ret.numAttacked; i++) {
            int oid = p.readInt();
            p.skip(14);
            List<Integer> allDamageNumbers = new ArrayList<>();
            Monster monster = chr.getMap().getMonsterByOid(oid);

            long currentCalcDmgMax = applyChargeAndElementalEffects(chr, ret, monster, calcDmgMax);

            int maxattack = ret.numDamage;
            // 作弊检测：伤害段数
            if (chr.getAutoBanManager().useAntiCheat() && effect != null) {
                maxattack = Math.max(effect.getBulletCount(), effect.getAttackCount());
                if (shadowPartner) {
                    maxattack = maxattack * 2;
                }
                ret.numDamage = chr.getAutoBanManager().checkDamageSegmentsHack(ret.numDamage, maxattack, ret.skill, ret.skilllevel, monster);
            }

            for (int j = 0; j < ret.numDamage; j++) {
                long damage = (long) p.readInt();
                long hitDmgMax = currentCalcDmgMax;

                // 处理影分身和特殊技能的伤害修正
                hitDmgMax = applyDamageModifiers(ret, j, shadowPartner, hitDmgMax);

                // 作弊检测：伤害值
                damage = chr.getAutoBanManager().checkDamageHack(damage, hitDmgMax * (canCrit ? 2 : 1), ret.skill, ret.skilllevel, monster);

                if (ret.skill == Marksman.SNIPE || (canCrit && damage > hitDmgMax)) {
                    // 如果技能是暴击，则反转伤害值以使其在客户端上正确显示。
                    damage = -Integer.MAX_VALUE + damage - 1;
                }
                allDamageNumbers.add((int) damage);
            }
            if (ret.skill != Corsair.RAPID_FIRE || ret.skill != Aran.HIDDEN_FULL_DOUBLE || ret.skill != Aran.HIDDEN_FULL_TRIPLE || ret.skill != Aran.HIDDEN_OVER_DOUBLE || ret.skill != Aran.HIDDEN_OVER_TRIPLE) {
                p.skip(4);
            }
            ret.allDamage.put(oid, allDamageNumbers);
        }
        if (ret.skill == NightWalker.POISON_BOMB) { // 奇袭者 - 毒炸弹
            p.skip(4);
            ret.position.setLocation(p.readShort(), p.readShort());
        }
        return ret;
    }

    // ==================================================
    // ============== 私有辅助方法 ======================
    // ==================================================

    /**
     * @param l 最小值
     * @param u 最大值
     * @return 随机整数
     * @description 生成一个指定范围内的随机整数。
     */
    private static int rand(int l, int u) {
        return (int) ((Math.random() * (u - l + 1)) + l);
    }

    /**
     * @param attack 攻击信息
     * @param map 地图对象
     * @description 处理金钱炸弹技能的逻辑。
     */
    private void handleMesoExplosion(AttackInfo attack, final MapleMap map) {
        int delay = 0;
        for (Integer oned : attack.allDamage.keySet()) {
            MapObject mapobject = map.getMapObject(oned);
            if (mapobject != null && mapobject.getType() == MapObjectType.ITEM) {
                final MapItem mapitem = (MapItem) mapobject;
                if (mapitem.getMeso() == 0) {
                    return;
                }

                mapitem.lockItem();
                try {
                    if (mapitem.isPickedUp()) {
                        return;
                    }
                    TimerManager.getInstance().schedule(() -> {
                        mapitem.lockItem();
                        try {
                            if (mapitem.isPickedUp()) {
                                return;
                            }
                            map.pickItemDrop(PacketCreator.removeItemFromMap(mapitem.getObjectId(), 4, 0), mapitem);
                        } finally {
                            mapitem.unlockItem();
                        }
                    }, delay);
                    delay += 100;
                } finally {
                    mapitem.unlockItem();
                }
            } else if (mapobject != null && mapobject.getType() != MapObjectType.MONSTER) {
                return;
            }
        }
    }

    /**
     * @param monster 怪物对象
     * @param attack 攻击信息
     * @param onedList 伤害列表
     * @description 处理怪物免疫状态（魔法免疫或武器免疫）。
     */
    private void handleMonsterImmunity(Monster monster, AttackInfo attack, List<Integer> onedList) {
        if (attack.magic) {
            if (monster.isBuffed(MonsterStatus.MAGIC_IMMUNITY)) {
                Collections.fill(onedList, 1);
            }
        } else {
            if (monster.isBuffed(MonsterStatus.WEAPON_IMMUNITY)) {
                Collections.fill(onedList, 1);
            }
        }
    }

    /**
     * @param attack 攻击信息
     * @param monster 怪物对象
     * @param onedList 伤害列表
     * @description 处理武陵道场Boss的伤害限制。
     */
    private void handleDojoBossDamageLimit(AttackInfo attack, Monster monster, List<Integer> onedList) {
        if (attack.skill == Beginner.BAMBOO_RAIN || attack.skill == Noblesse.BAMBOO_RAIN || attack.skill == Legend.BAMBOO_THRUST) {
            int dmgLimit = (int) Math.ceil(0.3 * monster.getMaxHp());
            List<Integer> _onedList = new LinkedList<>();
            for (Integer i : onedList) {
                _onedList.add(Math.min(i, dmgLimit));
            }
            onedList.clear();
            onedList.addAll(_onedList);
        }
    }

    /**
     * @param player 玩家角色
     * @param monster 怪物对象
     * @param attack 攻击信息
     * @param attackCount 攻击次数
     * @param totDamageToOneMonster 对单个怪物的总伤害
     * @param theSkill 技能对象
     * @param job 玩家职业ID
     * @param map 地图对象
     * @description 应用各种技能效果，如偷窃、吸血、元素效果等。
     */
    private void applySkillEffects(Character player, Monster monster, AttackInfo attack, int attackCount, int totDamageToOneMonster, Skill theSkill, int job, MapleMap map) {
        // 优先处理需要覆盖或特殊判断的逻辑
        if (player.getBuffedValue(BuffStat.PICKPOCKET) != null && (attack.skill == 0 || attack.skill == Rogue.DOUBLE_STAB || attack.skill == Bandit.SAVAGE_BLOW || attack.skill == ChiefBandit.ASSAULTER || attack.skill == ChiefBandit.BAND_OF_THIEVES || attack.skill == Shadower.ASSASSINATE || attack.skill == Shadower.TAUNT || attack.skill == Shadower.BOOMERANG_STEP)) {
            handlePickpocket(player, monster, attack, map);// 敛财术
        } else if (attack.skill == Marauder.ENERGY_DRAIN || attack.skill == ThunderBreaker.ENERGY_DRAIN || attack.skill == NightWalker.VAMPIRE || attack.skill == Assassin.DRAIN) {
            // 吸血技能
            player.addHP(Math.min(monster.getMaxHp(), Math.min((int) ((double) totDamageToOneMonster * (double) SkillFactory.getSkill(attack.skill).getEffect(player.getSkillLevel(SkillFactory.getSkill(attack.skill))).getX() / 100.0), player.getCurrentMaxHp() / 2)));
        } else {
            // 使用Map分发处理单一、独立的技能效果
            SkillEffectApplicator applicator = SKILL_EFFECT_APPLICATORS.get(attack.skill);
            if (applicator != null) {
                applicator.apply(this, player, monster, attack, attackCount, totDamageToOneMonster, theSkill, job, map);
            }
        }

        // 处理基于Buff或职业的通用效果
        if (player.isAran()) {
            handleAranSnowCharge(player, monster, totDamageToOneMonster);// 战神雪球冲刺
        }
        if (player.getBuffedValue(BuffStat.HAMSTRING) != null) {
            handleHamstring(player, monster);// 弓箭手腿部束缚
        }
        if (player.getBuffedValue(BuffStat.SLOW) != null) {
            handleEvanSlow(player, monster);// 龙神缓慢
        }
        if (player.getBuffedValue(BuffStat.BLIND) != null) {
            handleMarksmanBlind(player, monster);// 弩手致盲
        }
        if (job == Job.WHITEKNIGHT.getId() || job == Job.PALADIN.getId()) {
            handleKnightChargeSkills(player, monster, totDamageToOneMonster, job);// 骑士团充能技能
        } else if (player.getBuffedValue(BuffStat.COMBO_DRAIN) != null) {
            handleAranComboDrain(player, totDamageToOneMonster);// 战神连环吸血
        } else if (job == Job.SHADOWER.getId() || job == Job.NIGHTWALKER3.getId()) { // Dual Blader在v83中没有毒液技能
            handleVenomSkills(player, monster, attackCount);// 毒液技能（夜行者、侠盗）
        } else if (player.getJob().isA(Job.BOWMAN) && job >= Job.RANGER.getId() && job <= Job.SNIPER.getId()) {
            handleMortalBlowSkills(player, monster, map);// 致命一击（神射手、箭神）
        }
    }

    /**
     * @param player 玩家角色
     * @param monster 怪物对象
     * @param attack 攻击信息
     * @param map 地图对象
     * @description 处理敛财术技能（Pickpocket）的逻辑。
     */
    private void handlePickpocket(Character player, Monster monster, AttackInfo attack, MapleMap map) {
        Skill pickpocket = SkillFactory.getSkill(ChiefBandit.PICKPOCKET); // 侠盗 - 敛财术
        int picklv = (player.isGM()) ? pickpocket.getMaxLevel() : player.getSkillLevel(pickpocket);
        if (picklv > 0) {
            int delay = 0;
            final int maxmeso = player.getBuffedValue(BuffStat.PICKPOCKET);
            List<Integer> onedList = attack.allDamage.get(monster.getObjectId());
            for (Integer eachd : onedList) {
                eachd += Integer.MAX_VALUE;

                if (pickpocket.getEffect(picklv).makeChanceResult()) {
                    final int eachdf;
                    if (eachd < 0) {
                        eachdf = eachd + Integer.MAX_VALUE;
                    } else {
                        eachdf = eachd;
                    }

                    TimerManager.getInstance().schedule(() -> map.spawnMesoDrop(Math.min((int) Math.max(((double) eachdf / (double) 20000) * (double) maxmeso, 1), maxmeso), new Point((int) (monster.getPosition().getX() + Randomizer.nextInt(100) - 50), (int) (monster.getPosition().getY())), monster, player, true, (byte) 2), delay);
                    delay += 100;
                }
            }
        }
    }

    /**
     * @param player 玩家角色
     * @param monster 怪物对象
     * @param map 地图对象
     * @description 处理神通术（Steal）技能的逻辑。
     */
    private void handleStealSkill(Character player, Monster monster, MapleMap map) {
        Skill steal = SkillFactory.getSkill(Bandit.STEAL); // 飞侠 - 神通术
        if (monster.getStolen().isEmpty()) { // 每个怪物只能被偷取一次
            if (steal.getEffect(player.getSkillLevel(steal)).makeChanceResult()) {
                monster.addStolen(0);

                MonsterInformationProvider mi = MonsterInformationProvider.getInstance();
                List<Integer> dropPool = mi.retrieveDropPool(monster.getId());
                if (dropPool != null && !dropPool.isEmpty()) {
                    int rndPool = (int) Math.floor(Math.random() * dropPool.get(dropPool.size() - 1));

                    int i = 0;
                    while (rndPool >= dropPool.get(i)) {
                        i++;
                    }

                    List<MonsterDropEntry> toSteal = new ArrayList<>();
                    toSteal.add(mi.retrieveDrop(monster.getId()).get(i));

                    map.dropItemsFromMonster(toSteal, player, monster);
                    monster.addStolen(toSteal.get(0).itemId);
                }
            }
        }
    }

    /**
     * @param player 玩家角色
     * @param monster 怪物对象
     * @description 处理火焰喷射器（Flame Thrower）技能的逻辑。
     */
    private void handleFlameThrowerSkill(Character player, Monster monster) {
        if (!monster.isBoss()) {
            Skill type = SkillFactory.getSkill(Outlaw.FLAME_THROWER); // 侠盗 - 火焰喷射器
            if (player.getSkillLevel(type) > 0) {
                StatEffect DoT = type.getEffect(player.getSkillLevel(type));
                MonsterStatusEffect monsterStatusEffect = new MonsterStatusEffect(Collections.singletonMap(MonsterStatus.POISON, 1), type, null, false);
                monster.applyStatus(player, monsterStatusEffect, true, DoT.getDuration(), false);
            }
        }
    }

    /**
     * @param player 玩家角色
     * @param monster 怪物对象
     * @param totDamageToOneMonster 对单个怪物的总伤害
     * @description 处理战神雪花连击（Aran Snow Charge）技能的逻辑。
     */
    private void handleAranSnowCharge(Character player, Monster monster, int totDamageToOneMonster) {
        if (player.getBuffedValue(BuffStat.WK_CHARGE) != null) {
            Skill snowCharge = SkillFactory.getSkill(Aran.SNOW_CHARGE); // 战神 - 雪花连击
            if (totDamageToOneMonster > 0) {
                MonsterStatusEffect monsterStatusEffect = new MonsterStatusEffect(Collections.singletonMap(MonsterStatus.SPEED, snowCharge.getEffect(player.getSkillLevel(snowCharge)).getX()), snowCharge, null, false);
                long duration = SECONDS.toMillis(snowCharge.getEffect(player.getSkillLevel(snowCharge)).getY());
                monster.applyStatus(player, monsterStatusEffect, false, duration);
            }
        }
    }

    /**
     * @param player 玩家角色
     * @param monster 怪物对象
     * @description 处理弓箭手腿部束缚（Hamstring）技能的逻辑。
     */
    private void handleHamstring(Character player, Monster monster) {
        Skill hamstring = SkillFactory.getSkill(Bowmaster.HAMSTRING); // 箭神 - 腿部束缚
        if (hamstring.getEffect(player.getSkillLevel(hamstring)).makeChanceResult()) {
            MonsterStatusEffect monsterStatusEffect = new MonsterStatusEffect(Collections.singletonMap(MonsterStatus.SPEED, hamstring.getEffect(player.getSkillLevel(hamstring)).getX()), hamstring, null, false);
            long duration = SECONDS.toMillis(hamstring.getEffect(player.getSkillLevel(hamstring)).getY());
            monster.applyStatus(player, monsterStatusEffect, false, duration);
        }
    }

    /**
     * @param player 玩家角色
     * @param monster 怪物对象
     * @description 处理龙神缓慢（Evan Slow）技能的逻辑。
     */
    private void handleEvanSlow(Character player, Monster monster) {
        Skill slow = SkillFactory.getSkill(Evan.SLOW); // 龙神 - 缓慢
        if (slow.getEffect(player.getSkillLevel(slow)).makeChanceResult()) {
            MonsterStatusEffect monsterStatusEffect = new MonsterStatusEffect(Collections.singletonMap(MonsterStatus.SPEED, slow.getEffect(player.getSkillLevel(slow)).getX()), slow, null, false);
            long duration = MINUTES.toMillis(slow.getEffect(player.getSkillLevel(slow)).getY());
            monster.applyStatus(player, monsterStatusEffect, false, duration);
        }
    }

    /**
     * @param player 玩家角色
     * @param monster 怪物对象
     * @description 处理弩手致盲（Marksman Blind）技能的逻辑。
     */
    private void handleMarksmanBlind(Character player, Monster monster) {
        Skill blind = SkillFactory.getSkill(Marksman.BLIND); // 神射手 - 致盲
        if (blind.getEffect(player.getSkillLevel(blind)).makeChanceResult()) {
            MonsterStatusEffect monsterStatusEffect = new MonsterStatusEffect(Collections.singletonMap(MonsterStatus.ACC, blind.getEffect(player.getSkillLevel(blind)).getX()), blind, null, false);
            long duration = SECONDS.toMillis(blind.getEffect(player.getSkillLevel(blind)).getY());
            monster.applyStatus(player, monsterStatusEffect, false, duration);
        }
    }

    /**
     * @param player 玩家角色
     * @param monster 怪物对象
     * @param totDamageToOneMonster 对单个怪物的总伤害
     * @param job 玩家职业ID
     * @description 处理骑士团充能技能的逻辑。
     */
    private void handleKnightChargeSkills(Character player, Monster monster, int totDamageToOneMonster, int job) {
        for (int charge = WhiteKnight.SWORD_ICE_CHARGE; charge < WhiteKnight.SWORD_LIT_CHARGE; charge++) {
            Skill chargeSkill = SkillFactory.getSkill(charge);
            if (player.isBuffFrom(BuffStat.WK_CHARGE, chargeSkill)) {
                if (totDamageToOneMonster > 0) {
                    if (charge == WhiteKnight.BW_ICE_CHARGE || charge == WhiteKnight.SWORD_ICE_CHARGE) { // 准骑士 - 冰/剑冰属性
                        monster.setTempEffectiveness(Element.ICE, ElementalEffectiveness.WEAK, chargeSkill.getEffect(player.getSkillLevel(chargeSkill)).getY() * 1000);
                        // 修复冰技能不冰怪的问题，关键是冰和火都没有对应的异常状态，对应的异常只有冻结。如果这里把ICE改了，那火怎么办？所以，还是先注释掉。
                        // MonsterStatusEffect monsterStatusEffect = new MonsterStatusEffect(Collections.singletonMap(MonsterStatus.FREEZE, chargeSkill.getEffect(player.getSkillLevel(chargeSkill)).getX()), chargeSkill, null, false);
                        // long duration = SECONDS.toMillis(chargeSkill.getEffect(player.getSkillLevel(chargeSkill)).getY());
                        // monster.applyStatus(player, monsterStatusEffect, false, duration);
                        break;
                    }
                    if (charge == WhiteKnight.BW_FIRE_CHARGE || charge == WhiteKnight.SWORD_FIRE_CHARGE) { // 准骑士 - 火/剑火属性
                        monster.setTempEffectiveness(Element.FIRE, ElementalEffectiveness.WEAK, chargeSkill.getEffect(player.getSkillLevel(chargeSkill)).getY() * 1000);
                        break;
                    }
                }
            }
        }
        if (job == Job.PALADIN.getId()) { // 圣骑士
            for (int charge = Paladin.SWORD_HOLY_CHARGE; charge < Paladin.BW_HOLY_CHARGE; charge++) {
                Skill chargeSkill = SkillFactory.getSkill(charge);
                if (player.isBuffFrom(BuffStat.WK_CHARGE, chargeSkill)) {
                    if (totDamageToOneMonster > 0) {
                        monster.setTempEffectiveness(Element.HOLY, ElementalEffectiveness.WEAK, chargeSkill.getEffect(player.getSkillLevel(chargeSkill)).getY() * 1000);
                        break;
                    }
                }
            }
        }
    }

    /**
     * @param player 玩家角色
     * @param totDamageToOneMonster 对单个怪物的总伤害
     * @description 处理战神连环吸血（Aran Combo Drain）技能的逻辑。
     */
    private void handleAranComboDrain(Character player, int totDamageToOneMonster) {
        Skill skill = SkillFactory.getSkill(Aran.COMBO_DRAIN); // 战神 - 连环吸血
        player.addHP(((totDamageToOneMonster * skill.getEffect(player.getSkillLevel(skill)).getX()) / 100));
    }

    /**
     * @param player 玩家角色
     * @param monster 怪物对象
     * @param attackCount 攻击次数
     * @description 处理毒液技能（Venom Skills）的逻辑。
     */
    private void handleVenomSkills(Character player, Monster monster, int attackCount) {
        int skillId = 0;
        int jobId = player.getJob().getId();
        if (jobId == Job.SHADOWER.getId()) {
            skillId = Shadower.VENOMOUS_STAB;
        } else if (jobId == Job.NIGHTWALKER3.getId()) {
            skillId = NightWalker.VENOM;
        } else if (jobId == Job.CHIEFBANDIT.getId()) {
            // Chief Bandit doesn't have a specific venom skill, it's a passive in Shadower
        }

        if (skillId != 0) {
            Skill type = SkillFactory.getSkill(skillId);
            if (player.getSkillLevel(type) > 0) {
                StatEffect venomEffect = type.getEffect(player.getSkillLevel(type));
                for (int i = 0; i < attackCount; i++) {
                    if (venomEffect.makeChanceResult()) {
                        if (monster.getVenomMulti() < 3) {
                            monster.setVenomMulti((monster.getVenomMulti() + 1));
                            MonsterStatusEffect monsterStatusEffect = new MonsterStatusEffect(Collections.singletonMap(MonsterStatus.POISON, 1), type, null, false);
                            monster.applyStatus(player, monsterStatusEffect, false, venomEffect.getDuration(), true);
                        }
                    }
                }
            }
        }
    }

    /**
     * @param player 玩家角色
     * @param monster 怪物对象
     * @param map 地图对象
     * @description 处理致命一击（Mortal Blow）技能的逻辑。
     */
    private void handleMortalBlowSkills(Character player, Monster monster, MapleMap map) {
        if (!monster.isBoss()) {
            Skill mortalBlow;
            int jobId = player.getJob().getId();
            if (jobId == Job.RANGER.getId() || jobId == Job.HUNTER.getId()) { // 游侠, 猎人
                mortalBlow = SkillFactory.getSkill(Ranger.MORTAL_BLOW);
            } else { // 箭神, 弩手
                mortalBlow = SkillFactory.getSkill(Sniper.MORTAL_BLOW);
            }

            int skillLevel = player.getSkillLevel(mortalBlow);
            if (skillLevel > 0) {
                StatEffect mortal = mortalBlow.getEffect(skillLevel);
                if (monster.getHp() <= (monster.getStats().getHp() * mortal.getX()) / 100) {
                    if (Randomizer.rand(1, 100) <= mortal.getY()) {
                        map.damageMonster(player, monster, Integer.MAX_VALUE);
                    }
                }
            }
        }
    }

    /**
     * @param monster 怪物对象
     * @param player 玩家角色
     * @param attackEffect 攻击效果
     * @param theSkill 技能对象
     * @description 应用怪物状态效果。
     */
    private void applyMonsterStatusEffects(Monster monster, Character player, StatEffect attackEffect, Skill theSkill) {
        Map<MonsterStatus, Integer> attackEffectStati = attackEffect.getMonsterStati();
        if (!attackEffectStati.isEmpty()) {
            if (attackEffect.makeChanceResult()) {
                monster.applyStatus(player, new MonsterStatusEffect(attackEffectStati, theSkill, null, false), attackEffect.isPoison(), attackEffect.getDuration());
            }
        }
    }

    /**
     * @param player 玩家角色
     * @param map 地图对象
     * @param monster 怪物对象
     * @param attack 攻击信息
     * @param totDamageToOneMonster 对单个怪物的总伤害
     * @description 实际造成伤害。
     */
    private void dealFinalDamage(Character player, MapleMap map, Monster monster, AttackInfo attack, int totDamageToOneMonster) {
        if (attack.skill == Paladin.HEAVENS_HAMMER) { // 圣骑士 - 天堂之锤
            if (!monster.isBoss()) {
                damageMonsterWithSkill(player, map, monster, monster.getHp() - 1, attack.skill, 1777);
            } else {
                int HHDmg = (player.calculateMaxBaseDamage(player.getTotalWatk()) * (SkillFactory.getSkill(Paladin.HEAVENS_HAMMER).getEffect(player.getSkillLevel(SkillFactory.getSkill(Paladin.HEAVENS_HAMMER))).getDamage() / 100));
                damageMonsterWithSkill(player, map, monster, (int) (Math.floor(Math.random() * (HHDmg / 5) + HHDmg * .8)), attack.skill, 1777);
            }
        } else if (attack.skill == Aran.COMBO_TEMPEST) { // 战神 - 连击风暴
            if (!monster.isBoss()) {
                damageMonsterWithSkill(player, map, monster, monster.getHp(), attack.skill, 0);
            } else {
                int TmpDmg = (player.calculateMaxBaseDamage(player.getTotalWatk()) * (SkillFactory.getSkill(Aran.COMBO_TEMPEST).getEffect(player.getSkillLevel(SkillFactory.getSkill(Aran.COMBO_TEMPEST))).getDamage() / 100));
                damageMonsterWithSkill(player, map, monster, (int) (Math.floor(Math.random() * (TmpDmg / 5) + TmpDmg * .8)), attack.skill, 0);
            }
        } else {
            if (attack.skill == Aran.BODY_PRESSURE) { // 战神 - 体压
                map.broadcastMessage(PacketCreator.damageMonster(monster.getObjectId(), totDamageToOneMonster));
            }
            map.damageMonster(player, monster, totDamageToOneMonster);
        }
    }

    /**
     * @param player 玩家角色
     * @param map 地图对象
     * @param monster 怪物对象
     * @param attack 攻击信息
     * @description 处理怪物反伤（武器反伤或魔法反伤）。
     */
    private void handleMonsterReflect(Character player, MapleMap map, Monster monster, AttackInfo attack) {
        if (monster.isBuffed(MonsterStatus.WEAPON_REFLECT) && !attack.magic) {
            for (MobSkillId msId : monster.getSkills()) {
                if (msId.type() == MobSkillType.PHYSICAL_AND_MAGIC_COUNTER) {
                    MobSkill toUse = MobSkillFactory.getMobSkillOrThrow(MobSkillType.PHYSICAL_AND_MAGIC_COUNTER, msId.level());
                    player.addHP(-toUse.getX());
                    map.broadcastMessage(player, PacketCreator.damagePlayer(0, monster.getId(), player.getId(), toUse.getX(), 0, 0, false, 0, true, monster.getObjectId(), 0, 0), true);
                }
            }
        }
        if (monster.isBuffed(MonsterStatus.MAGIC_REFLECT) && attack.magic) {
            for (MobSkillId msId : monster.getSkills()) {
                if (msId.type() == MobSkillType.PHYSICAL_AND_MAGIC_COUNTER) {
                    MobSkill toUse = MobSkillFactory.getMobSkillOrThrow(MobSkillType.PHYSICAL_AND_MAGIC_COUNTER, msId.level());
                    player.addHP(-toUse.getY());
                    map.broadcastMessage(player, PacketCreator.damagePlayer(0, monster.getId(), player.getId(), toUse.getY(), 0, 0, false, 0, true, monster.getObjectId(), 0, 0), true);
                }
            }
        }
    }

    /**
     * @param attacker 攻击者角色
     * @param map 地图对象
     * @param monster 怪物对象
     * @param damage 伤害值
     * @param skillid 技能ID
     * @param fixedTime 固定动画时间
     * @description 使用技能对怪物造成伤害，并处理动画延迟。
     */
    private static void damageMonsterWithSkill(final Character attacker, final MapleMap map, final Monster monster, final int damage, int skillid, int fixedTime) {
        int animationTime;

        if (fixedTime == 0) {
            animationTime = SkillFactory.getSkill(skillid).getAnimationTime();
        } else {
            animationTime = fixedTime;
        }

        if (animationTime > 0) {
            TimerManager.getInstance().schedule(() -> {
                map.broadcastMessage(PacketCreator.damageMonster(monster.getObjectId(), damage), monster.getPosition());
                map.damageMonster(attacker, monster, damage);
            }, animationTime);
        } else {
            map.broadcastMessage(PacketCreator.damageMonster(monster.getObjectId(), damage), monster.getPosition());
            map.damageMonster(attacker, monster, damage);
        }
    }

    /**
     * @param p 输入包
     * @param ret 攻击信息对象
     * @return 攻击信息对象
     * @description 解析金钱炸弹技能的伤害数据。
     */
    private AttackInfo parseMesoExplosionDamage(InPacket p, AttackInfo ret) {
        if (ret.numAttackedAndDamage == 0) {
            p.skip(10);
            int bullets = p.readByte();
            for (int j = 0; j < bullets; j++) {
                int mesoid = p.readInt();
                p.skip(1);
                ret.allDamage.put(mesoid, null);
            }
            return ret;
        } else {
            p.skip(6);
        }
        for (int i = 0; i < ret.numAttacked + 1; i++) {
            int oid = p.readInt();
            if (i < ret.numAttacked) {
                p.skip(12);
                int bullets = p.readByte();
                List<Integer> allDamageNumbers = new ArrayList<>();
                for (int j = 0; j < bullets; j++) {
                    int damage = p.readInt();
                    allDamageNumbers.add(damage);
                }
                ret.allDamage.put(oid, allDamageNumbers);
                p.skip(4);
            } else {
                int bullets = p.readByte();
                for (int j = 0; j < bullets; j++) {
                    int mesoid = p.readInt();
                    p.skip(1);
                    ret.allDamage.put(mesoid, null);
                }
            }
        }
        return ret;
    }

    /**
     * @param chr 角色对象
     * @param ret 攻击信息对象
     * @return 计算出的最大伤害值
     * @description 根据角色属性和攻击类型计算基础最大伤害。
     */
    private long calculateMaxDamage(Character chr, AttackInfo ret) {
        long calcDmgMax;
        if (ret.magic && ret.skill != 0) {
            calcDmgMax = (long) (Math.ceil((chr.getTotalMagic() * Math.ceil(chr.getTotalMagic() / 1000.0) + chr.getTotalMagic()) / 30.0) + Math.ceil(chr.getTotalInt() / 200.0));
        } else if (ret.skill == Rogue.LUCKY_SEVEN || ret.skill == NightWalker.LUCKY_SEVEN || ret.skill == NightLord.TRIPLE_THROW) { // 飞侠/夜行者 - 双飞斩 / 标飞 - 三连环光击破
            calcDmgMax = (long) ((chr.getTotalLuk() * 5) * Math.ceil(chr.getTotalWatk() / 100.0));
        } else if (ret.skill == DragonKnight.DRAGON_ROAR) { // 龙骑士 - 龙咆哮
            calcDmgMax = (long) ((chr.getTotalStr() * 4 + chr.getTotalDex()) * Math.ceil(chr.getTotalWatk() / 100.0));
        } else if (ret.skill == NightLord.VENOMOUS_STAR || ret.skill == Shadower.VENOMOUS_STAB) { // 标飞 - 武器用毒液 / 侠盗 - 武器用毒液
            calcDmgMax = (long) (Math.ceil((18.5 * (chr.getTotalStr() + chr.getTotalLuk()) + chr.getTotalDex() * 2) / 100.0) * chr.calculateMaxBaseDamage(chr.getTotalWatk()));
        } else {
            calcDmgMax = chr.calculateMaxBaseDamage(chr.getTotalWatk());
        }
        return calcDmgMax;
    }

    /**
     * @param chr 角色对象
     * @param ret 攻击信息对象
     * @param skill 技能对象
     * @param effect 技能效果
     * @param calcDmgMax 当前最大伤害值
     * @return 修正后的最大伤害值
     * @description 应用技能特有的伤害公式。
     */
    private long applySkillSpecificDamageFormula(Character chr, AttackInfo ret, Skill skill, StatEffect effect, long calcDmgMax) {
        if (ret.magic) {
            if (chr.getJob() == Job.IL_ARCHMAGE || chr.getJob() == Job.IL_MAGE) { // 冰雷大法师, 冰雷法师
                int skillLvl = chr.getSkillLevel(ILMage.ELEMENT_AMPLIFICATION);
                if (skillLvl > 0) {
                    calcDmgMax = calcDmgMax * SkillFactory.getSkill(ILMage.ELEMENT_AMPLIFICATION).getEffect(skillLvl).getY() / 100;
                }
            } else if (chr.getJob() == Job.FP_ARCHMAGE || chr.getJob() == Job.FP_MAGE) { // 火毒大法师, 火毒法师
                int skillLvl = chr.getSkillLevel(FPMage.ELEMENT_AMPLIFICATION);
                if (skillLvl > 0) {
                    calcDmgMax = calcDmgMax * SkillFactory.getSkill(FPMage.ELEMENT_AMPLIFICATION).getEffect(skillLvl).getY() / 100;
                }
            } else if (chr.getJob() == Job.BLAZEWIZARD3 || chr.getJob() == Job.BLAZEWIZARD4) { // 炎术士 (3/4转)
                int skillLvl = chr.getSkillLevel(BlazeWizard.ELEMENT_AMPLIFICATION);
                if (skillLvl > 0) {
                    calcDmgMax = calcDmgMax * SkillFactory.getSkill(BlazeWizard.ELEMENT_AMPLIFICATION).getEffect(skillLvl).getY() / 100;
                }
            } else if (chr.getJob() == Job.EVAN7 || chr.getJob() == Job.EVAN8 || chr.getJob() == Job.EVAN9 || chr.getJob() == Job.EVAN10) { // 龙神 (7-10转)
                int skillLvl = chr.getSkillLevel(Evan.MAGIC_AMPLIFICATION);
                if (skillLvl > 0) {
                    calcDmgMax = calcDmgMax * SkillFactory.getSkill(Evan.MAGIC_AMPLIFICATION).getEffect(skillLvl).getY() / 100;
                }
            }
            calcDmgMax *= effect.getMatk();
            if (ret.skill == Cleric.HEAL) { // 牧师 - 群体治愈
                calcDmgMax = (long) Math.round((chr.getTotalInt() * 4.8 + chr.getTotalLuk() * 4) * chr.getTotalMagic() / 1000);
                calcDmgMax = calcDmgMax * effect.getHp() / 100;
                ret.speed = 7;
            }
        } else if (ret.skill == Hermit.SHADOW_MESO) { // 隐士 - 金钱攻击
            calcDmgMax = effect.getMoneyCon() * 10;
            calcDmgMax = (long) Math.floor(calcDmgMax * 1.5);
        } else {
            calcDmgMax = calcDmgMax * effect.getDamage() / 100;
        }
        return calcDmgMax;
    }

    /**
     * @param chr 角色对象
     * @param ret 攻击信息对象
     * @param calcDmgMax 当前最大伤害值
     * @return 修正后的最大伤害值
     * @description 应用Buff和能量条效果对伤害进行修正。
     */
    private long applyBuffAndEnergyBarEffects(Character chr, AttackInfo ret, long calcDmgMax) {
        Integer comboBuff = chr.getBuffedValue(BuffStat.COMBO);
        if (comboBuff != null && comboBuff > 0) {
            int oid = chr.isCygnus() ? DawnWarrior.COMBO : Crusader.COMBO;
            int advcomboid = chr.isCygnus() ? DawnWarrior.ADVANCED_COMBO : Hero.ADVANCED_COMBO;

            if (comboBuff > 6) {
                StatEffect ceffect = SkillFactory.getSkill(advcomboid).getEffect(chr.getSkillLevel(advcomboid));
                calcDmgMax = (long) Math.floor(calcDmgMax * (ceffect.getDamage() + 50) / 100 + 0.20 + (comboBuff - 5) * 0.04);
            } else {
                int skillLv = chr.getSkillLevel(oid);
                if (skillLv <= 0 || chr.isGM()) {
                    skillLv = SkillFactory.getSkill(oid).getMaxLevel();
                }
                if (skillLv > 0) {
                    StatEffect ceffect = SkillFactory.getSkill(oid).getEffect(skillLv);
                    calcDmgMax = (long) Math.floor(calcDmgMax * (ceffect.getDamage() + 50) / 100 + Math.floor((comboBuff - 1) * (skillLv / 6)) / 100);
                }
            }

            if (GameConstants.isFinisherSkill(ret.skill)) {
                int orbs = comboBuff - 1;
                if (orbs == 2) {
                    calcDmgMax *= 1.2;
                } else if (orbs == 3) {
                    calcDmgMax *= 1.54;
                } else if (orbs == 4) {
                    calcDmgMax *= 2;
                } else if (orbs >= 5) {
                    calcDmgMax *= 2.5;
                }
            }
        }

        if (chr.getEnergyBar() == 15000) {
            int energycharge = chr.isCygnus() ? ThunderBreaker.ENERGY_CHARGE : Marauder.ENERGY_CHARGE;
            StatEffect ceffect = SkillFactory.getSkill(energycharge).getEffect(chr.getSkillLevel(energycharge));
            calcDmgMax *= (100 + ceffect.getDamage()) / 100;
        }

        int bonusDmgBuff = 100;
        for (PlayerBuffValueHolder pbvh : chr.getAllBuffs()) {
            int bonusDmg = pbvh.effect.getDamage() - 100;
            bonusDmgBuff += bonusDmg;
        }

        if (bonusDmgBuff != 100) {
            float dmgBuff = bonusDmgBuff / 100.0f;
            calcDmgMax = (long) Math.ceil(calcDmgMax * dmgBuff);
        }

        if (chr.getMapId() >= MapId.ARAN_TUTORIAL_START && chr.getMapId() <= MapId.ARAN_TUTORIAL_MAX) {
            calcDmgMax += 80000; // 战神教程.
        }
        return calcDmgMax;
    }

    /**
     * @param chr 角色对象
     * @param ret 攻击信息对象
     * @param monster 怪物对象
     * @param calcDmgMax 当前最大伤害值
     * @return 修正后的最大伤害值
     * @description 应用充能和元素效果对伤害进行修正。
     */
    private long applyChargeAndElementalEffects(Character chr, AttackInfo ret, Monster monster, long calcDmgMax) {
        if (chr.getBuffEffect(BuffStat.WK_CHARGE) != null) {
            int sourceID = chr.getBuffSource(BuffStat.WK_CHARGE);
            int level = chr.getBuffedValue(BuffStat.WK_CHARGE);
            if (monster != null) {
                if (sourceID == WhiteKnight.BW_FIRE_CHARGE || sourceID == WhiteKnight.SWORD_FIRE_CHARGE) {
                    if (monster.getStats().getEffectiveness(Element.FIRE) == ElementalEffectiveness.WEAK) {
                        calcDmgMax *= 1.05 + level * 0.015;
                    }
                } else if (sourceID == WhiteKnight.BW_ICE_CHARGE || sourceID == WhiteKnight.SWORD_ICE_CHARGE) {
                    if (monster.getStats().getEffectiveness(Element.ICE) == ElementalEffectiveness.WEAK) {
                        calcDmgMax *= 1.05 + level * 0.015;
                    }
                } else if (sourceID == WhiteKnight.BW_LIT_CHARGE || sourceID == WhiteKnight.SWORD_LIT_CHARGE) {
                    if (monster.getStats().getEffectiveness(Element.LIGHTING) == ElementalEffectiveness.WEAK) {
                        calcDmgMax *= 1.05 + level * 0.015;
                    }
                } else if (sourceID == Paladin.BW_HOLY_CHARGE || sourceID == Paladin.SWORD_HOLY_CHARGE) {
                    if (monster.getStats().getEffectiveness(Element.HOLY) == ElementalEffectiveness.WEAK) {
                        calcDmgMax *= 1.2 + level * 0.015;
                    }
                }
            } else {
                calcDmgMax *= 1.5;
            }
        }

        if (ret.skill != 0) {
            Skill skill = SkillFactory.getSkill(ret.skill);
            if (skill.getElement() != Element.NEUTRAL && chr.getBuffedValue(BuffStat.ELEMENTAL_RESET) == null) {
                if (monster != null) {
                    ElementalEffectiveness eff = monster.getElementalEffectiveness(skill.getElement());
                    if (eff == ElementalEffectiveness.WEAK) {
                        calcDmgMax *= 1.5;
                    } else if (eff == ElementalEffectiveness.STRONG) {
                        calcDmgMax *= 0.5;
                    }
                } else {
                    calcDmgMax *= 1.5;
                }
            }
            if (ret.skill == FPWizard.POISON_BREATH || ret.skill == FPMage.POISON_MIST || ret.skill == FPArchMage.FIRE_DEMON || ret.skill == ILArchMage.ICE_DEMON) {
                if (monster != null) {
                    // 毒素完全是服务器端处理的
                    // calcDmgMax = monster.getHp() / (70 - chr.getSkillLevel(skill));
                }
            } else if (ret.skill == Hermit.SHADOW_WEB) { // 隐士 - 影网术
                if (monster != null) {
                    calcDmgMax = monster.getHp() / (50 - chr.getSkillLevel(skill));
                }
            } else if (ret.skill == Hermit.SHADOW_MESO) { // 隐士 - 金钱攻击
                if (monster != null) {
                    monster.debuffMob(Hermit.SHADOW_MESO);
                }
            } else if (ret.skill == Aran.BODY_PRESSURE) { // 战神 - 体压
                if (monster != null) {
                    int bodyPressureDmg = (int) Math.ceil(monster.getMaxHp() * SkillFactory.getSkill(Aran.BODY_PRESSURE).getEffect(ret.skilllevel).getDamage() / 100.0);
                    if (bodyPressureDmg > calcDmgMax) {
                        calcDmgMax = bodyPressureDmg;
                    }
                }
            }
        }
        return calcDmgMax;
    }

    /**
     * @param ret 攻击信息对象
     * @param j 伤害段数索引
     * @param shadowPartner 是否有影分身
     * @param hitDmgMax 当前最大伤害值
     * @return 修正后的最大伤害值
     * @description 应用伤害修正，例如影分身和特殊技能。
     */
    private long applyDamageModifiers(AttackInfo ret, int j, boolean shadowPartner, long hitDmgMax) {
        if (ret.skill == Buccaneer.BARRAGE || ret.skill == ThunderBreaker.BARRAGE) { // 冲锋队长/拳手 - 连环攻击
            if (j > 3) {
                hitDmgMax *= Math.pow(2, (j - 3));
            }
        }
        if (shadowPartner) {
            if (j >= ret.numDamage / 2) {
                hitDmgMax *= 0.5;
            }
        }

        // 狙击技能特殊处理：固定伤害19.5万-20万
        if (ret.skill == Marksman.SNIPE) { // 神射手 - 狙击
            //damage = 195000 + Randomizer.nextInt(5000); // 客户端发送的伤害会被覆盖
            //hitDmgMax = 200000; // 设置最大伤害上限为20万
            hitDmgMax = 195000 + Randomizer.nextInt(5000); // 假设客户端伤害上限199,999
        }
        // 竹林雨/竹林突刺技能特殊处理：用于武陵道场Boss战
        else if (ret.skill == Beginner.BAMBOO_RAIN || ret.skill == Noblesse.BAMBOO_RAIN
                || ret.skill == Evan.BAMBOO_THRUST || ret.skill == Legend.BAMBOO_THRUST) {
            hitDmgMax = 82569000; // 设置为武陵道场最强Boss最大血量的30%，即82569000
        }
        return hitDmgMax;
    }
}
