package org.gms.util.packets;

import org.gms.client.status.MonsterStatus;
import org.gms.client.status.MonsterStatusEffect;
import org.gms.net.opcodes.SendOpcode;
import org.gms.net.packet.InPacket;
import org.gms.net.packet.OutPacket;
import org.gms.net.packet.Packet;
import org.gms.server.life.Monster;
import org.gms.util.Pair;

import java.awt.*;
import java.util.List;
import java.util.Map;

/**
 * MobPackets
 * 处理怪物生成、移动、伤害、血量显示、状态等相关的数据包构建
 */
public class MobPackets {

    /**
     * 获取生成怪物包
     *
     * @param life     怪物对象
     * @param newSpawn 是否新生成
     * @return 生成怪物包
     */
    public static Packet spawnMonster(Monster life, boolean newSpawn) {
        return spawnMonsterInternal(life, false, newSpawn, false, 0, false);
    }

    /**
     * 获取生成怪物包
     *
     * @param life     怪物对象
     * @param newSpawn 是否新生成
     * @param effect   生成特效
     * @return 生成怪物包
     */
    public static Packet spawnMonster(Monster life, boolean newSpawn, int effect) {
        return spawnMonsterInternal(life, false, newSpawn, false, effect, false);
    }

    /**
     * 获取控制怪物包
     *
     * @param life     怪物对象
     * @param newSpawn 是否新生成
     * @param aggro    是否主动攻击
     * @return 控制怪物包
     */
    public static Packet controlMonster(Monster life, boolean newSpawn, boolean aggro) {
        return spawnMonsterInternal(life, true, newSpawn, aggro, 0, false);
    }

    /**
     * 获取停止控制怪物包
     *
     * @param oid 怪物对象 ID
     * @return 停止控制怪物包
     */
    public static Packet stopControllingMonster(int oid) {
        OutPacket p = OutPacket.create(SendOpcode.SPAWN_MONSTER_CONTROL);
        p.writeByte(0);
        p.writeInt(oid);
        return p;
    }

    /**
     * 内部方法：处理怪物生成和控制
     *
     * @param life              怪物对象
     * @param requestController 是否请求控制
     * @param newSpawn          是否新生成
     * @param aggro             是否主动攻击
     * @param effect            生成特效
     * @param makeInvis         是否隐身
     * @return 生成/控制怪物包
     */
    private static Packet spawnMonsterInternal(Monster life, boolean requestController, boolean newSpawn, boolean aggro, int effect, boolean makeInvis) {
        if (makeInvis) {
            OutPacket p = OutPacket.create(SendOpcode.SPAWN_MONSTER_CONTROL);
            p.writeByte(0);
            p.writeInt(life.getObjectId());
            return p;
        }

        final OutPacket p;
        if (requestController) {
            p = OutPacket.create(SendOpcode.SPAWN_MONSTER_CONTROL);
            p.writeByte(aggro ? 2 : 1);
        } else {
            p = OutPacket.create(SendOpcode.SPAWN_MONSTER);
        }

        p.writeInt(life.getObjectId());
        p.writeByte(life.getController() == null ? 5 : 1);
        p.writeInt(life.getId());

        if (requestController) {
            PacketHelper.encodeTemporary(p, life.getStati());
        } else {
            p.skip(16);
        }

        p.writePos(life.getPosition());
        p.writeByte(life.getStance());
        p.writeShort(0); //Origin FH // 原点 FH
        p.writeShort(life.getFh());

        if (life.getParentMobOid() != 0) {
            Monster parentMob = life.getMap().getMonsterByOid(life.getParentMobOid());
            if (parentMob != null && parentMob.isAlive()) {
                p.writeByte(effect != 0 ? effect : -3);
                p.writeInt(life.getParentMobOid());
            } else {
                PacketHelper.encodeParentlessMobSpawnEffect(p, newSpawn, effect);
            }
        } else {
            PacketHelper.encodeParentlessMobSpawnEffect(p, newSpawn, effect);
        }

        p.writeByte(life.getTeam());
        p.writeInt(0); // getItemEffect // 获取物品特效
        return p;
    }

    /**
     * 生成假怪物包
     *
     * @param life   怪物对象
     * @param effect 特效
     * @return 生成假怪物包
     */
    public static Packet spawnFakeMonster(Monster life, int effect) {
        OutPacket p = OutPacket.create(SendOpcode.SPAWN_MONSTER_CONTROL);
        p.writeByte(1);
        p.writeInt(life.getObjectId());
        p.writeByte(5);
        p.writeInt(life.getId());
        PacketHelper.encodeTemporary(p, life.getStati());
        p.writePos(life.getPosition());
        p.writeByte(life.getStance());
        p.writeShort(0);
        p.writeShort(life.getFh());
        if (effect > 0) {
            p.writeByte(effect);
            p.writeByte(0);
            p.writeShort(0);
        }
        p.writeShort(-2);
        p.writeByte(life.getTeam());
        p.writeInt(0);
        return p;
    }

    /**
     * 使怪物变真包
     *
     * @param life 怪物对象
     * @return 使怪物变真包
     */
    public static Packet makeMonsterReal(Monster life) {
        OutPacket p = OutPacket.create(SendOpcode.SPAWN_MONSTER);
        p.writeInt(life.getObjectId());
        p.writeByte(5);
        p.writeInt(life.getId());
        PacketHelper.encodeTemporary(p, life.getStati());
        p.writePos(life.getPosition());
        p.writeByte(life.getStance());
        p.writeShort(0);
        p.writeShort(life.getFh());
        p.writeShort(-1);
        p.writeInt(0);
        return p;
    }

    /**
     * 移除怪物隐身包
     *
     * @param life 怪物对象
     * @return 移除怪物隐身包
     */
    public static Packet removeMonsterInvisibility(Monster life) {
        final OutPacket p = OutPacket.create(SendOpcode.SPAWN_MONSTER_CONTROL);
        p.writeByte(1);
        p.writeInt(life.getObjectId());
        return p;
    }

    /**
     * 使怪物隐身包
     *
     * @param life 怪物对象
     * @return 使怪物隐身包
     */
    public static Packet makeMonsterInvisible(Monster life) {
        return spawnMonsterInternal(life, true, false, false, 0, true);
    }

    /**
     * 移动怪物包
     *
     * @param oid                对象ID
     * @param skillPossible      是否可能使用技能
     * @param skill              技能
     * @param skillId            技能ID
     * @param skillLevel         技能等级
     * @param pOption            选项
     * @param startPos           起始位置
     * @param movementPacket     移动数据包
     * @param movementDataLength 移动数据长度
     * @return 移动怪物包
     */
    public static Packet moveMonster(int oid, boolean skillPossible, int skill, int skillId, int skillLevel, int pOption,
                                     Point startPos, InPacket movementPacket, long movementDataLength) {
        final OutPacket p = OutPacket.create(SendOpcode.MOVE_MONSTER);
        p.writeInt(oid);
        p.writeByte(0);
        p.writeBool(skillPossible);
        p.writeByte(skill);
        p.writeByte(skillId);
        p.writeByte(skillLevel);
        p.writeShort(pOption);
        p.writePos(startPos);
        PacketHelper.rebroadcastMovementList(p, movementPacket, movementDataLength);
        return p;
    }

    /**
     * 移动怪物响应包
     *
     * @param objectid  对象ID
     * @param moveid    移动ID
     * @param currentMp 当前MP
     * @param useSkills 是否使用技能
     * @return 移动怪物响应包
     */
    public static Packet moveMonsterResponse(int objectid, short moveid, int currentMp, boolean useSkills) {
        return moveMonsterResponse(objectid, moveid, currentMp, useSkills, 0, 0);
    }

    /**
     * 移动怪物响应包（带技能）
     *
     * @param objectid   对象ID
     * @param moveid     移动ID
     * @param currentMp  当前MP
     * @param useSkills  是否使用技能
     * @param skillId    技能ID
     * @param skillLevel 技能等级
     * @return 移动怪物响应包
     */
    public static Packet moveMonsterResponse(int objectid, short moveid, int currentMp, boolean useSkills, int skillId, int skillLevel) {
        OutPacket p = OutPacket.create(SendOpcode.MOVE_MONSTER_RESPONSE);
        p.writeInt(objectid);
        p.writeShort(moveid);
        p.writeBool(useSkills);
        p.writeShort(currentMp);
        p.writeByte(skillId);
        p.writeByte(skillLevel);
        return p;
    }

    /**
     * 杀死怪物包
     *
     * @param objId     对象ID
     * @param animation 是否有动画
     * @return 杀死怪物包
     */
    public static Packet killMonster(int objId, boolean animation) {
        return killMonster(objId, animation ? 1 : 0);
    }

    /**
     * 杀死怪物包（带动画类型）
     *
     * @param objId     对象ID
     * @param animation 动画类型
     * @return 杀死怪物包
     */
    public static Packet killMonster(int objId, int animation) {
        OutPacket p = OutPacket.create(SendOpcode.KILL_MONSTER);
        p.writeInt(objId);
        p.writeByte(animation);
        p.writeByte(animation);
        return p;
    }

    /**
     * 伤害怪物包
     *
     * @param oid    对象ID
     * @param damage 伤害
     * @return 伤害怪物包
     */
    public static Packet damageMonster(int oid, int damage) {
        return damageMonster(oid, damage, 0, 0);
    }

    /**
     * 治疗怪物包
     *
     * @param oid   对象ID
     * @param heal  治疗量
     * @param curhp 当前HP
     * @param maxhp 最大HP
     * @return 治疗怪物包
     */
    public static Packet healMonster(int oid, int heal, int curhp, int maxhp) {
        return damageMonster(oid, -heal, curhp, maxhp);
    }

    /**
     * 伤害怪物包（带HP信息）
     *
     * @param oid    对象ID
     * @param damage 伤害
     * @param curhp  当前HP
     * @param maxhp  最大HP
     * @return 伤害怪物包
     */
    private static Packet damageMonster(int oid, int damage, int curhp, int maxhp) {
        final OutPacket p = OutPacket.create(SendOpcode.DAMAGE_MONSTER);
        p.writeInt(oid);
        p.writeByte(0);
        p.writeInt(damage);
        p.writeInt(curhp);
        p.writeInt(maxhp);
        return p;
    }

    /**
     * 显示怪物HP包
     *
     * @param oid             对象ID
     * @param remhppercentage 剩余HP百分比
     * @return 显示怪物HP包
     */
    public static Packet showMonsterHP(int oid, int remhppercentage) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_MONSTER_HP);
        p.writeInt(oid);
        p.writeByte(remhppercentage);
        return p;
    }

    /**
     * 显示Boss HP包
     *
     * @param oid        对象ID
     * @param currHP     当前HP
     * @param maxHP      最大HP
     * @param tagColor   标签颜色
     * @param tagBgColor 标签背景颜色
     * @return 显示Boss HP包
     */
    public static Packet showBossHP(int oid, int currHP, int maxHP, byte tagColor, byte tagBgColor) {
        final OutPacket p = OutPacket.create(SendOpcode.FIELD_EFFECT);
        p.writeByte(5);
        p.writeInt(oid);
        p.writeInt(currHP);
        p.writeInt(maxHP);
        p.writeByte(tagColor);
        p.writeByte(tagBgColor);
        return p;
    }

    /**
     * 自定义显示Boss HP包
     *
     * @param call       调用
     * @param oid        对象ID
     * @param currHP     当前HP
     * @param maxHP      最大HP
     * @param tagColor   标签颜色
     * @param tagBgColor 标签背景颜色
     * @return 自定义显示Boss HP包
     */
    public static Packet customShowBossHP(byte call, int oid, long currHP, long maxHP, byte tagColor, byte tagBgColor) {
        Pair<Integer, Integer> customHP = PacketHelper.normalizedCustomMaxHP(currHP, maxHP);

        final OutPacket p = OutPacket.create(SendOpcode.FIELD_EFFECT);
        p.writeByte(call);
        p.writeInt(oid);
        p.writeInt(customHP.left);
        p.writeInt(customHP.right);
        p.writeByte(tagColor);
        p.writeByte(tagBgColor);
        return p;
    }

    /**
     * 应用怪物状态包
     *
     * @param oid        对象ID
     * @param mse        怪物状态效果
     * @param reflection 反射
     * @return 应用怪物状态包
     */
    public static Packet applyMonsterStatus(final int oid, final MonsterStatusEffect mse, final List<Integer> reflection) {
        Map<MonsterStatus, Integer> stati = mse.getStati();
        final OutPacket p = OutPacket.create(SendOpcode.APPLY_MONSTER_STATUS);
        p.writeInt(oid);
        p.writeLong(0);
        PacketHelper.writeIntMask(p, stati);
        for (Map.Entry<MonsterStatus, Integer> stat : stati.entrySet()) {
            p.writeShort(stat.getValue());
            if (mse.isMonsterSkill()) {
                PacketHelper.writeMobSkillId(p, mse.getMobSkill().getId());
            } else {
                p.writeInt(mse.getSkill().getId());
            }
            p.writeShort(-1);
        }
        int size = stati.size();
        if (reflection != null) {
            for (Integer ref : reflection) {
                p.writeInt(ref);
            }
            if (reflection.size() > 0) {
                size /= 2;
            }
        }
        p.writeByte(size);
        p.writeInt(0);
        return p;
    }

    /**
     * 取消怪物状态包
     *
     * @param oid   对象ID
     * @param stats 状态映射
     * @return 取消怪物状态包
     */
    public static Packet cancelMonsterStatus(int oid, Map<MonsterStatus, Integer> stats) {
        final OutPacket p = OutPacket.create(SendOpcode.CANCEL_MONSTER_STATUS);
        p.writeInt(oid);
        p.writeLong(0);
        PacketHelper.writeIntMask(p, stats);
        p.writeInt(0);
        return p;
    }

    /**
     * 捕捉怪物包
     *
     * @param mobOid  怪物对象ID
     * @param success 是否成功
     * @return 捕捉怪物包
     */
    public static Packet catchMonster(int mobOid, byte success) {
        final OutPacket p = OutPacket.create(SendOpcode.CATCH_MONSTER);
        p.writeInt(mobOid);
        p.writeByte(success);
        return p;
    }

    /**
     * 捕捉怪物包（带物品）
     *
     * @param mobOid  怪物对象ID
     * @param itemid  物品ID
     * @param success 是否成功
     * @return 捕捉怪物包
     */
    public static Packet catchMonster(int mobOid, int itemid, byte success) {
        final OutPacket p = OutPacket.create(SendOpcode.CATCH_MONSTER_WITH_ITEM);
        p.writeInt(mobOid);
        p.writeInt(itemid);
        p.writeByte(success);
        return p;
    }

    /**
     * 捕捉消息包
     *
     * @param message 消息
     * @return 捕捉消息包
     */
    public static Packet catchMessage(int message) {
        final OutPacket p = OutPacket.create(SendOpcode.BRIDLE_MOB_CATCH_FAIL);
        p.writeByte(message);
        p.writeInt(0);
        p.writeInt(0);
        return p;
    }

    /**
     * 怪物伤害怪物包（友好）
     *
     * @param mob         怪物对象
     * @param damage      伤害
     * @param remainingHp 剩余HP
     * @return 怪物伤害怪物包
     */
    public static Packet MobDamageMobFriendly(Monster mob, int damage, int remainingHp) {
        final OutPacket p = OutPacket.create(SendOpcode.DAMAGE_MONSTER);
        p.writeInt(mob.getObjectId());
        p.writeByte(1);
        p.writeInt(damage);
        p.writeInt(remainingHp);
        p.writeInt(mob.getMaxHp());
        return p;
    }
}
