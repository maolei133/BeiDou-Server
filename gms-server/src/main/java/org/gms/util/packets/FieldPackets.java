package org.gms.util.packets;

import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.constants.id.ItemId;
import org.gms.constants.id.MapId;
import org.gms.constants.inventory.ItemConstants;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.Pet;
import org.gms.client.status.MonsterStatus;
import org.gms.client.status.MonsterStatusEffect;
import org.gms.net.opcodes.SendOpcode;
import org.gms.net.packet.ByteBufOutPacket;
import org.gms.net.packet.InPacket;
import org.gms.net.packet.OutPacket;
import org.gms.net.packet.Packet;
import org.gms.net.server.Server;
import org.gms.net.server.channel.handlers.SummonDamageHandler.SummonAttackEntry;
import org.gms.net.server.guild.Alliance;
import org.gms.net.server.guild.Guild;
import org.gms.net.server.guild.GuildSummary;
import org.gms.server.ItemInformationProvider;
import org.gms.server.life.MobSkill;
import org.gms.server.life.MobSkillId;
import org.gms.server.maps.Door;
import org.gms.server.maps.DoorObject;
import org.gms.server.maps.Dragon;
import org.gms.server.maps.MapleMap;
import org.gms.server.maps.MiniGame;
import org.gms.server.maps.Mist;
import org.gms.server.maps.PlayerShop;
import org.gms.server.maps.Reactor;
import org.gms.server.maps.Summon;
import org.gms.server.movement.LifeMovementFragment;
import org.gms.util.HexTool;
import org.gms.util.Pair;
import org.gms.util.Randomizer;

import java.awt.*;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * FieldPackets
 * 处理地图、移动、特效、召唤物等相关的数据包构建
 */
public class FieldPackets {

    /**
     * 获取地图切换包
     *
     * @param to         目标地图
     * @param spawnPoint 出生点编号
     * @param chr        角色对象
     * @return 地图切换包
     */
    public static Packet getWarpToMap(MapleMap to, int spawnPoint, Character chr) {
        final OutPacket p = OutPacket.create(SendOpcode.SET_FIELD);
        p.writeInt(chr.getClient().getChannel() - 1);
        p.writeInt(0);
        p.writeByte(0);
        p.writeInt(to.getId());
        p.writeByte(spawnPoint);
        p.writeShort(chr.getHp());
        p.writeBool(chr.isChasing());
        if (chr.isChasing()) {
            chr.setChasing(false);
            p.writeInt(chr.getPosition().x);
            p.writeInt(chr.getPosition().y);
        }
        p.writeLong(PacketHelper.getTime(Server.getInstance().getCurrentTime()));
        return p;
    }

    public static Packet getWarpToMap(MapleMap to, int spawnPoint, Point spawnPosition, Character chr) {
        final OutPacket p = OutPacket.create(SendOpcode.SET_FIELD);
        p.writeInt(chr.getClient().getChannel() - 1);
        p.writeInt(0);
        p.writeByte(0);
        p.writeInt(to.getId());
        p.writeByte(spawnPoint);
        p.writeShort(chr.getHp());
        p.writeBool(true);
        p.writeInt(spawnPosition.x);
        p.writeInt(spawnPosition.y);
        p.writeLong(PacketHelper.getTime(Server.getInstance().getCurrentTime()));
        return p;
    }

    /**
     * 获取生成传送门包
     *
     * @param townId   城镇 ID
     * @param targetId 目标 ID
     * @param pos      位置
     * @return 生成传送门包
     */
    public static Packet spawnPortal(int townId, int targetId, Point pos) {
        OutPacket p = OutPacket.create(SendOpcode.SPAWN_PORTAL);
        p.writeInt(townId);
        p.writeInt(targetId);
        p.writePos(pos);
        return p;
    }

    /**
     * 获取生成时空门包
     *
     * @param ownerid  拥有者 ID
     * @param pos      位置
     * @param launched 是否已展开
     * @return 生成时空门包
     */
    public static Packet spawnDoor(int ownerid, Point pos, boolean launched) {
        OutPacket p = OutPacket.create(SendOpcode.SPAWN_DOOR);
        p.writeBool(launched);
        p.writeInt(ownerid);
        p.writePos(pos);
        return p;
    }

    /**
     * 获取移除时空门包
     *
     * @param ownerId 拥有者 ID
     * @param town    是否在城镇
     * @return 移除时空门包
     */
    public static Packet removeDoor(int ownerId, boolean town) {
        final OutPacket p;
        if (town) {
            p = OutPacket.create(SendOpcode.SPAWN_PORTAL);
            p.writeInt(MapId.NONE);
            p.writeInt(MapId.NONE);
        } else {
            p = OutPacket.create(SendOpcode.REMOVE_DOOR);
            p.writeByte(0);
            p.writeInt(ownerId);
        }
        return p;
    }

    /**
     * 获取生成召唤物包
     *
     * @param summon   召唤物对象
     * @param animated 是否有动画
     * @return 生成召唤物包
     */
    public static Packet spawnSummon(Summon summon, boolean animated) {
        OutPacket p = OutPacket.create(SendOpcode.SPAWN_SPECIAL_MAPOBJECT);
        p.writeInt(summon.getOwner().getId());
        p.writeInt(summon.getObjectId());
        p.writeInt(summon.getSkill());
        p.writeByte(0x0A); //v83
        p.writeByte(summon.getSkillLevel());
        p.writePos(summon.getPosition());
        p.writeByte(summon.getStance());
        p.writeShort(0);
        p.writeByte(summon.getMovementType().getValue());
        p.writeBool(!summon.isPuppet());
        p.writeBool(!animated);
        return p;
    }

    /**
     * 获取移除召唤物包
     *
     * @param summon   召唤物对象
     * @param animated 是否有动画
     * @return 移除召唤物包
     */
    public static Packet removeSummon(Summon summon, boolean animated) {
        OutPacket p = OutPacket.create(SendOpcode.REMOVE_SPECIAL_MAPOBJECT);
        p.writeInt(summon.getOwner().getId());
        p.writeInt(summon.getObjectId());
        p.writeByte(animated ? 4 : 1);
        return p;
    }

    public static Packet spawnKite(int objId, int itemId, String name, String msg, Point pos, int ft) {
        OutPacket p = OutPacket.create(SendOpcode.SPAWN_KITE);
        p.writeInt(objId);
        p.writeInt(itemId);
        p.writeString(msg);
        p.writeString(name);
        p.writeShort(pos.x);
        p.writeShort(ft);
        return p;
    }

    public static Packet removeKite(int objId, int animationType) {
        OutPacket p = OutPacket.create(SendOpcode.REMOVE_KITE);
        p.writeByte(animationType); // 0 is 10/10, 1 just vanishes
        p.writeInt(objId);
        return p;
    }

    public static Packet sendCannotSpawnKite() {
        return OutPacket.create(SendOpcode.CANNOT_SPAWN_KITE);
    }

    public static Packet spawnMobMist(int objId, int ownerMobId, MobSkillId msId, Mist mist) {
        return spawnMist(objId, ownerMobId, msId.type().getId(), msId.level(), mist);
    }

    public static Packet spawnMist(int objId, int ownerId, int skill, int level, Mist mist) {
        OutPacket p = OutPacket.create(SendOpcode.SPAWN_MIST);
        p.writeInt(objId);
        p.writeInt(mist.isMobMist() ? 0 : mist.isPoisonMist() ? 1 : mist.isRecoveryMist() ? 4 : 2);
        p.writeInt(ownerId);
        p.writeInt(skill);
        p.writeByte(level);
        p.writeShort(mist.getSkillDelay());
        p.writeInt(mist.getBox().x);
        p.writeInt(mist.getBox().y);
        p.writeInt(mist.getBox().x + mist.getBox().width);
        p.writeInt(mist.getBox().y + mist.getBox().height);
        p.writeInt(0);
        return p;
    }

    public static Packet removeMist(int objId) {
        OutPacket p = OutPacket.create(SendOpcode.REMOVE_MIST);
        p.writeInt(objId);
        return p;
    }

    public static Packet spawnReactor(Reactor reactor) {
        OutPacket p = OutPacket.create(SendOpcode.REACTOR_SPAWN);
        p.writeInt(reactor.getObjectId());
        p.writeInt(reactor.getId());
        p.writeByte(reactor.getState());
        p.writePos(reactor.getPosition());
        p.writeByte(0);
        p.writeShort(0);
        return p;
    }

    public static Packet triggerReactor(Reactor reactor, int stance) {
        OutPacket p = OutPacket.create(SendOpcode.REACTOR_HIT);
        p.writeInt(reactor.getObjectId());
        p.writeByte(reactor.getState());
        p.writePos(reactor.getPosition());
        p.writeByte(stance);
        p.writeShort(0);
        p.writeByte(5);
        return p;
    }

    public static Packet destroyReactor(Reactor reactor) {
        OutPacket p = OutPacket.create(SendOpcode.REACTOR_DESTROY);
        p.writeInt(reactor.getObjectId());
        p.writeByte(reactor.getState());
        p.writePos(reactor.getPosition());
        return p;
    }

    public static Packet musicChange(String song) {
        return environmentChange(song, 6);
    }

    public static Packet showEffect(String effect) {
        return environmentChange(effect, 3);
    }

    public static Packet playSound(String sound) {
        return environmentChange(sound, 4);
    }

    public static Packet environmentChange(String env, int mode) {
        OutPacket p = OutPacket.create(SendOpcode.FIELD_EFFECT);
        p.writeByte(mode);
        p.writeString(env);
        return p;
    }

    public static Packet environmentMove(String env, int mode) {
        OutPacket p = OutPacket.create(SendOpcode.FIELD_OBSTACLE_ONOFF);
        p.writeString(env);
        p.writeInt(mode);   // 0: stop and back to start, 1: move
        return p;
    }

    public static Packet environmentMoveList(Set<Entry<String, Integer>> envList) {
        OutPacket p = OutPacket.create(SendOpcode.FIELD_OBSTACLE_ONOFF_LIST);
        p.writeInt(envList.size());

        for (Entry<String, Integer> envMove : envList) {
            p.writeString(envMove.getKey());
            p.writeInt(envMove.getValue());
        }

        return p;
    }

    public static Packet environmentMoveReset() {
        return OutPacket.create(SendOpcode.FIELD_OBSTACLE_ALL_RESET);
    }

    public static Packet startMapEffect(String msg, int itemId, boolean active) {
        OutPacket p = OutPacket.create(SendOpcode.BLOW_WEATHER);
        p.writeBool(!active);
        p.writeInt(itemId);
        if (active) {
            p.writeString(msg);
        }
        return p;
    }

    public static Packet removeMapEffect() {
        OutPacket p = OutPacket.create(SendOpcode.BLOW_WEATHER);
        p.writeByte(0);
        p.writeInt(0);
        return p;
    }

    public static Packet mapEffect(String path) {
        final OutPacket p = OutPacket.create(SendOpcode.FIELD_EFFECT);
        p.writeByte(3);
        p.writeString(path);
        return p;
    }

    public static Packet mapSound(String path) {
        final OutPacket p = OutPacket.create(SendOpcode.FIELD_EFFECT);
        p.writeByte(4);
        p.writeString(path);
        return p;
    }

    public static Packet trembleEffect(int type, int delay) {
        final OutPacket p = OutPacket.create(SendOpcode.FIELD_EFFECT);
        p.writeByte(1);
        p.writeByte(type);
        p.writeInt(delay);
        return p;
    }

    public static Packet showSpecialEffect(int effect) {
        OutPacket p = OutPacket.create(SendOpcode.SHOW_ITEM_GAIN_INCHAT);
        p.writeByte(effect);
        return p;
    }

    public static Packet playPortalSound() {
        return showSpecialEffect(7);
    }

    public static Packet showMonsterBookPickup() {
        return showSpecialEffect(14);
    }

    public static Packet showEquipmentLevelUp() {
        return showSpecialEffect(15);
    }

    public static Packet showItemLevelup() {
        return showSpecialEffect(15);
    }

    public static Packet showForeignEffect(int effect) {
        return showForeignEffect(-1, effect);
    }

    public static Packet showForeignEffect(int chrId, int effect) {
        OutPacket p = OutPacket.create(SendOpcode.SHOW_FOREIGN_EFFECT);
        p.writeInt(chrId);
        p.writeByte(effect);
        return p;
    }

    public static Packet showBuffEffect(int chrId, int skillId, int effectId) {
        return showBuffEffect(chrId, skillId, effectId, (byte) 3);
    }

    public static Packet showBuffEffect(int chrId, int skillId, int effectId, byte direction) {
        OutPacket p = OutPacket.create(SendOpcode.SHOW_FOREIGN_EFFECT);
        p.writeInt(chrId);
        p.writeByte(effectId); //buff level
        p.writeInt(skillId);
        p.writeByte(direction);
        p.writeByte(1);
        p.writeLong(0);
        return p;
    }

    public static Packet showBuffEffect(int chrId, int skillId, int skillLv, int effectId, byte direction) {
        OutPacket p = OutPacket.create(SendOpcode.SHOW_FOREIGN_EFFECT);
        p.writeInt(chrId);
        p.writeByte(effectId);
        p.writeInt(skillId);
        p.writeByte(0);
        p.writeByte(skillLv);
        p.writeByte(direction);
        return p;
    }

    public static Packet showOwnBuffEffect(int skillId, int effectId) {
        OutPacket p = OutPacket.create(SendOpcode.SHOW_ITEM_GAIN_INCHAT);
        p.writeByte(effectId);
        p.writeInt(skillId);
        p.writeByte(0xA9);
        p.writeByte(1);
        return p;
    }

    public static Packet showOwnBerserk(int skilllevel, boolean Berserk) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_ITEM_GAIN_INCHAT);
        p.writeByte(1);
        p.writeInt(1320006);
        p.writeByte(0xA9);
        p.writeByte(skilllevel);
        p.writeByte(Berserk ? 1 : 0);
        return p;
    }

    public static Packet showBerserk(int chrId, int skillLv, boolean berserk) {
        OutPacket p = OutPacket.create(SendOpcode.SHOW_FOREIGN_EFFECT);
        p.writeInt(chrId);
        p.writeByte(1);
        p.writeInt(1320006);
        p.writeByte(0xA9);
        p.writeByte(skillLv);
        p.writeBool(berserk);
        return p;
    }

    public static Packet skillEffect(Character from, int skillId, int level, byte flags, int speed, byte direction) {
        final OutPacket p = OutPacket.create(SendOpcode.SKILL_EFFECT);
        p.writeInt(from.getId());
        p.writeInt(skillId);
        p.writeByte(level);
        p.writeByte(flags);
        p.writeByte(speed);
        p.writeByte(direction);
        return p;
    }

    public static Packet skillCancel(Character from, int skillId) {
        final OutPacket p = OutPacket.create(SendOpcode.CANCEL_SKILL_EFFECT);
        p.writeInt(from.getId());
        p.writeInt(skillId);
        return p;
    }

    public static Packet getClock(Number time) { // time in seconds
        OutPacket p = OutPacket.create(SendOpcode.CLOCK);
        p.writeByte(2);
        p.writeInt(time.intValue());
        return p;
    }

    public static Packet getClockTime(int hour, int min, int sec) { // Current Time
        OutPacket p = OutPacket.create(SendOpcode.CLOCK);
        p.writeByte(1); //Clock-Type
        p.writeByte(hour);
        p.writeByte(min);
        p.writeByte(sec);
        return p;
    }

    public static Packet removeClock() {
        final OutPacket p = OutPacket.create(SendOpcode.STOP_CLOCK);
        p.writeByte(0);
        return p;
    }

    public static Packet spawnGuide(boolean spawn) {
        OutPacket p = OutPacket.create(SendOpcode.SPAWN_GUIDE);
        p.writeBool(spawn);
        return p;
    }

    public static Packet talkGuide(String talk) {
        final OutPacket p = OutPacket.create(SendOpcode.TALK_GUIDE);
        p.writeByte(0);
        p.writeString(talk);
        p.writeBytes(new byte[]{(byte) 0xC8, 0, 0, 0, (byte) 0xA0, (byte) 0x0F, 0, 0});
        return p;
    }

    public static Packet guideHint(int hint) {
        OutPacket p = OutPacket.create(SendOpcode.TALK_GUIDE);
        p.writeByte(1);
        p.writeInt(hint);
        p.writeInt(7000);
        return p;
    }

    public static Packet changeBackgroundEffect(boolean remove, int layer, int transition) {
        OutPacket p = OutPacket.create(SendOpcode.SET_BACK_EFFECT);
        p.writeBool(remove);
        p.writeInt(0);
        p.writeByte(layer);
        p.writeInt(transition);
        return p;
    }

    public static Packet spawnDragon(Dragon dragon) {
        OutPacket p = OutPacket.create(SendOpcode.SPAWN_DRAGON);
        p.writeInt(dragon.getOwner().getId());
        p.writeShort(dragon.getPosition().x);
        p.writeShort(0);
        p.writeShort(dragon.getPosition().y);
        p.writeShort(0);
        p.writeByte(dragon.getStance());
        p.writeByte(0);
        p.writeShort(dragon.getOwner().getJob().getId());
        return p;
    }

    public static Packet moveDragon(Dragon dragon, Point startPos, InPacket movementPacket, long movementDataLength) {
        final OutPacket p = OutPacket.create(SendOpcode.MOVE_DRAGON);
        p.writeInt(dragon.getOwner().getId());
        p.writePos(startPos);
        PacketHelper.rebroadcastMovementList(p, movementPacket, movementDataLength);
        return p;
    }

    public static Packet removeDragon(int chrId) {
        OutPacket p = OutPacket.create(SendOpcode.REMOVE_DRAGON);
        p.writeInt(chrId);
        return p;
    }

    public static Packet movePlayer(int chrId, InPacket movementPacket, long movementDataLength) {
        OutPacket p = OutPacket.create(SendOpcode.MOVE_PLAYER);
        p.writeInt(chrId);
        p.writeInt(0);
        PacketHelper.rebroadcastMovementList(p, movementPacket, movementDataLength);
        return p;
    }

    public static Packet moveSummon(int cid, int oid, Point startPos, InPacket movementPacket, long movementDataLength) {
        final OutPacket p = OutPacket.create(SendOpcode.MOVE_SUMMON);
        p.writeInt(cid);
        p.writeInt(oid);
        p.writePos(startPos);
        PacketHelper.rebroadcastMovementList(p, movementPacket, movementDataLength);
        return p;
    }

    public static Packet summonAttack(int cid, int summonOid, byte direction, List<SummonAttackEntry> allDamage) {
        OutPacket p = OutPacket.create(SendOpcode.SUMMON_ATTACK);
        p.writeInt(cid);
        p.writeInt(summonOid);
        p.writeByte(0);
        p.writeByte(direction);
        p.writeByte(allDamage.size());
        for (SummonAttackEntry attackEntry : allDamage) {
            p.writeInt(attackEntry.getMonsterOid());
            p.writeByte(6);
            p.writeInt(attackEntry.getDamage());
        }
        return p;
    }

    /*
    public static Packet summonAttack(int cid, int summonSkillId, byte direction, List<SummonAttackEntry> allDamage) {
            OutPacket p = OutPacket.create(SendOpcode);
            //b2 00 29 f7 00 00 9a a3 04 00 c8 04 01 94 a3 04 00 06 ff 2b 00
            SUMMON_ATTACK);
            p.writeInt(cid);
            p.writeInt(summonSkillId);
            p.writeByte(direction);
            p.writeByte(4);
            p.writeByte(allDamage.size());
            for (SummonAttackEntry attackEntry : allDamage) {
                    p.writeInt(attackEntry.getMonsterOid()); // oid
                    p.writeByte(6); // who knows
                    p.writeInt(attackEntry.getDamage()); // damage
            }
            return p;
    }
    */

    public static Packet damageSummon(int cid, int oid, int damage, int monsterIdFrom) {
        final OutPacket p = OutPacket.create(SendOpcode.DAMAGE_SUMMON);
        p.writeInt(cid);
        p.writeInt(oid);
        p.writeByte(12);
        p.writeInt(damage);
        p.writeInt(monsterIdFrom);
        p.writeByte(0);
        return p;
    }

    public static Packet summonSkill(int cid, int summonSkillId, int newStance) {
        final OutPacket p = OutPacket.create(SendOpcode.SUMMON_SKILL);
        p.writeInt(cid);
        p.writeInt(summonSkillId);
        p.writeByte(newStance);
        return p;
    }

    public static Packet closeRangeAttack(Character chr, int skill, int skilllevel, int stance, int numAttackedAndDamage, Map<Integer, List<Integer>> damage, int speed, int direction, int display) {
        final OutPacket p = OutPacket.create(SendOpcode.CLOSE_RANGE_ATTACK);
        PacketHelper.addAttackBody(p, chr, skill, skilllevel, stance, numAttackedAndDamage, 0, damage, speed, direction, display);
        return p;
    }

    public static Packet rangedAttack(Character chr, int skill, int skilllevel, int stance, int numAttackedAndDamage, int projectile, Map<Integer, List<Integer>> damage, int speed, int direction, int display) {
        final OutPacket p = OutPacket.create(SendOpcode.RANGED_ATTACK);
        PacketHelper.addAttackBody(p, chr, skill, skilllevel, stance, numAttackedAndDamage, projectile, damage, speed, direction, display);
        p.writeInt(0);
        return p;
    }

    public static Packet magicAttack(Character chr, int skill, int skilllevel, int stance, int numAttackedAndDamage, Map<Integer, List<Integer>> damage, int charge, int speed, int direction, int display) {
        final OutPacket p = OutPacket.create(SendOpcode.MAGIC_ATTACK);
        PacketHelper.addAttackBody(p, chr, skill, skilllevel, stance, numAttackedAndDamage, 0, damage, speed, direction, display);
        if (charge != -1) {
            p.writeInt(charge);
        }
        return p;
    }

    public static Packet throwGrenade(int cid, Point pos, int keyDown, int skillId, int skillLevel) {
        OutPacket p = OutPacket.create(SendOpcode.THROW_GRENADE);
        p.writeInt(cid);
        p.writeInt(pos.x);
        p.writeInt(pos.y);
        p.writeInt(keyDown);
        p.writeInt(skillId);
        p.writeInt(skillLevel);
        return p;
    }

    public static Packet damagePlayer(int skill, int monsteridfrom, int cid, int damage, int fake, int direction, boolean pgmr, int pgmr_1, boolean is_pg, int oid, int pos_x, int pos_y) {
        final OutPacket p = OutPacket.create(SendOpcode.DAMAGE_PLAYER);
        p.writeInt(cid);
        p.writeByte(skill);
        if (skill == -3) {
            p.writeInt(0);
        }
        p.writeInt(damage);
        if (skill != -4) {
            p.writeInt(monsteridfrom);
            p.writeByte(direction);
            if (pgmr) {
                p.writeByte(pgmr_1);
                p.writeByte(is_pg ? 1 : 0);
                p.writeInt(oid);
                p.writeByte(6);
                p.writeShort(pos_x);
                p.writeShort(pos_y);
                p.writeByte(0);
            } else {
                p.writeShort(0);
            }
            p.writeInt(damage);
            if (fake > 0) {
                p.writeInt(fake);
            }
        } else {
            p.writeInt(damage);
        }
        return p;
    }

    public static Packet facialExpression(Character from, int expression) {
        OutPacket p = OutPacket.create(SendOpcode.FACIAL_EXPRESSION);
        p.writeInt(from.getId());
        p.writeInt(expression);
        return p;
    }

    public static Packet showChair(int characterid, int itemid) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_CHAIR);
        p.writeInt(characterid);
        p.writeInt(itemid);
        return p;
    }

    public static Packet cancelChair(int id) {
        final OutPacket p = OutPacket.create(SendOpcode.CANCEL_CHAIR);
        if (id < 0) {
            p.writeByte(0);
        } else {
            p.writeByte(1);
            p.writeShort(id);
        }
        return p;
    }

    public static Packet giveForeignChairSkillEffect(int cid) {
        final OutPacket p = OutPacket.create(SendOpcode.GIVE_FOREIGN_BUFF);
        p.writeInt(cid);
        PacketHelper.writeLongMaskChair(p);

        p.writeShort(0);
        p.writeShort(0);
        p.writeShort(100);
        p.writeShort(1);

        p.writeShort(0);
        p.writeShort(900);

        p.skip(7);

        return p;
    }

    public static Packet cancelForeignChairSkillEffect(int chrId) {
        OutPacket p = OutPacket.create(SendOpcode.CANCEL_FOREIGN_BUFF);
        p.writeInt(chrId);
        PacketHelper.writeLongMaskChair(p);
        return p;
    }

    public static Packet spawnPlayerMapObject(Client target, Character chr, boolean enteringField) {
        OutPacket p = OutPacket.create(SendOpcode.SPAWN_PLAYER);
        p.writeInt(chr.getId());
        p.writeByte(chr.getLevel());
        p.writeString(chr.getName());
        if (chr.getGuildId() < 1) {
            p.writeString("");
            p.writeBytes(new byte[6]);
        } else {
            GuildSummary gs = chr.getClient().getWorldServer().getGuildSummary(chr.getGuildId(), chr.getWorld());
            if (gs != null) {
                p.writeString(gs.getName());
                p.writeShort(gs.getLogoBG());
                p.writeByte(gs.getLogoBGColor());
                p.writeShort(gs.getLogo());
                p.writeByte(gs.getLogoColor());
            } else {
                p.writeString("");
                p.writeBytes(new byte[6]);
            }
        }

        PacketHelper.writeForeignBuffs(p, chr);

        p.writeShort(chr.getJob().getId());

        PacketHelper.addCharLook(p, chr, false);
        p.writeInt(chr.getInventory(InventoryType.CASH).countById(ItemId.HEART_SHAPED_CHOCOLATE));
        p.writeInt(chr.getItemEffect());
        p.writeInt(ItemConstants.getInventoryType(chr.getChair()) == InventoryType.SETUP ? chr.getChair() : 0);

        if (enteringField) {
            Point spawnPos = new Point(chr.getPosition());
            spawnPos.y -= 42;
            p.writePos(spawnPos);
            p.writeByte(6);
        } else {
            p.writePos(chr.getPosition());
            p.writeByte(chr.getStance());
        }

        p.writeShort(0);
        p.writeByte(0);
        Pet[] pet = chr.getPets();
        for (int i = 0; i < 3; i++) {
            if (pet[i] != null) {
                PacketHelper.addPetInfo(p, pet[i], false);
            }
        }
        p.writeByte(0);
        if (chr.getMapleMount() == null) {
            p.writeInt(1);
            p.writeLong(0);
        } else {
            p.writeInt(chr.getMapleMount().getLevel());
            p.writeInt(chr.getMapleMount().getExp());
            p.writeInt(chr.getMapleMount().getTiredness());
        }

        PlayerShop mps = chr.getPlayerShop();
        if (mps != null && mps.isOwner(chr)) {
            if (mps.hasFreeSlot()) {
                PacketHelper.addAnnounceBox(p, mps, mps.getVisitors().length);
            } else {
                PacketHelper.addAnnounceBox(p, mps, 1);
            }
        } else {
            MiniGame miniGame = chr.getMiniGame();
            if (miniGame != null && miniGame.isOwner(chr)) {
                if (miniGame.hasFreeSlot()) {
                    PacketHelper.addAnnounceBox(p, miniGame, 1, 0);
                } else {
                    PacketHelper.addAnnounceBox(p, miniGame, 2, miniGame.isMatchInProgress() ? 1 : 0);
                }
            } else {
                p.writeByte(0);
            }
        }

        if (chr.getChalkboard() != null) {
            p.writeByte(1);
            p.writeString(chr.getChalkboard());
        } else {
            p.writeByte(0);
        }
        PacketHelper.addRingLook(p, chr, true);
        PacketHelper.addRingLook(p, chr, false);
        PacketHelper.addMarriageRingLook(target, p, chr);
        PacketHelper.encodeNewYearCardInfo(p, chr);
        p.writeByte(0);
        p.writeByte(0);
        p.writeByte(chr.getTeam());
        return p;
    }

    public static Packet removePlayerFromMap(int chrId) {
        OutPacket p = OutPacket.create(SendOpcode.REMOVE_PLAYER_FROM_MAP);
        p.writeInt(chrId);
        return p;
    }

    public static Packet updateCharLook(Client target, Character chr) {
        OutPacket p = OutPacket.create(SendOpcode.UPDATE_CHAR_LOOK);
        p.writeInt(chr.getId());
        p.writeByte(1);
        PacketHelper.addCharLook(p, chr, false);
        PacketHelper.addRingLook(p, chr, true);
        PacketHelper.addRingLook(p, chr, false);
        PacketHelper.addMarriageRingLook(target, p, chr);
        p.writeInt(0);
        return p;
    }

    public static Packet showForeignInfo(int cid, String path) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_FOREIGN_EFFECT);
        p.writeInt(cid);
        p.writeByte(0x17);
        p.writeString(path);
        p.writeInt(1);
        return p;
    }

    public static Packet showInfo(String path) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_ITEM_GAIN_INCHAT);
        p.writeByte(0x17);
        p.writeString(path);
        p.writeInt(1);
        return p;
    }

    public static Packet showIntro(String path) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_ITEM_GAIN_INCHAT);
        p.writeByte(0x12);
        p.writeString(path);
        return p;
    }

    public static Packet showInfoText(String text) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        p.writeByte(9);
        p.writeString(text);
        return p;
    }

    public static Packet blockedMessage(int type) {
        final OutPacket p = OutPacket.create(SendOpcode.BLOCKED_MAP);
        p.writeByte(type);
        return p;
    }

    public static Packet blockedMessage2(int type) {
        final OutPacket p = OutPacket.create(SendOpcode.BLOCKED_SERVER);
        p.writeByte(type);
        return p;
    }

    public static Packet boatPacket(boolean type) {
        OutPacket p = OutPacket.create(SendOpcode.CONTI_STATE);
        p.writeByte(type ? 1 : 2);
        p.writeByte(0);
        return p;
    }

    public static Packet crogBoatPacket(boolean type) {
        OutPacket p = OutPacket.create(SendOpcode.CONTI_MOVE);
        p.writeByte(10);
        p.writeByte(type ? 4 : 5);
        return p;
    }

    public static Packet showForcedEquip(int team) {
        OutPacket p = OutPacket.create(SendOpcode.FORCED_MAP_EQUIP);
        if (team > -1) {
            p.writeByte(team);
        }
        return p;
    }

    /**
     * Sends a player hint.
     *
     * @param hint   The hint it's going to send.
     * @param width  How tall the box is going to be.
     * @param height How long the box is going to be.
     * @return The player hint packet.
     */
    public static Packet sendHint(String hint, int width, int height) {
        if (width < 1) {
            width = hint.length() * 10;
            if (width < 40) {
                width = 40;
            }
        }
        if (height < 5) {
            height = 5;
        }
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_HINT);
        p.writeString(hint);
        p.writeShort(width);
        p.writeShort(height);
        p.writeByte(1);
        return p;
    }
}
