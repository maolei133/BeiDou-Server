package org.gms.util;

import org.gms.client.BuddylistEntry;
import org.gms.client.BuffStat;
import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.Disease;
import org.gms.client.FamilyEntry;
import org.gms.client.Mount;
import org.gms.client.QuestStatus;
import org.gms.client.SkillMacro;
import org.gms.client.Stat;
import org.gms.client.inventory.Equip.ScrollResult;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.ModifyInventory;
import org.gms.client.inventory.Pet;
import org.gms.client.keybind.KeyBinding;
import org.gms.client.keybind.QuickslotBinding;
import org.gms.client.status.MonsterStatus;
import org.gms.client.status.MonsterStatusEffect;
import org.gms.dao.entity.HiredMerchantItemsDO;
import org.gms.dao.entity.HiredMerchantsDO;
import org.gms.dao.entity.ModifiedCashItemDO;
import org.gms.model.pojo.NewYearCardRecord;
import org.gms.net.encryption.InitializationVector;
import org.gms.net.packet.InPacket;
import org.gms.net.packet.Packet;
import org.gms.net.server.channel.Channel;
import org.gms.net.server.channel.handlers.SummonDamageHandler.SummonAttackEntry;
import org.gms.net.server.world.Party;
import org.gms.net.server.world.PartyCharacter;
import org.gms.net.server.world.PartyOperation;
import org.gms.server.DueyPackage;
import org.gms.server.MTSItemInfo;
import org.gms.server.ShopItem;
import org.gms.server.Trade;
import org.gms.server.events.gm.Snowball;
import org.gms.server.life.MobSkill;
import org.gms.server.life.MobSkillId;
import org.gms.server.life.Monster;
import org.gms.server.life.NPC;
import org.gms.server.life.PlayerNPC;
import org.gms.server.maps.AbstractMapObject;
import org.gms.server.maps.Dragon;
import org.gms.server.maps.HiredMerchant;
import org.gms.server.maps.MapItem;
import org.gms.server.maps.MapleMap;
import org.gms.server.maps.MiniGame;
import org.gms.server.maps.Mist;
import org.gms.server.maps.PlayerShop;
import org.gms.server.maps.PlayerShopItem;
import org.gms.server.maps.Reactor;
import org.gms.server.maps.Summon;
import org.gms.server.movement.LifeMovementFragment;
import org.gms.util.packets.AdminPackets;
import org.gms.util.packets.CashShopPackets;
import org.gms.util.packets.FieldPackets;
import org.gms.util.packets.InventoryPackets;
import org.gms.util.packets.LoginPackets;
import org.gms.util.packets.MiniGamePackets;
import org.gms.util.packets.MiscPackets;
import org.gms.util.packets.MobPackets;
import org.gms.util.packets.NpcPackets;
import org.gms.util.packets.PacketHelper;
import org.gms.util.packets.PetPackets;
import org.gms.util.packets.SocialPackets;
import org.gms.util.packets.WeddingPackets;

import java.awt.*;
import java.net.InetAddress;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * PacketCreator
 * 统一入口类，负责转发调用到各个分类的 Packet 类
 * 采用外观模式 (Facade Pattern) 重构
 */
public class PacketCreator {

    public static final List<Pair<Stat, Integer>> EMPTY_STATUPDATE = PacketHelper.EMPTY_STATUPDATE;
    public final static long ZERO_TIME = PacketHelper.ZERO_TIME;

    public static class WhisperFlag {
        public static final byte LOCATION = 0x01;
        public static final byte WHISPER = 0x02;
        public static final byte REQUEST = 0x04;
        public static final byte RESULT = 0x08;
        public static final byte RECEIVE = 0x10;
        public static final byte BLOCKED = 0x20;
        public static final byte LOCATION_FRIEND = 0x40;
    }

    public static long getTime(long utcTimestamp) {
        return PacketHelper.getTime(utcTimestamp);
    }

    public static Packet showHpHealed(int cid, int amount) {
        return PacketHelper.showHpHealed(cid, amount);
    }

    // LoginPackets
    public static Packet getHello(short mapleVersion, InitializationVector sendIv, InitializationVector recvIv) {
        return LoginPackets.getHello(mapleVersion, sendIv, recvIv);
    }

    public static Packet getPing() {
        return LoginPackets.getPing();
    }

    public static Packet getLoginFailed(int reason) {
        return LoginPackets.getLoginFailed(reason);
    }

    public static Packet getAfterLoginError(int reason) {
        return LoginPackets.getAfterLoginError(reason);
    }

    public static Packet getAuthSuccess(Client c) {
        return LoginPackets.getAuthSuccess(c);
    }

    public static Packet pinRegistered() {
        return LoginPackets.pinRegistered();
    }

    public static Packet requestPin() {
        return LoginPackets.requestPin();
    }

    public static Packet requestPinAfterFailure() {
        return LoginPackets.requestPinAfterFailure();
    }

    public static Packet registerPin() {
        return LoginPackets.registerPin();
    }

    public static Packet pinAccepted() {
        return LoginPackets.pinAccepted();
    }

    public static Packet wrongPic() {
        return LoginPackets.wrongPic();
    }

    public static Packet getServerList(int serverId, String serverName, int flag, String eventmsg, List<Channel> channelLoad) {
        return LoginPackets.getServerList(serverId, serverName, flag, eventmsg, channelLoad);
    }

    public static Packet getEndOfServerList() {
        return LoginPackets.getEndOfServerList();
    }

    public static Packet getServerStatus(int status) {
        return LoginPackets.getServerStatus(status);
    }

    public static Packet getServerIP(InetAddress inetAddr, int port, int clientId) {
        return LoginPackets.getServerIP(inetAddr, port, clientId);
    }

    public static Packet getChannelChange(InetAddress inetAddr, int port) {
        return LoginPackets.getChannelChange(inetAddr, port);
    }

    public static Packet getCharList(Client c, int serverId, int status) {
        return LoginPackets.getCharList(c, serverId, status);
    }

    public static Packet getRelogResponse() {
        return LoginPackets.getRelogResponse();
    }

    public static Packet sendGuestTOS() {
        return LoginPackets.sendGuestTOS();
    }

    public static Packet sendRecommended(List<Pair<Integer, String>> worlds) {
        return LoginPackets.sendRecommended(worlds);
    }

    public static Packet selectWorld(int world) {
        return LoginPackets.selectWorld(world);
    }

    public static Packet showAllCharacter(int totalWorlds, int totalChrs) {
        return LoginPackets.showAllCharacter(totalWorlds, totalChrs);
    }

    public static Packet showAllCharacterInfo(int worldid, List<Character> chars, boolean usePic) {
        return LoginPackets.showAllCharacterInfo(worldid, chars, usePic);
    }

    public static Packet addNewCharEntry(Character chr) {
        return LoginPackets.addNewCharEntry(chr);
    }

    public static Packet deleteCharResponse(int cid, int state) {
        return LoginPackets.deleteCharResponse(cid, state);
    }

    public static Packet charNameResponse(String charname, boolean nameUsed) {
        return LoginPackets.charNameResponse(charname, nameUsed);
    }

    public static Packet sendMapleLifeCharacterInfo() {
        return LoginPackets.sendMapleLifeCharacterInfo();
    }

    public static Packet sendMapleLifeNameError() {
        return LoginPackets.sendMapleLifeNameError();
    }

    public static Packet sendMapleLifeError(int code) {
        return LoginPackets.sendMapleLifeError(code);
    }

    public static Packet enableReport() {
        return LoginPackets.enableReport();
    }

    public static Packet reportResponse(byte mode) {
        return LoginPackets.reportResponse(mode);
    }

    public static Packet updateGender(Character chr) {
        return LoginPackets.updateGender(chr);
    }

    public static Packet sendMesoLimit() {
        return LoginPackets.sendMesoLimit();
    }

    public static Packet updateHpMpAlert(byte hp, byte mp) {
        return LoginPackets.updateHpMpAlert(hp, mp);
    }

    // FieldPackets
    public static Packet getWarpToMap(MapleMap to, int spawnPoint, Character chr) {
        return FieldPackets.getWarpToMap(to, spawnPoint, chr);
    }

    public static Packet getWarpToMap(MapleMap to, int spawnPoint, Point spawnPosition, Character chr) {
        return FieldPackets.getWarpToMap(to, spawnPoint, spawnPosition, chr);
    }

    public static Packet spawnPortal(int townId, int targetId, Point pos) {
        return FieldPackets.spawnPortal(townId, targetId, pos);
    }

    public static Packet spawnDoor(int ownerid, Point pos, boolean launched) {
        return FieldPackets.spawnDoor(ownerid, pos, launched);
    }

    public static Packet removeDoor(int ownerId, boolean town) {
        return FieldPackets.removeDoor(ownerId, town);
    }

    public static Packet spawnSummon(Summon summon, boolean animated) {
        return FieldPackets.spawnSummon(summon, animated);
    }

    public static Packet removeSummon(Summon summon, boolean animated) {
        return FieldPackets.removeSummon(summon, animated);
    }

    public static Packet spawnKite(int objId, int itemId, String name, String msg, Point pos, int ft) {
        return FieldPackets.spawnKite(objId, itemId, name, msg, pos, ft);
    }

    public static Packet removeKite(int objId, int animationType) {
        return FieldPackets.removeKite(objId, animationType);
    }

    public static Packet sendCannotSpawnKite() {
        return FieldPackets.sendCannotSpawnKite();
    }

    public static Packet spawnMobMist(int objId, int ownerMobId, MobSkillId msId, Mist mist) {
        return FieldPackets.spawnMobMist(objId, ownerMobId, msId, mist);
    }

    public static Packet spawnMist(int objId, int ownerId, int skill, int level, Mist mist) {
        return FieldPackets.spawnMist(objId, ownerId, skill, level, mist);
    }

    public static Packet removeMist(int objId) {
        return FieldPackets.removeMist(objId);
    }

    public static Packet spawnReactor(Reactor reactor) {
        return FieldPackets.spawnReactor(reactor);
    }

    public static Packet triggerReactor(Reactor reactor, int stance) {
        return FieldPackets.triggerReactor(reactor, stance);
    }

    public static Packet destroyReactor(Reactor reactor) {
        return FieldPackets.destroyReactor(reactor);
    }

    public static Packet environmentChange(String env, int mode) {
        return FieldPackets.environmentChange(env, mode);
    }

    public static Packet musicChange(String song) {
        return FieldPackets.musicChange(song);
    }

    public static Packet showEffect(String effect) {
        return FieldPackets.showEffect(effect);
    }

    public static Packet playSound(String sound) {
        return FieldPackets.playSound(sound);
    }

    public static Packet environmentMove(String env, int mode) {
        return FieldPackets.environmentMove(env, mode);
    }

    public static Packet environmentMoveList(Set<Map.Entry<String, Integer>> envList) {
        return FieldPackets.environmentMoveList(envList);
    }

    public static Packet environmentMoveReset() {
        return FieldPackets.environmentMoveReset();
    }

    public static Packet startMapEffect(String msg, int itemId, boolean active) {
        return FieldPackets.startMapEffect(msg, itemId, active);
    }

    public static Packet removeMapEffect() {
        return FieldPackets.removeMapEffect();
    }

    public static Packet mapEffect(String path) {
        return FieldPackets.mapEffect(path);
    }

    public static Packet mapSound(String path) {
        return FieldPackets.mapSound(path);
    }

    public static Packet trembleEffect(int type, int delay) {
        return FieldPackets.trembleEffect(type, delay);
    }

    public static Packet showSpecialEffect(int effect) {
        return FieldPackets.showSpecialEffect(effect);
    }

    public static Packet playPortalSound() {
        return FieldPackets.playPortalSound();
    }

    public static Packet showMonsterBookPickup() {
        return FieldPackets.showMonsterBookPickup();
    }

    public static Packet showEquipmentLevelUp() {
        return FieldPackets.showEquipmentLevelUp();
    }

    public static Packet showItemLevelup() {
        return FieldPackets.showItemLevelup();
    }

    public static Packet showForeignEffect(int effect) {
        return FieldPackets.showForeignEffect(effect);
    }

    public static Packet showForeignEffect(int chrId, int effect) {
        return FieldPackets.showForeignEffect(chrId, effect);
    }

    public static Packet showBuffEffect(int chrId, int skillId, int effectId) {
        return FieldPackets.showBuffEffect(chrId, skillId, effectId);
    }

    public static Packet showBuffEffect(int chrId, int skillId, int effectId, byte direction) {
        return FieldPackets.showBuffEffect(chrId, skillId, effectId, direction);
    }

    public static Packet showBuffEffect(int chrId, int skillId, int skillLv, int effectId, byte direction) {
        return FieldPackets.showBuffEffect(chrId, skillId, skillLv, effectId, direction);
    }

    public static Packet showOwnBuffEffect(int skillId, int effectId) {
        return FieldPackets.showOwnBuffEffect(skillId, effectId);
    }

    public static Packet showOwnBerserk(int skilllevel, boolean Berserk) {
        return FieldPackets.showOwnBerserk(skilllevel, Berserk);
    }

    public static Packet showBerserk(int chrId, int skillLv, boolean berserk) {
        return FieldPackets.showBerserk(chrId, skillLv, berserk);
    }

    public static Packet skillEffect(Character from, int skillId, int level, byte flags, int speed, byte direction) {
        return FieldPackets.skillEffect(from, skillId, level, flags, speed, direction);
    }

    public static Packet skillCancel(Character from, int skillId) {
        return FieldPackets.skillCancel(from, skillId);
    }

    public static Packet getClock(Number time) {
        return FieldPackets.getClock(time);
    }

    public static Packet getClockTime(int hour, int min, int sec) {
        return FieldPackets.getClockTime(hour, min, sec);
    }

    public static Packet removeClock() {
        return FieldPackets.removeClock();
    }

    public static Packet spawnGuide(boolean spawn) {
        return FieldPackets.spawnGuide(spawn);
    }

    public static Packet talkGuide(String talk) {
        return FieldPackets.talkGuide(talk);
    }

    public static Packet guideHint(int hint) {
        return FieldPackets.guideHint(hint);
    }

    public static Packet changeBackgroundEffect(boolean remove, int layer, int transition) {
        return FieldPackets.changeBackgroundEffect(remove, layer, transition);
    }

    public static Packet spawnDragon(Dragon dragon) {
        return FieldPackets.spawnDragon(dragon);
    }

    public static Packet moveDragon(Dragon dragon, Point startPos, InPacket movementPacket, long movementDataLength) {
        return FieldPackets.moveDragon(dragon, startPos, movementPacket, movementDataLength);
    }

    public static Packet removeDragon(int chrId) {
        return FieldPackets.removeDragon(chrId);
    }

    public static Packet movePlayer(int chrId, InPacket movementPacket, long movementDataLength) {
        return FieldPackets.movePlayer(chrId, movementPacket, movementDataLength);
    }

    public static Packet moveSummon(int cid, int oid, Point startPos, InPacket movementPacket, long movementDataLength) {
        return FieldPackets.moveSummon(cid, oid, startPos, movementPacket, movementDataLength);
    }

    public static Packet summonAttack(int cid, int summonOid, byte direction, List<SummonAttackEntry> allDamage) {
        return FieldPackets.summonAttack(cid, summonOid, direction, allDamage);
    }

    public static Packet damageSummon(int cid, int oid, int damage, int monsterIdFrom) {
        return FieldPackets.damageSummon(cid, oid, damage, monsterIdFrom);
    }

    public static Packet summonSkill(int cid, int summonSkillId, int newStance) {
        return FieldPackets.summonSkill(cid, summonSkillId, newStance);
    }

    public static Packet closeRangeAttack(Character chr, int skill, int skilllevel, int stance, int numAttackedAndDamage, Map<Integer, List<Integer>> damage, int speed, int direction, int display) {
        return FieldPackets.closeRangeAttack(chr, skill, skilllevel, stance, numAttackedAndDamage, damage, speed, direction, display);
    }

    public static Packet rangedAttack(Character chr, int skill, int skilllevel, int stance, int numAttackedAndDamage, int projectile, Map<Integer, List<Integer>> damage, int speed, int direction, int display) {
        return FieldPackets.rangedAttack(chr, skill, skilllevel, stance, numAttackedAndDamage, projectile, damage, speed, direction, display);
    }

    public static Packet magicAttack(Character chr, int skill, int skilllevel, int stance, int numAttackedAndDamage, Map<Integer, List<Integer>> damage, int charge, int speed, int direction, int display) {
        return FieldPackets.magicAttack(chr, skill, skilllevel, stance, numAttackedAndDamage, damage, charge, speed, direction, display);
    }

    public static Packet throwGrenade(int cid, Point pos, int keyDown, int skillId, int skillLevel) {
        return FieldPackets.throwGrenade(cid, pos, keyDown, skillId, skillLevel);
    }

    public static Packet damagePlayer(int skill, int monsteridfrom, int cid, int damage, int fake, int direction, boolean pgmr, int pgmr_1, boolean is_pg, int oid, int pos_x, int pos_y) {
        return FieldPackets.damagePlayer(skill, monsteridfrom, cid, damage, fake, direction, pgmr, pgmr_1, is_pg, oid, pos_x, pos_y);
    }

    public static Packet facialExpression(Character from, int expression) {
        return FieldPackets.facialExpression(from, expression);
    }

    public static Packet showChair(int characterid, int itemid) {
        return FieldPackets.showChair(characterid, itemid);
    }

    public static Packet cancelChair(int id) {
        return FieldPackets.cancelChair(id);
    }

    public static Packet giveForeignChairSkillEffect(int cid) {
        return FieldPackets.giveForeignChairSkillEffect(cid);
    }

    public static Packet cancelForeignChairSkillEffect(int chrId) {
        return FieldPackets.cancelForeignChairSkillEffect(chrId);
    }

    public static Packet spawnPlayerMapObject(Client target, Character chr, boolean enteringField) {
        return FieldPackets.spawnPlayerMapObject(target, chr, enteringField);
    }

    public static Packet removePlayerFromMap(int chrId) {
        return FieldPackets.removePlayerFromMap(chrId);
    }

    public static Packet updateCharLook(Client target, Character chr) {
        return FieldPackets.updateCharLook(target, chr);
    }

    public static Packet showForeignInfo(int cid, String path) {
        return FieldPackets.showForeignInfo(cid, path);
    }

    public static Packet showInfo(String path) {
        return FieldPackets.showInfo(path);
    }

    public static Packet showIntro(String path) {
        return FieldPackets.showIntro(path);
    }

    public static Packet showInfoText(String text) {
        return FieldPackets.showInfoText(text);
    }

    public static Packet blockedMessage(int type) {
        return FieldPackets.blockedMessage(type);
    }

    public static Packet blockedMessage2(int type) {
        return FieldPackets.blockedMessage2(type);
    }

    public static Packet boatPacket(boolean type) {
        return FieldPackets.boatPacket(type);
    }

    public static Packet crogBoatPacket(boolean type) {
        return FieldPackets.crogBoatPacket(type);
    }

    public static Packet showForcedEquip(int team) {
        return FieldPackets.showForcedEquip(team);
    }

    // NpcPackets
    public static Packet spawnNPC(NPC life) {
        return NpcPackets.spawnNPC(life);
    }

    public static Packet spawnNPCRequestController(NPC life, boolean miniMap) {
        return NpcPackets.spawnNPCRequestController(life, miniMap);
    }

    public static Packet removeNPC(int objId) {
        return NpcPackets.removeNPC(objId);
    }

    public static Packet removeNPCController(int objId) {
        return NpcPackets.removeNPCController(objId);
    }

    public static Packet getNPCTalk(int npc, byte msgType, String talk, String endBytes, byte speaker) {
        return NpcPackets.getNPCTalk(npc, msgType, talk, endBytes, speaker);
    }

    public static Packet getDimensionalMirror(String talk) {
        return NpcPackets.getDimensionalMirror(talk);
    }

    public static Packet getNPCTalkStyle(int npc, String talk, int[] styles) {
        return NpcPackets.getNPCTalkStyle(npc, talk, styles);
    }

    public static Packet getNPCTalkNum(int npc, String talk, int def, int min, int max) {
        return NpcPackets.getNPCTalkNum(npc, talk, def, min, max);
    }

    public static Packet getNPCTalkNum(int npc, String talk, int def, int min, int max, byte speaker) {
        return NpcPackets.getNPCTalkNum(npc, talk, def, min, max, speaker);
    }

    public static Packet getNPCTalkText(int npc, String talk, String def) {
        return NpcPackets.getNPCTalkText(npc, talk, def);
    }

    public static Packet getNPCTalkText(int npc, String talk, String def, byte speaker) {
        return NpcPackets.getNPCTalkText(npc, talk, def, speaker);
    }

    public static Packet OnAskQuiz(int nSpeakerTypeID, int nSpeakerTemplateID, int nResCode, String sTitle, String sProblemText, String sHintText, int nMinInput, int nMaxInput, int tRemainInitialQuiz) {
        return NpcPackets.OnAskQuiz(nSpeakerTypeID, nSpeakerTemplateID, nResCode, sTitle, sProblemText, sHintText, nMinInput, nMaxInput, tRemainInitialQuiz);
    }

    public static Packet OnAskSpeedQuiz(int nSpeakerTypeID, int nSpeakerTemplateID, int nResCode, int nType, int dwAnswer, int nCorrect, int nRemain, int tRemainInitialQuiz) {
        return NpcPackets.OnAskSpeedQuiz(nSpeakerTypeID, nSpeakerTemplateID, nResCode, nType, dwAnswer, nCorrect, nRemain, tRemainInitialQuiz);
    }

    public static Packet getNPCShop(Client c, int sid, List<ShopItem> items) {
        return NpcPackets.getNPCShop(c, sid, items);
    }

    public static Packet shopTransaction(byte code) {
        return NpcPackets.shopTransaction(code);
    }

    public static Packet shopErrorMessage(int error, int type) {
        return NpcPackets.shopErrorMessage(error, type);
    }

    public static Packet spawnPlayerNPC(PlayerNPC npc) {
        return NpcPackets.spawnPlayerNPC(npc);
    }

    public static Packet getPlayerNPC(PlayerNPC npc) {
        return NpcPackets.getPlayerNPC(npc);
    }

    public static Packet removePlayerNPC(int oid) {
        return NpcPackets.removePlayerNPC(oid);
    }

    public static Packet setNPCScriptable(Map<Integer, String> scriptableNpcIds) {
        return NpcPackets.setNPCScriptable(scriptableNpcIds);
    }

    // InventoryPackets
    public static Packet modifyInventory(boolean updateTick, final List<ModifyInventory> mods) {
        return InventoryPackets.modifyInventory(updateTick, mods);
    }

    public static Packet updateInventorySlotLimit(int type, int newLimit) {
        return InventoryPackets.updateInventorySlotLimit(type, newLimit);
    }

    public static Packet getInventoryFull() {
        return InventoryPackets.getInventoryFull();
    }

    public static Packet getShowInventoryFull() {
        return InventoryPackets.getShowInventoryFull();
    }

    public static Packet showItemUnavailable() {
        return InventoryPackets.showItemUnavailable();
    }

    public static Packet getShowInventoryStatus(int mode) {
        return InventoryPackets.getShowInventoryStatus(mode);
    }

    public static Packet getScrollEffect(int chr, ScrollResult scrollSuccess, boolean legendarySpirit, boolean whiteScroll) {
        return InventoryPackets.getScrollEffect(chr, scrollSuccess, legendarySpirit, whiteScroll);
    }

    public static Packet sendHammerData(int hammerUsed) {
        return InventoryPackets.sendHammerData(hammerUsed);
    }

    public static Packet sendHammerMessage() {
        return InventoryPackets.sendHammerMessage();
    }

    public static Packet getStorage(int npcId, byte slots, Collection<Item> items, int meso) {
        return InventoryPackets.getStorage(npcId, slots, items, meso);
    }

    public static Packet getStorageError(byte i) {
        return InventoryPackets.getStorageError(i);
    }

    public static Packet mesoStorage(byte slots, int meso) {
        return InventoryPackets.mesoStorage(slots, meso);
    }

    public static Packet storeStorage(byte slots, InventoryType type, Collection<Item> items) {
        return InventoryPackets.storeStorage(slots, type, items);
    }

    public static Packet takeOutStorage(byte slots, InventoryType type, Collection<Item> items) {
        return InventoryPackets.takeOutStorage(slots, type, items);
    }

    public static Packet arrangeStorage(byte slots, Collection<Item> items) {
        return InventoryPackets.arrangeStorage(slots, items);
    }

    public static Packet finishedSort(int inv) {
        return InventoryPackets.finishedSort(inv);
    }

    public static Packet finishedSort2(int inv) {
        return InventoryPackets.finishedSort2(inv);
    }

    public static Packet itemEffect(int characterid, int itemid) {
        return InventoryPackets.itemEffect(characterid, itemid);
    }

    public static Packet itemExpired(int itemid) {
        return InventoryPackets.itemExpired(itemid);
    }

    public static Packet getItemMessage(int itemid) {
        return InventoryPackets.getItemMessage(itemid);
    }

    public static Packet silentRemoveItemFromMap(int objId) {
        return InventoryPackets.silentRemoveItemFromMap(objId);
    }

    public static Packet removeItemFromMap(int objId, int animation, int chrId) {
        return InventoryPackets.removeItemFromMap(objId, animation, chrId);
    }

    public static Packet removeItemFromMap(int objId, int animation, int chrId, boolean pet, int slot) {
        return InventoryPackets.removeItemFromMap(objId, animation, chrId, pet, slot);
    }

    public static Packet dropItemFromMapObject(Character player, MapItem drop, Point dropfrom, Point dropto, byte mod) {
        return InventoryPackets.dropItemFromMapObject(player, drop, dropfrom, dropto, mod);
    }

    public static Packet updateMapItemObject(MapItem drop, boolean giveOwnership) {
        return InventoryPackets.updateMapItemObject(drop, giveOwnership);
    }

    public static Packet getShowItemGain(int itemId, short quantity) {
        return InventoryPackets.getShowItemGain(itemId, quantity);
    }

    public static Packet getShowItemGain(int itemId, short quantity, boolean inChat) {
        return InventoryPackets.getShowItemGain(itemId, quantity, inChat);
    }

    // SocialPackets
    public static Packet getChatText(int cidfrom, String text, boolean gm, int show) {
        return SocialPackets.getChatText(cidfrom, text, gm, show);
    }

    public static Packet multiChat(String name, String chattext, int mode) {
        return SocialPackets.multiChat(name, chattext, mode);
    }

    public static Packet getMultiMegaphone(String[] messages, int channel, boolean showEar) {
        return SocialPackets.getMultiMegaphone(messages, channel, showEar);
    }

    public static Packet serverMessage(String message) {
        return SocialPackets.serverMessage(message);
    }

    public static Packet serverNotice(int type, String message) {
        return SocialPackets.serverNotice(type, message);
    }

    public static Packet serverNotice(int type, String message, int npc) {
        return SocialPackets.serverNotice(type, message, npc);
    }

    public static Packet serverNotice(int type, int channel, String message) {
        return SocialPackets.serverNotice(type, channel, message);
    }

    public static Packet serverNotice(int type, int channel, String message, boolean smegaEar) {
        return SocialPackets.serverNotice(type, channel, message, smegaEar);
    }

    public static Packet getAvatarMega(Character chr, String medal, int channel, int itemId, List<String> message, boolean ear) {
        return SocialPackets.getAvatarMega(chr, medal, channel, itemId, message, ear);
    }

    public static Packet byeAvatarMega() {
        return SocialPackets.byeAvatarMega();
    }

    public static Packet itemMegaphone(String msg, boolean whisper, int channel, Item item) {
        return SocialPackets.itemMegaphone(msg, whisper, channel, item);
    }

    public static Packet partyCreated(Party party, int partycharid) {
        return SocialPackets.partyCreated(party, partycharid);
    }

    public static Packet partyInvite(Character from) {
        return SocialPackets.partyInvite(from);
    }

    public static Packet partySearchInvite(Character from) {
        return SocialPackets.partySearchInvite(from);
    }

    public static Packet partyStatusMessage(int message) {
        return SocialPackets.partyStatusMessage(message);
    }

    public static Packet partyStatusMessage(int message, String charname) {
        return SocialPackets.partyStatusMessage(message, charname);
    }

    public static Packet updateParty(int forChannel, Party party, PartyOperation op, PartyCharacter target) {
        return SocialPackets.updateParty(forChannel, party, op, target);
    }

    public static Packet partyPortal(int townId, int targetId, Point position) {
        return SocialPackets.partyPortal(townId, targetId, position);
    }

    public static Packet updatePartyMemberHP(int cid, int curhp, int maxhp) {
        return SocialPackets.updatePartyMemberHP(cid, curhp, maxhp);
    }

    public static Packet updateBuddylist(Collection<BuddylistEntry> buddylist) {
        return SocialPackets.updateBuddylist(buddylist);
    }

    public static Packet buddylistMessage(byte message) {
        return SocialPackets.buddylistMessage(message);
    }

    public static Packet requestBuddylistAdd(int chrIdFrom, int chrId, String nameFrom) {
        return SocialPackets.requestBuddylistAdd(chrIdFrom, chrId, nameFrom);
    }

    public static Packet updateBuddyChannel(int characterid, int channel) {
        return SocialPackets.updateBuddyChannel(characterid, channel);
    }

    public static Packet updateBuddyCapacity(int capacity) {
        return SocialPackets.updateBuddyCapacity(capacity);
    }

    public static Packet loadFamily(Character player) {
        return SocialPackets.loadFamily(player);
    }

    public static Packet sendFamilyMessage(int type, int mesos) {
        return SocialPackets.sendFamilyMessage(type, mesos);
    }

    public static Packet getFamilyInfo(FamilyEntry f) {
        return SocialPackets.getFamilyInfo(f);
    }

    public static Packet showPedigree(FamilyEntry entry) {
        return SocialPackets.showPedigree(entry);
    }

    public static Packet sendFamilyInvite(int playerId, String inviter) {
        return SocialPackets.sendFamilyInvite(playerId, inviter);
    }

    public static Packet sendFamilySummonRequest(String familyName, String from) {
        return SocialPackets.sendFamilySummonRequest(familyName, from);
    }

    public static Packet sendFamilyLoginNotice(String name, boolean loggedIn) {
        return SocialPackets.sendFamilyLoginNotice(name, loggedIn);
    }

    public static Packet sendFamilyJoinResponse(boolean accepted, String added) {
        return SocialPackets.sendFamilyJoinResponse(accepted, added);
    }

    public static Packet getSeniorMessage(String name) {
        return SocialPackets.getSeniorMessage(name);
    }

    public static Packet sendGainRep(int gain, String from) {
        return SocialPackets.sendGainRep(gain, from);
    }

    public static Packet familyBuff(int type, int buffnr, int amount, int time) {
        return SocialPackets.familyBuff(type, buffnr, amount, time);
    }

    public static Packet cancelFamilyBuff() {
        return SocialPackets.cancelFamilyBuff();
    }

    public static Packet levelUpMessage(int type, int level, String charname) {
        return SocialPackets.levelUpMessage(type, level, charname);
    }

    public static Packet marriageMessage(int type, String charname) {
        return SocialPackets.marriageMessage(type, charname);
    }

    public static Packet jobMessage(int type, int job, String charname) {
        return SocialPackets.jobMessage(type, job, charname);
    }

    public static Packet messengerInvite(String from, int messengerid) {
        return SocialPackets.messengerInvite(from, messengerid);
    }

    public static Packet OnCoupleMessage(String fiance, String text, boolean spouse) {
        return SocialPackets.OnCoupleMessage(fiance, text, spouse);
    }

    public static Packet addMessengerPlayer(String from, Character chr, int position, int channel) {
        return SocialPackets.addMessengerPlayer(from, chr, position, channel);
    }

    public static Packet removeMessengerPlayer(int position) {
        return SocialPackets.removeMessengerPlayer(position);
    }

    public static Packet updateMessengerPlayer(String from, Character chr, int position, int channel) {
        return SocialPackets.updateMessengerPlayer(from, chr, position, channel);
    }

    public static Packet joinMessenger(int position) {
        return SocialPackets.joinMessenger(position);
    }

    public static Packet messengerChat(String text) {
        return SocialPackets.messengerChat(text);
    }

    public static Packet messengerNote(String text, int mode, int mode2) {
        return SocialPackets.messengerNote(text, mode, mode2);
    }

    public static Packet getWhisperResult(String target, boolean success) {
        return SocialPackets.getWhisperResult(target, success);
    }

    public static Packet getWhisperReceive(String sender, int channel, boolean fromAdmin, String message) {
        return SocialPackets.getWhisperReceive(sender, channel, fromAdmin, message);
    }

    public static Packet getFindResult(Character target, byte type, int fieldOrChannel, byte flag) {
        return SocialPackets.getFindResult(target, type, fieldOrChannel, flag);
    }

    public static Packet noteError(byte error) {
        return SocialPackets.noteError(error);
    }

    public static Packet sendDuey(int operation, List<DueyPackage> packages) {
        return SocialPackets.sendDuey(operation, packages);
    }

    public static Packet sendDueyMSG(byte operation) {
        return SocialPackets.sendDueyMSG(operation);
    }

    public static Packet sendDueyParcelNotification(boolean quick) {
        return SocialPackets.sendDueyParcelNotification(quick);
    }

    public static Packet sendDueyParcelReceived(String from, boolean quick) {
        return SocialPackets.sendDueyParcelReceived(from, quick);
    }

    public static Packet removeItemFromDuey(boolean remove, int Package) {
        return SocialPackets.removeItemFromDuey(remove, Package);
    }

    // CashShopPackets
    public static Packet openCashShop(Client c, boolean mts) throws Exception {
        return CashShopPackets.openCashShop(c, mts);
    }

    public static Packet showCash(Character mc) {
        return CashShopPackets.showCash(mc);
    }

    public static Packet enableCSUse(Character mc) {
        return CashShopPackets.enableCSUse(mc);
    }

    public static Packet showCashInventory(Client c) {
        return CashShopPackets.showCashInventory(c);
    }

    public static Packet showBoughtCashItem(Item item, int accountId) {
        return CashShopPackets.showBoughtCashItem(item, accountId);
    }

    public static Packet showBoughtCashPackage(List<Item> cashPackage, int accountId) {
        return CashShopPackets.showBoughtCashPackage(cashPackage, accountId);
    }

    public static Packet showBoughtCashRing(Item ring, String recipient, int accountId) {
        return CashShopPackets.showBoughtCashRing(ring, recipient, accountId);
    }

    public static Packet showBoughtQuestItem(int itemId) {
        return CashShopPackets.showBoughtQuestItem(itemId);
    }

    public static Packet showBoughtInventorySlots(int type, short slots) {
        return CashShopPackets.showBoughtInventorySlots(type, slots);
    }

    public static Packet showBoughtStorageSlots(short slots) {
        return CashShopPackets.showBoughtStorageSlots(slots);
    }

    public static Packet showBoughtCharacterSlot(short slots) {
        return CashShopPackets.showBoughtCharacterSlot(slots);
    }

    public static Packet showGiftSucceed(String to, ModifiedCashItemDO item) {
        return CashShopPackets.showGiftSucceed(to, item);
    }

    public static Packet showGifts(List<Pair<Item, String>> gifts) {
        return CashShopPackets.showGifts(gifts);
    }

    public static Packet takeFromCashInventory(Item item) {
        return CashShopPackets.takeFromCashInventory(item);
    }

    public static Packet putIntoCashInventory(Item item, int accountId) {
        return CashShopPackets.putIntoCashInventory(item, accountId);
    }

    public static Packet deleteCashItem(Item item) {
        return CashShopPackets.deleteCashItem(item);
    }

    public static Packet refundCashItem(Item item, int maplePoints) {
        return CashShopPackets.refundCashItem(item, maplePoints);
    }

    public static Packet showCashShopMessage(byte message) {
        return CashShopPackets.showCashShopMessage(message);
    }

    public static Packet showWishList(Character mc, boolean update) {
        return CashShopPackets.showWishList(mc, update);
    }

    public static Packet showCouponRedeemedItems(int accountId, int maplePoints, int mesos, List<Item> cashItems, List<Pair<Integer, Integer>> items) {
        return CashShopPackets.showCouponRedeemedItems(accountId, maplePoints, mesos, cashItems, items);
    }

    public static Packet onCashItemGachaponOpenFailed() {
        return CashShopPackets.onCashItemGachaponOpenFailed();
    }

    public static Packet onCashGachaponOpenSuccess(int accountid, long boxCashId, int remainingBoxes, Item reward, int rewardItemId, int rewardQuantity, boolean bJackpot) {
        return CashShopPackets.onCashGachaponOpenSuccess(accountid, boxCashId, remainingBoxes, reward, rewardItemId, rewardQuantity, bJackpot);
    }

    public static Packet sendWorldTransferRules(int error, Client c) {
        return CashShopPackets.sendWorldTransferRules(error, c);
    }

    public static Packet showWorldTransferSuccess(Item item, int accountId) {
        return CashShopPackets.showWorldTransferSuccess(item, accountId);
    }

    public static Packet showWorldTransferCancel(boolean success) {
        return CashShopPackets.showWorldTransferCancel(success);
    }

    public static Packet sendNameTransferRules(int error) {
        return CashShopPackets.sendNameTransferRules(error);
    }

    public static Packet sendNameTransferCheck(String availableName, boolean canUseName) {
        return CashShopPackets.sendNameTransferCheck(availableName, canUseName);
    }

    public static Packet showNameChangeSuccess(Item item, int accountId) {
        return CashShopPackets.showNameChangeSuccess(item, accountId);
    }

    public static Packet showNameChangeCancel(boolean success) {
        return CashShopPackets.showNameChangeCancel(success);
    }

    public static Packet showMTSCash(Character chr) {
        return CashShopPackets.showMTSCash(chr);
    }

    public static Packet sendMTS(List<MTSItemInfo> items, int tab, int type, int page, int pages) {
        return CashShopPackets.sendMTS(items, tab, type, page, pages);
    }

    public static Packet MTSWantedListingOver(int nx, int items) {
        return CashShopPackets.MTSWantedListingOver(nx, items);
    }

    public static Packet MTSConfirmSell() {
        return CashShopPackets.MTSConfirmSell();
    }

    public static Packet MTSConfirmBuy() {
        return CashShopPackets.MTSConfirmBuy();
    }

    public static Packet MTSFailBuy() {
        return CashShopPackets.MTSFailBuy();
    }

    public static Packet MTSConfirmTransfer(int quantity, int pos) {
        return CashShopPackets.MTSConfirmTransfer(quantity, pos);
    }

    public static Packet notYetSoldInv(List<MTSItemInfo> items) {
        return CashShopPackets.notYetSoldInv(items);
    }

    public static Packet transferInventory(List<MTSItemInfo> items) {
        return CashShopPackets.transferInventory(items);
    }

    public static Packet UseTreasureBox(int type) {
        return CashShopPackets.UseTreasureBox(type);
    }

    // MiniGamePackets
    public static Packet getMiniGame(Client c, MiniGame minigame, boolean owner, int piece) {
        return MiniGamePackets.getMiniGame(c, minigame, owner, piece);
    }

    public static Packet getMiniGameReady(MiniGame game) {
        return MiniGamePackets.getMiniGameReady(game);
    }

    public static Packet getMiniGameUnReady(MiniGame game) {
        return MiniGamePackets.getMiniGameUnReady(game);
    }

    public static Packet getMiniGameStart(MiniGame game, int loser) {
        return MiniGamePackets.getMiniGameStart(game, loser);
    }

    public static Packet getMiniGameSkipOwner(MiniGame game) {
        return MiniGamePackets.getMiniGameSkipOwner(game);
    }

    public static Packet getMiniGameSkipVisitor(MiniGame game) {
        return MiniGamePackets.getMiniGameSkipVisitor(game);
    }

    public static Packet getMiniGameRequestTie(MiniGame game) {
        return MiniGamePackets.getMiniGameRequestTie(game);
    }

    public static Packet getMiniGameDenyTie(MiniGame game) {
        return MiniGamePackets.getMiniGameDenyTie(game);
    }

    public static Packet getMiniGameMoveOmok(MiniGame game, int move1, int move2, int move3) {
        return MiniGamePackets.getMiniGameMoveOmok(game, move1, move2, move3);
    }

    public static Packet getMiniGameNewVisitor(MiniGame minigame, Character chr, int slot) {
        return MiniGamePackets.getMiniGameNewVisitor(minigame, chr, slot);
    }

    public static Packet getMiniGameRemoveVisitor() {
        return MiniGamePackets.getMiniGameRemoveVisitor();
    }

    public static Packet getMiniGameOwnerWin(MiniGame game, boolean forfeit) {
        return MiniGamePackets.getMiniGameOwnerWin(game, forfeit);
    }

    public static Packet getMiniGameVisitorWin(MiniGame game, boolean forfeit) {
        return MiniGamePackets.getMiniGameVisitorWin(game, forfeit);
    }

    public static Packet getMiniGameTie(MiniGame game) {
        return MiniGamePackets.getMiniGameTie(game);
    }

    public static Packet getMiniGameClose(boolean visitor, int type) {
        return MiniGamePackets.getMiniGameClose(visitor, type);
    }

    public static Packet getMatchCard(Client c, MiniGame minigame, boolean owner, int piece) {
        return MiniGamePackets.getMatchCard(c, minigame, owner, piece);
    }

    public static Packet getMatchCardStart(MiniGame game, int loser) {
        return MiniGamePackets.getMatchCardStart(game, loser);
    }

    public static Packet getMatchCardNewVisitor(MiniGame minigame, Character chr, int slot) {
        return MiniGamePackets.getMatchCardNewVisitor(minigame, chr, slot);
    }

    public static Packet getMatchCardSelect(MiniGame game, int turn, int slot, int firstslot, int type) {
        return MiniGamePackets.getMatchCardSelect(game, turn, slot, firstslot, type);
    }

    public static Packet getMiniRoomError(int status) {
        return MiniGamePackets.getMiniRoomError(status);
    }

    public static Packet addOmokBox(Character chr, int amount, int type) {
        return MiniGamePackets.addOmokBox(chr, amount, type);
    }

    public static Packet addMatchCardBox(Character chr, int amount, int type) {
        return MiniGamePackets.addMatchCardBox(chr, amount, type);
    }

    public static Packet removeMinigameBox(Character chr) {
        return MiniGamePackets.removeMinigameBox(chr);
    }

    public static Packet getPlayerShop(PlayerShop shop, boolean owner) {
        return MiniGamePackets.getPlayerShop(shop, owner);
    }

    public static Packet getPlayerShopChat(Character chr, String chat, boolean owner) {
        return MiniGamePackets.getPlayerShopChat(chr, chat, owner);
    }

    public static Packet getPlayerShopChat(Character chr, String chat, byte slot) {
        return MiniGamePackets.getPlayerShopChat(chr, chat, slot);
    }

    public static Packet getPlayerShopNewVisitor(Character chr, int slot) {
        return MiniGamePackets.getPlayerShopNewVisitor(chr, slot);
    }

    public static Packet getPlayerShopRemoveVisitor(int slot) {
        return MiniGamePackets.getPlayerShopRemoveVisitor(slot);
    }

    public static Packet getPlayerShopItemUpdate(PlayerShop shop) {
        return MiniGamePackets.getPlayerShopItemUpdate(shop);
    }

    public static Packet getPlayerShopOwnerUpdate(PlayerShop.SoldItem item, int position) {
        return MiniGamePackets.getPlayerShopOwnerUpdate(item, position);
    }

    public static Packet updatePlayerShopBox(PlayerShop shop) {
        return MiniGamePackets.updatePlayerShopBox(shop);
    }

    public static Packet removePlayerShopBox(PlayerShop shop) {
        return MiniGamePackets.removePlayerShopBox(shop);
    }

    public static Packet getTradeStart(Client c, Trade trade, byte number) {
        return MiniGamePackets.getTradeStart(c, trade, number);
    }

    public static Packet getTradeConfirmation() {
        return MiniGamePackets.getTradeConfirmation();
    }

    public static Packet getTradeResult(byte number, byte operation) {
        return MiniGamePackets.getTradeResult(number, operation);
    }

    public static Packet getTradePartnerAdd(Character chr) {
        return MiniGamePackets.getTradePartnerAdd(chr);
    }

    public static Packet tradeInvite(Character chr) {
        return MiniGamePackets.tradeInvite(chr);
    }

    public static Packet getTradeMesoSet(byte number, int meso) {
        return MiniGamePackets.getTradeMesoSet(number, meso);
    }

    public static Packet getTradeItemAdd(byte number, Item item) {
        return MiniGamePackets.getTradeItemAdd(number, item);
    }

    public static Packet getTradeChat(Character chr, String chat, boolean owner) {
        return MiniGamePackets.getTradeChat(chr, chat, owner);
    }

    public static Packet hiredMerchantBox() {
        return MiniGamePackets.hiredMerchantBox();
    }

    public static Packet getHiredMerchant(Character chr, HiredMerchant hm, boolean firstTime) {
        return MiniGamePackets.getHiredMerchant(chr, hm, firstTime);
    }

    public static Packet updateHiredMerchant(HiredMerchant hm, Character chr) {
        return MiniGamePackets.updateHiredMerchant(hm, chr);
    }

    public static Packet hiredMerchantChat(String message, byte slot) {
        return MiniGamePackets.hiredMerchantChat(message, slot);
    }

    public static Packet hiredMerchantVisitorLeave(int slot) {
        return MiniGamePackets.hiredMerchantVisitorLeave(slot);
    }

    public static Packet hiredMerchantOwnerLeave() {
        return MiniGamePackets.hiredMerchantOwnerLeave();
    }

    public static Packet hiredMerchantOwnerMaintenanceLeave() {
        return MiniGamePackets.hiredMerchantOwnerMaintenanceLeave();
    }

    public static Packet hiredMerchantMaintenanceMessage() {
        return MiniGamePackets.hiredMerchantMaintenanceMessage();
    }

    public static Packet leaveHiredMerchant(int slot, int status2) {
        return MiniGamePackets.leaveHiredMerchant(slot, status2);
    }

    public static Packet viewMerchantVisitorHistory(List<HiredMerchant.PastVisitor> pastVisitors) {
        return MiniGamePackets.viewMerchantVisitorHistory(pastVisitors);
    }

    public static Packet viewMerchantBlacklist(Set<String> chrNames) {
        return MiniGamePackets.viewMerchantBlacklist(chrNames);
    }

    public static Packet hiredMerchantVisitorAdd(Character chr, int slot) {
        return MiniGamePackets.hiredMerchantVisitorAdd(chr, slot);
    }

    public static Packet spawnHiredMerchantBox(HiredMerchant hm) {
        return MiniGamePackets.spawnHiredMerchantBox(hm);
    }

    public static Packet removeHiredMerchantBox(int id) {
        return MiniGamePackets.removeHiredMerchantBox(id);
    }

    public static Packet updateHiredMerchantBox(HiredMerchant hm) {
        return MiniGamePackets.updateHiredMerchantBox(hm);
    }

    public static Packet getFredrick(byte op) {
        return MiniGamePackets.getFredrick(op);
    }

    public static Packet getFredrick(Character chr, List<HiredMerchantsDO> merchants) {
        return MiniGamePackets.getFredrick(chr, merchants);
    }

    public static Packet fredrickMessage(byte operation) {
        return MiniGamePackets.fredrickMessage(operation);
    }

    public static Packet openRPSNPC() {
        return MiniGamePackets.openRPSNPC();
    }

    public static Packet rpsMesoError(int mesos) {
        return MiniGamePackets.rpsMesoError(mesos);
    }

    public static Packet rpsSelection(byte selection, byte answer) {
        return MiniGamePackets.rpsSelection(selection, answer);
    }

    public static Packet rpsMode(byte mode) {
        return MiniGamePackets.rpsMode(mode);
    }

    public static Packet getOwlMessage(int msg) {
        return MiniGamePackets.getOwlMessage(msg);
    }

    public static Packet owlOfMinerva(Client c, int itemId, List<Pair<PlayerShopItem, AbstractMapObject>> hmsAvailable) {
        return MiniGamePackets.owlOfMinerva(c, itemId, hmsAvailable);
    }

    public static Packet getOwlOpen(List<Integer> owlLeaderboards) {
        return MiniGamePackets.getOwlOpen(owlLeaderboards);
    }

    public static Packet retrieveFirstMessage() {
        return MiniGamePackets.retrieveFirstMessage();
    }

    public static Packet remoteChannelChange(byte ch) {
        return MiniGamePackets.remoteChannelChange(ch);
    }

    // MobPackets
    public static Packet spawnMonster(Monster life, boolean newSpawn) {
        return MobPackets.spawnMonster(life, newSpawn);
    }

    public static Packet spawnMonster(Monster life, boolean newSpawn, int effect) {
        return MobPackets.spawnMonster(life, newSpawn, effect);
    }

    public static Packet controlMonster(Monster life, boolean newSpawn, boolean aggro) {
        return MobPackets.controlMonster(life, newSpawn, aggro);
    }

    public static Packet stopControllingMonster(int oid) {
        return MobPackets.stopControllingMonster(oid);
    }

    public static Packet moveMonster(int oid, boolean skillPossible, int skill, int skillId, int skillLevel, int pOption, Point startPos, InPacket movementPacket, long movementDataLength) {
        return MobPackets.moveMonster(oid, skillPossible, skill, skillId, skillLevel, pOption, startPos, movementPacket, movementDataLength);
    }

    public static Packet moveMonsterResponse(int objectid, short moveid, int currentMp, boolean useSkills) {
        return MobPackets.moveMonsterResponse(objectid, moveid, currentMp, useSkills);
    }

    public static Packet moveMonsterResponse(int objectid, short moveid, int currentMp, boolean useSkills, int skillId, int skillLevel) {
        return MobPackets.moveMonsterResponse(objectid, moveid, currentMp, useSkills, skillId, skillLevel);
    }

    public static Packet killMonster(int objId, boolean animation) {
        return MobPackets.killMonster(objId, animation);
    }

    public static Packet killMonster(int objId, int animation) {
        return MobPackets.killMonster(objId, animation);
    }

    public static Packet damageMonster(int oid, int damage) {
        return MobPackets.damageMonster(oid, damage);
    }

    public static Packet healMonster(int oid, int heal, int curhp, int maxhp) {
        return MobPackets.healMonster(oid, heal, curhp, maxhp);
    }

    public static Packet showMonsterHP(int oid, int remhppercentage) {
        return MobPackets.showMonsterHP(oid, remhppercentage);
    }

    public static Packet showBossHP(int oid, int currHP, int maxHP, byte tagColor, byte tagBgColor) {
        return MobPackets.showBossHP(oid, currHP, maxHP, tagColor, tagBgColor);
    }

    public static Packet customShowBossHP(byte call, int oid, long currHP, long maxHP, byte tagColor, byte tagBgColor) {
        return MobPackets.customShowBossHP(call, oid, currHP, maxHP, tagColor, tagBgColor);
    }

    public static Packet applyMonsterStatus(final int oid, final MonsterStatusEffect mse, final List<Integer> reflection) {
        return MobPackets.applyMonsterStatus(oid, mse, reflection);
    }

    public static Packet cancelMonsterStatus(int oid, Map<MonsterStatus, Integer> stats) {
        return MobPackets.cancelMonsterStatus(oid, stats);
    }

    public static Packet catchMonster(int mobOid, byte success) {
        return MobPackets.catchMonster(mobOid, success);
    }

    public static Packet catchMonster(int mobOid, int itemid, byte success) {
        return MobPackets.catchMonster(mobOid, itemid, success);
    }

    public static Packet catchMessage(int message) {
        return MobPackets.catchMessage(message);
    }

    public static Packet spawnFakeMonster(Monster life, int effect) {
        return MobPackets.spawnFakeMonster(life, effect);
    }

    public static Packet makeMonsterReal(Monster life) {
        return MobPackets.makeMonsterReal(life);
    }

    public static Packet removeMonsterInvisibility(Monster life) {
        return MobPackets.removeMonsterInvisibility(life);
    }

    public static Packet makeMonsterInvisible(Monster life) {
        return MobPackets.makeMonsterInvisible(life);
    }

    public static Packet MobDamageMobFriendly(Monster mob, int damage, int remainingHp) {
        return MobPackets.MobDamageMobFriendly(mob, damage, remainingHp);
    }

    // PetPackets
    public static Packet showPet(Character chr, Pet pet, boolean remove, boolean hunger) {
        return PetPackets.showPet(chr, pet, remove, hunger);
    }

    public static Packet movePet(int cid, int pid, byte slot, List<LifeMovementFragment> moves) {
        return PetPackets.movePet(cid, pid, slot, moves);
    }

    public static Packet petChat(int cid, byte index, int act, String text) {
        return PetPackets.petChat(cid, index, act, text);
    }

    public static Packet petFoodResponse(int cid, byte index, boolean success, boolean balloonType) {
        return PetPackets.petFoodResponse(cid, index, success, balloonType);
    }

    public static Packet commandResponse(int cid, byte index, boolean talk, int animation, boolean balloonType) {
        return PetPackets.commandResponse(cid, index, talk, animation, balloonType);
    }

    public static Packet showOwnPetLevelUp(byte index) {
        return PetPackets.showOwnPetLevelUp(index);
    }

    public static Packet showPetLevelUp(Character chr, byte index) {
        return PetPackets.showPetLevelUp(chr, index);
    }

    public static Packet changePetName(Character chr, String newname, int slot) {
        return PetPackets.changePetName(chr, newname, slot);
    }

    public static Packet loadExceptionList(final int cid, final int petId, final byte petIdx, final List<Integer> data) {
        return PetPackets.loadExceptionList(cid, petId, petIdx, data);
    }

    public static Packet petStatUpdate(Character chr) {
        return PetPackets.petStatUpdate(chr);
    }

    // AdminPackets
    public static Packet getGMEffect(int type, byte mode) {
        return AdminPackets.getGMEffect(type, mode);
    }

    public static Packet getPermBan(byte reason) {
        return AdminPackets.getPermBan(reason);
    }

    public static Packet getTempBan(long timestampTill, byte reason) {
        return AdminPackets.getTempBan(timestampTill, reason);
    }

    public static Packet sendPolice() {
        return AdminPackets.sendPolice();
    }

    public static Packet sendPolice(String text) {
        return AdminPackets.sendPolice(text);
    }

    public static Packet findMerchantResponse(boolean map, int extra) {
        return AdminPackets.findMerchantResponse(map, extra);
    }

    public static Packet disableMinimap() {
        return AdminPackets.disableMinimap();
    }

    // MiscPackets
    public static Packet enableTV() {
        return MiscPackets.enableTV();
    }

    public static Packet removeTV() {
        return MiscPackets.removeTV();
    }

    public static Packet sendTV(Character chr, List<String> messages, int type, Character partner) {
        return MiscPackets.sendTV(chr, messages, type, partner);
    }

    public static Packet enableActions() {
        return MiscPackets.enableActions();
    }

    public static Packet updatePlayerStats(List<Pair<Stat, Integer>> stats, boolean enableActions, Character chr) {
        return MiscPackets.updatePlayerStats(stats, enableActions, chr);
    }

    public static Packet getCharInfo(Character chr) {
        return MiscPackets.getCharInfo(chr);
    }

    public static Packet charInfo(Character chr) {
        return MiscPackets.charInfo(chr);
    }

    public static Packet giveBuff(int buffid, int bufflength, List<Pair<BuffStat, Integer>> statups) {
        return MiscPackets.giveBuff(buffid, bufflength, statups);
    }

    public static Packet giveForeignBuff(int chrId, List<Pair<BuffStat, Integer>> statups) {
        return MiscPackets.giveForeignBuff(chrId, statups);
    }

    public static Packet cancelBuff(List<BuffStat> statups) {
        return MiscPackets.cancelBuff(statups);
    }

    public static Packet cancelForeignBuff(int chrId, List<BuffStat> statups) {
        return MiscPackets.cancelForeignBuff(chrId, statups);
    }

    public static Packet giveDebuff(List<Pair<Disease, Integer>> statups, MobSkill skill) {
        return MiscPackets.giveDebuff(statups, skill);
    }

    public static Packet giveForeignDebuff(int chrId, List<Pair<Disease, Integer>> statups, MobSkill skill) {
        return MiscPackets.giveForeignDebuff(chrId, statups, skill);
    }

    public static Packet cancelDebuff(long mask) {
        return MiscPackets.cancelDebuff(mask);
    }

    public static Packet cancelForeignDebuff(int cid, long mask) {
        return MiscPackets.cancelForeignDebuff(cid, mask);
    }

    public static Packet cancelForeignFirstDebuff(int cid, long mask) {
        return MiscPackets.cancelForeignFirstDebuff(cid, mask);
    }

    public static Packet giveForeignSlowDebuff(int chrId, List<Pair<Disease, Integer>> statups, MobSkill skill) {
        return MiscPackets.giveForeignSlowDebuff(chrId, statups, skill);
    }

    public static Packet cancelForeignSlowDebuff(int chrId) {
        return MiscPackets.cancelForeignSlowDebuff(chrId);
    }

    public static Packet giveForeignWKChargeEffect(int cid, int buffid, List<Pair<BuffStat, Integer>> statups) {
        return MiscPackets.giveForeignWKChargeEffect(cid, buffid, statups);
    }

    public static Packet givePirateBuff(List<Pair<BuffStat, Integer>> statups, int buffid, int duration) {
        return MiscPackets.givePirateBuff(statups, buffid, duration);
    }

    public static Packet giveForeignPirateBuff(int cid, int buffid, int time, List<Pair<BuffStat, Integer>> statups) {
        return MiscPackets.giveForeignPirateBuff(cid, buffid, time, statups);
    }

    public static Packet giveFinalAttack(int skillid, int time) {
        return MiscPackets.giveFinalAttack(skillid, time);
    }

    public static Packet updateSkill(int skillId, int level, int masterlevel, long expiration) {
        return MiscPackets.updateSkill(skillId, level, masterlevel, expiration);
    }

    public static Packet skillCooldown(int sid, int time) {
        return MiscPackets.skillCooldown(sid, time);
    }

    public static Packet skillBookResult(Character chr, int skillid, int maxlevel, boolean canuse, boolean success) {
        return MiscPackets.skillBookResult(chr, skillid, maxlevel, canuse, success);
    }

    public static Packet getMacros(SkillMacro[] macros) {
        return MiscPackets.getMacros(macros);
    }

    public static Packet updateMount(int charid, Mount mount, boolean levelup) {
        return MiscPackets.updateMount(charid, mount, levelup);
    }

    public static Packet showMonsterRiding(int cid, Mount mount) {
        return MiscPackets.showMonsterRiding(cid, mount);
    }

    public static Packet useChalkboard(Character chr, boolean close) {
        return MiscPackets.useChalkboard(chr, close);
    }

    public static Packet openUI(byte ui) {
        return MiscPackets.openUI(ui);
    }

    public static Packet lockUI(boolean enable) {
        return MiscPackets.lockUI(enable);
    }

    public static Packet disableUI(boolean enable) {
        return MiscPackets.disableUI(enable);
    }

    public static Packet getKeymap(Map<Integer, KeyBinding> keybindings) {
        return MiscPackets.getKeymap(keybindings);
    }

    public static Packet QuickslotMappedInit(QuickslotBinding pQuickslot) {
        return MiscPackets.QuickslotMappedInit(pQuickslot);
    }

    public static Packet showCombo(int count) {
        return MiscPackets.showCombo(count);
    }

    public static Packet resetForcedStats() {
        return MiscPackets.resetForcedStats();
    }

    public static Packet aranGodlyStats() {
        return MiscPackets.aranGodlyStats();
    }

    public static Packet updateAreaInfo(int area, String info) {
        return MiscPackets.updateAreaInfo(area, info);
    }

    public static Packet getGPMessage(int gpChange) {
        return MiscPackets.getGPMessage(gpChange);
    }

    public static Packet addCard(boolean full, int cardid, int level) {
        return MiscPackets.addCard(full, cardid, level);
    }

    public static Packet showGainCard() {
        return MiscPackets.showGainCard();
    }

    public static Packet showForeignCardEffect(int id) {
        return MiscPackets.showForeignCardEffect(id);
    }

    public static Packet changeCover(int cardid) {
        return MiscPackets.changeCover(cardid);
    }

    public static Packet onNewYearCardRes(Character user, int cardId, int mode, int msg) {
        return MiscPackets.onNewYearCardRes(user, cardId, mode, msg);
    }

    public static Packet onNewYearCardRes(Character user, NewYearCardRecord newyear, int mode, int msg) {
        return PacketHelper.onNewYearCardRes(user, newyear, mode, msg);
    }

    public static Packet earnTitleMessage(String msg) {
        return MiscPackets.earnTitleMessage(msg);
    }

    public static Packet sendYellowTip(String tip) {
        return MiscPackets.sendYellowTip(tip);
    }

    public static Packet gachaponMessage(Item item, String town, Character player) {
        return MiscPackets.gachaponMessage(item, town, player);
    }

    public static Packet showEventInstructions() {
        return MiscPackets.showEventInstructions();
    }

    public static Packet bunnyPacket() {
        return MiscPackets.bunnyPacket();
    }

    public static Packet hpqMessage(String text) {
        return MiscPackets.hpqMessage(text);
    }

    public static Packet rollSnowBall(boolean entermap, int state, Snowball ball0, Snowball ball1) {
        return MiscPackets.rollSnowBall(entermap, state, ball0, ball1);
    }

    public static Packet hitSnowBall(int what, int damage) {
        return MiscPackets.hitSnowBall(what, damage);
    }

    public static Packet snowballMessage(int team, int message) {
        return MiscPackets.snowballMessage(team, message);
    }

    public static Packet coconutScore(int team1, int team2) {
        return MiscPackets.coconutScore(team1, team2);
    }

    public static Packet hitCoconut(boolean spawn, int id, int type) {
        return MiscPackets.hitCoconut(spawn, id, type);
    }

    public static Packet CPUpdate(boolean party, int curCP, int totalCP, int team) {
        return MiscPackets.CPUpdate(party, curCP, totalCP, team);
    }

    public static Packet CPQMessage(byte message) {
        return MiscPackets.CPQMessage(message);
    }

    public static Packet playerSummoned(String name, int tab, int number) {
        return MiscPackets.playerSummoned(name, tab, number);
    }

    public static Packet playerDiedMessage(String name, int lostCP, int team) {
        return MiscPackets.playerDiedMessage(name, lostCP, team);
    }

    public static Packet startMonsterCarnival(Character chr, int team, int opposition) {
        return MiscPackets.startMonsterCarnival(chr, team, opposition);
    }

    public static Packet sheepRanchInfo(byte wolf, byte sheep) {
        return MiscPackets.sheepRanchInfo(wolf, sheep);
    }

    public static Packet sheepRanchClothes(int id, byte clothes) {
        return MiscPackets.sheepRanchClothes(id, clothes);
    }

    public static Packet pyramidGauge(int gauge) {
        return MiscPackets.pyramidGauge(gauge);
    }

    public static Packet pyramidScore(byte score, int exp) {
        return MiscPackets.pyramidScore(score, exp);
    }

    public static Packet incubatorResult() {
        return MiscPackets.incubatorResult();
    }

    public static Packet getDojoInfo(String info) {
        return MiscPackets.getDojoInfo(info);
    }

    public static Packet getDojoInfoMessage(String message) {
        return MiscPackets.getDojoInfoMessage(message);
    }

    public static Packet sendDojoAnimation(byte firstByte, String animation) {
        return MiscPackets.sendDojoAnimation(firstByte, animation);
    }

    public static Packet updateDojoStats(Character chr, int belt) {
        return MiscPackets.updateDojoStats(chr, belt);
    }

    public static Packet dojoWarpUp() {
        return MiscPackets.dojoWarpUp();
    }

    public static Packet getEnergy(String info, int amount) {
        return MiscPackets.getEnergy(info, amount);
    }

    public static Packet showAriantScoreBoard() {
        return MiscPackets.showAriantScoreBoard();
    }

    public static Packet updateAriantPQRanking(Map<Character, Integer> playerScore) {
        return MiscPackets.updateAriantPQRanking(playerScore);
    }

    public static Packet updateWitchTowerScore(int score) {
        return MiscPackets.updateWitchTowerScore(score);
    }

    public static Packet makerResult(boolean success, int itemMade, int itemCount, int mesos, List<Pair<Integer, Integer>> itemsLost, int catalystID, List<Integer> INCBuffGems) {
        return MiscPackets.makerResult(success, itemMade, itemCount, mesos, itemsLost, catalystID, INCBuffGems);
    }

    public static Packet makerResultCrystal(int itemIdGained, int itemIdLost) {
        return MiscPackets.makerResultCrystal(itemIdGained, itemIdLost);
    }

    public static Packet makerResultDesynth(int itemId, int mesos, List<Pair<Integer, Integer>> itemsGained) {
        return MiscPackets.makerResultDesynth(itemId, mesos, itemsGained);
    }

    public static Packet makerEnableActions() {
        return MiscPackets.makerEnableActions();
    }

    public static Packet showMakerEffect(boolean makerSucceeded) {
        return MiscPackets.showMakerEffect(makerSucceeded);
    }

    public static Packet showForeignMakerEffect(int cid, boolean makerSucceeded) {
        return MiscPackets.showForeignMakerEffect(cid, makerSucceeded);
    }

    public static Packet showRecovery(int chrId, byte amount) {
        return MiscPackets.showRecovery(chrId, amount);
    }

    public static Packet showOwnRecovery(byte heal) {
        return MiscPackets.showOwnRecovery(heal);
    }

    public static Packet showWheelsLeft(int left) {
        return MiscPackets.showWheelsLeft(left);
    }

    public static Packet questError(short quest) {
        return MiscPackets.questError(quest);
    }

    public static Packet questFailure(byte type) {
        return MiscPackets.questFailure(type);
    }

    public static Packet questExpire(short quest) {
        return MiscPackets.questExpire(quest);
    }

    public static Packet updateQuest(Character chr, QuestStatus qs, boolean infoUpdate) {
        return MiscPackets.updateQuest(chr, qs, infoUpdate);
    }

    public static Packet updateQuestInfo(short quest, int npc) {
        return MiscPackets.updateQuestInfo(quest, npc);
    }

    public static Packet updateQuestFinish(short quest, int npc, short nextquest) {
        return MiscPackets.updateQuestFinish(quest, npc, nextquest);
    }

    public static Packet addQuestTimeLimit(final short quest, final int time) {
        return MiscPackets.addQuestTimeLimit(quest, time);
    }

    public static Packet removeQuestTimeLimit(final short quest) {
        return MiscPackets.removeQuestTimeLimit(quest);
    }

    public static Packet forfeitQuest(short quest) {
        return MiscPackets.forfeitQuest(quest);
    }

    public static Packet completeQuest(short quest, long time) {
        return MiscPackets.completeQuest(quest, time);
    }

    public static Packet getShowQuestCompletion(int id) {
        return MiscPackets.getShowQuestCompletion(id);
    }

    public static Packet onNotifyHPDecByField(int change) {
        return MiscPackets.onNotifyHPDecByField(change);
    }

    public static Packet customPacket(String packet) {
        return MiscPackets.customPacket(packet);
    }

    public static Packet customPacket(byte[] packet) {
        return MiscPackets.customPacket(packet);
    }

    public static Packet sendHint(String hint, int width, int height) {
        return FieldPackets.sendHint(hint, width, height);
    }

    public static Packet getShowExpGain(int gain, int equip, int party, boolean inChat, boolean white) {
        return PacketHelper.getShowExpGain(gain, equip, party, inChat, white);
    }

    public static Packet giveFameResponse(int mode, String charname, int newfame) {
        return PacketHelper.giveFameResponse(mode, charname, newfame);
    }

    public static Packet receiveFame(int mode, String charnameFrom) {
        return PacketHelper.receiveFame(mode, charnameFrom);
    }

    public static Packet getShowFameGain(int gain) {
        return PacketHelper.getShowFameGain(gain);
    }

    public static Packet getShowMesoGain(int gain, boolean inChat) {
        return PacketHelper.getShowMesoGain(gain, inChat);
    }

    public static Packet showOXQuiz(int questionSet, int questionId, boolean askQuestion) {
        return PacketHelper.showOXQuiz(questionSet, questionId, askQuestion);
    }

    public static Packet trockRefreshMapList(Character chr, boolean delete, boolean vip) {
        return PacketHelper.trockRefreshMapList(chr, delete, vip);
    }

    public static Packet giveFameErrorResponse(int status) {
        return PacketHelper.giveFameErrorResponse(status);
    }

    public static Packet leftKnockBack() {
        return PacketHelper.leftKnockBack();
    }

    public static Packet sendAutoHpPot(int itemId) {
        return PacketHelper.sendAutoHpPot(itemId);
    }

    public static Packet sendAutoMpPot(int itemId) {
        return PacketHelper.sendAutoMpPot(itemId);
    }

    public static Packet sendVegaScroll(int op) {
        return PacketHelper.sendVegaScroll(op);
    }

    // WeddingPackets
    public static Packet OnNotifyWeddingPartnerTransfer(int mapid, int channel) {
        return WeddingPackets.OnNotifyWeddingPartnerTransfer(mapid, channel);
    }

    public static Packet onWeddingGiftResult(byte mode, List<String> names, List<Item> items) {
        return WeddingPackets.onWeddingGiftResult(mode, names, items);
    }

    public static Packet sendWishList() {
        return WeddingPackets.sendWishList();
    }

    public static Packet OnWeddingProgress(boolean start, int groomId, int brideId, byte state) {
        return WeddingPackets.OnWeddingProgress(start, groomId, brideId, state);
    }

    public static Packet OnMarriageResult(byte mode) {
        return WeddingPackets.OnMarriageResult(mode);
    }

    public static Packet OnMarriageResult(int mode, Character chr, boolean success) {
        return WeddingPackets.OnMarriageResult(mode, chr, success);
    }

    public static Packet onMarriageRequest(String name, int id) {
        return WeddingPackets.onMarriageRequest(name, id);
    }

    public static Packet sendWeddingInvitation(String groom, String bride) {
        return WeddingPackets.sendWeddingInvitation(groom, bride);
    }

    public static Packet onTakePhoto(String ReservedGroomName, String ReservedBrideName, int m_dwField, List<Character> m_dwUsers) {
        return WeddingPackets.onTakePhoto(ReservedGroomName, ReservedBrideName, m_dwField, m_dwUsers);
    }
}
