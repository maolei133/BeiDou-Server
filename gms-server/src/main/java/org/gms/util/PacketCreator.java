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

    /**
     * 获取时间戳
     * @param utcTimestamp UTC时间戳
     * @return 转换后的时间戳
     */
    public static long getTime(long utcTimestamp) {
        return PacketHelper.getTime(utcTimestamp);
    }

    /**
     * 显示HP恢复效果
     * @param cid 角色ID
     * @param amount 恢复量
     * @return 数据包
     */
    public static Packet showHpHealed(int cid, int amount) {
        return PacketHelper.showHpHealed(cid, amount);
    }

    // LoginPackets
    /**
     * 获取Hello包
     * @param mapleVersion 冒险岛版本
     * @param sendIv 发送IV
     * @param recvIv 接收IV
     * @return 数据包
     */
    public static Packet getHello(short mapleVersion, InitializationVector sendIv, InitializationVector recvIv) {
        return LoginPackets.getHello(mapleVersion, sendIv, recvIv);
    }

    /**
     * 获取Ping包
     * @return 数据包
     */
    public static Packet getPing() {
        return LoginPackets.getPing();
    }

    /**
     * 获取登录失败包
     * <p>
     * reason 可能的值:<br>
     * 3: ID 已删除或被封锁<br>
     * 4: 密码错误<br>
     * 5: 不是注册的 ID<br>
     * 6: 系统错误<br>
     * 7: 已经登录<br>
     * 8: 系统错误<br>
     * 9: 系统错误<br>
     * 10: 无法处理这么多连接<br>
     * 11: 只有 20 岁以上的用户可以使用此频道<br>
     * 13: 无法在此 IP 以管理员身份登录<br>
     * 14: 错误的网关或个人信息以及奇怪的韩语按钮<br>
     * 15: 正在处理该韩语按钮的请求！<br>
     * 16: 请通过电子邮件验证您的帐户...<br>
     * 17: 错误的网关或个人信息<br>
     * 21: 请通过电子邮件验证您的帐户...<br>
     * 23: 许可协议<br>
     * 25: Maple Europe 通知 =[ FUCK YOU NEXON<br>
     * 27: 一些奇怪的完整客户端通知，可能用于试用版<br>
     *
     * @param reason 登录失败的原因
     * @return 登录失败包
     */
    public static Packet getLoginFailed(int reason) {
        return LoginPackets.getLoginFailed(reason);
    }

    /**
     * 获取登录后错误包
     * @param reason 错误原因
     * @return 数据包
     */
    public static Packet getAfterLoginError(int reason) {
        return LoginPackets.getAfterLoginError(reason);
    }

    /**
     * 获取认证成功包
     * @param c 客户端对象
     * @return 数据包
     */
    public static Packet getAuthSuccess(Client c) {
        return LoginPackets.getAuthSuccess(c);
    }

    /**
     * PIN码已注册
     * @return 数据包
     */
    public static Packet pinRegistered() {
        return LoginPackets.pinRegistered();
    }

    /**
     * 请求PIN码
     * @return 数据包
     */
    public static Packet requestPin() {
        return LoginPackets.requestPin();
    }

    /**
     * 失败后请求PIN码
     * @return 数据包
     */
    public static Packet requestPinAfterFailure() {
        return LoginPackets.requestPinAfterFailure();
    }

    /**
     * 注册PIN码
     * @return 数据包
     */
    public static Packet registerPin() {
        return LoginPackets.registerPin();
    }

    /**
     * PIN码已接受
     * @return 数据包
     */
    public static Packet pinAccepted() {
        return LoginPackets.pinAccepted();
    }

    /**
     * 错误的PIC码
     * @return 数据包
     */
    public static Packet wrongPic() {
        return LoginPackets.wrongPic();
    }

    /**
     * 获取服务器列表
     * @param serverId 服务器ID
     * @param serverName 服务器名称
     * @param flag 标志
     * @param eventmsg 事件消息
     * @param channelLoad 频道负载
     * @return 数据包
     */
    public static Packet getServerList(int serverId, String serverName, int flag, String eventmsg, List<Channel> channelLoad) {
        return LoginPackets.getServerList(serverId, serverName, flag, eventmsg, channelLoad);
    }

    /**
     * 获取服务器列表结束包
     * @return 数据包
     */
    public static Packet getEndOfServerList() {
        return LoginPackets.getEndOfServerList();
    }

    /**
     * 获取服务器状态
     * @param status 状态
     * @return 数据包
     */
    public static Packet getServerStatus(int status) {
        return LoginPackets.getServerStatus(status);
    }

    /**
     * 获取服务器IP
     * @param inetAddr IP地址
     * @param port 端口
     * @param clientId 客户端ID
     * @return 数据包
     */
    public static Packet getServerIP(InetAddress inetAddr, int port, int clientId) {
        return LoginPackets.getServerIP(inetAddr, port, clientId);
    }

    /**
     * 获取频道切换包
     * @param inetAddr IP地址
     * @param port 端口
     * @return 数据包
     */
    public static Packet getChannelChange(InetAddress inetAddr, int port) {
        return LoginPackets.getChannelChange(inetAddr, port);
    }

    /**
     * 获取角色列表
     * @param c 客户端对象
     * @param serverId 服务器ID
     * @param status 状态
     * @return 数据包
     */
    public static Packet getCharList(Client c, int serverId, int status) {
        return LoginPackets.getCharList(c, serverId, status);
    }

    /**
     * 获取重新登录响应
     * @return 数据包
     */
    public static Packet getRelogResponse() {
        return LoginPackets.getRelogResponse();
    }

    /**
     * 发送访客服务条款
     * @return 数据包
     */
    public static Packet sendGuestTOS() {
        return LoginPackets.sendGuestTOS();
    }

    /**
     * 发送推荐服务器
     * @param worlds 推荐服务器列表
     * @return 数据包
     */
    public static Packet sendRecommended(List<Pair<Integer, String>> worlds) {
        return LoginPackets.sendRecommended(worlds);
    }

    /**
     * 选择世界
     * @param world 世界ID
     * @return 数据包
     */
    public static Packet selectWorld(int world) {
        return LoginPackets.selectWorld(world);
    }

    /**
     * 显示所有角色
     * @param totalWorlds 总世界数
     * @param totalChrs 总角色数
     * @return 数据包
     */
    public static Packet showAllCharacter(int totalWorlds, int totalChrs) {
        return LoginPackets.showAllCharacter(totalWorlds, totalChrs);
    }

    /**
     * 显示所有角色信息
     * @param worldid 世界ID
     * @param chars 角色列表
     * @param usePic 是否使用PIC
     * @return 数据包
     */
    public static Packet showAllCharacterInfo(int worldid, List<Character> chars, boolean usePic) {
        return LoginPackets.showAllCharacterInfo(worldid, chars, usePic);
    }

    /**
     * 添加新角色条目
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet addNewCharEntry(Character chr) {
        return LoginPackets.addNewCharEntry(chr);
    }

    /**
     * 删除角色响应
     * @param cid 角色ID
     * @param state 状态
     * @return 数据包
     */
    public static Packet deleteCharResponse(int cid, int state) {
        return LoginPackets.deleteCharResponse(cid, state);
    }

    /**
     * 角色名称响应
     * @param charname 角色名称
     * @param nameUsed 名称是否已使用
     * @return 数据包
     */
    public static Packet charNameResponse(String charname, boolean nameUsed) {
        return LoginPackets.charNameResponse(charname, nameUsed);
    }

    /**
     * 发送MapleLife角色信息
     * @return 数据包
     */
    public static Packet sendMapleLifeCharacterInfo() {
        return LoginPackets.sendMapleLifeCharacterInfo();
    }

    /**
     * 发送MapleLife名称错误
     * @return 数据包
     */
    public static Packet sendMapleLifeNameError() {
        return LoginPackets.sendMapleLifeNameError();
    }

    /**
     * 发送MapleLife错误
     * @param code 错误代码
     * @return 数据包
     */
    public static Packet sendMapleLifeError(int code) {
        return LoginPackets.sendMapleLifeError(code);
    }

    /**
     * 启用举报
     * @return 数据包
     */
    public static Packet enableReport() {
        return LoginPackets.enableReport();
    }

    /**
     * 举报响应
     * @param mode 模式
     * @return 数据包
     */
    public static Packet reportResponse(byte mode) {
        return LoginPackets.reportResponse(mode);
    }

    /**
     * 更新性别
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet updateGender(Character chr) {
        return LoginPackets.updateGender(chr);
    }

    /**
     * 发送金币限制
     * @return 数据包
     */
    public static Packet sendMesoLimit() {
        return LoginPackets.sendMesoLimit();
    }

    /**
     * 更新HP/MP警告
     * @param hp HP百分比
     * @param mp MP百分比
     * @return 数据包
     */
    public static Packet updateHpMpAlert(byte hp, byte mp) {
        return LoginPackets.updateHpMpAlert(hp, mp);
    }

    // FieldPackets
    /**
     * 获取传送到地图包
     * @param to 目标地图
     * @param spawnPoint 出生点
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet getWarpToMap(MapleMap to, int spawnPoint, Character chr) {
        return FieldPackets.getWarpToMap(to, spawnPoint, chr);
    }

    /**
     * 获取传送到地图包（指定坐标）
     * @param to 目标地图
     * @param spawnPoint 出生点
     * @param spawnPosition 出生坐标
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet getWarpToMap(MapleMap to, int spawnPoint, Point spawnPosition, Character chr) {
        return FieldPackets.getWarpToMap(to, spawnPoint, spawnPosition, chr);
    }

    /**
     * 生成传送门
     * @param townId 城镇ID
     * @param targetId 目标ID
     * @param pos 坐标
     * @return 数据包
     */
    public static Packet spawnPortal(int townId, int targetId, Point pos) {
        return FieldPackets.spawnPortal(townId, targetId, pos);
    }

    /**
     * 生成门
     * @param ownerid 拥有者ID
     * @param pos 坐标
     * @param launched 是否已发射
     * @return 数据包
     */
    public static Packet spawnDoor(int ownerid, Point pos, boolean launched) {
        return FieldPackets.spawnDoor(ownerid, pos, launched);
    }

    /**
     * 移除门
     * @param ownerId 拥有者ID
     * @param town 是否在城镇
     * @return 数据包
     */
    public static Packet removeDoor(int ownerId, boolean town) {
        return FieldPackets.removeDoor(ownerId, town);
    }

    /**
     * 生成召唤物
     * @param summon 召唤物对象
     * @param animated 是否有动画
     * @return 数据包
     */
    public static Packet spawnSummon(Summon summon, boolean animated) {
        return FieldPackets.spawnSummon(summon, animated);
    }

    /**
     * 移除召唤物
     * @param summon 召唤物对象
     * @param animated 是否有动画
     * @return 数据包
     */
    public static Packet removeSummon(Summon summon, boolean animated) {
        return FieldPackets.removeSummon(summon, animated);
    }

    /**
     * 生成风筝
     * @param objId 对象ID
     * @param itemId 物品ID
     * @param name 名称
     * @param msg 消息
     * @param pos 坐标
     * @param ft 类型
     * @return 数据包
     */
    public static Packet spawnKite(int objId, int itemId, String name, String msg, Point pos, int ft) {
        return FieldPackets.spawnKite(objId, itemId, name, msg, pos, ft);
    }

    /**
     * 移除风筝
     * @param objId 对象ID
     * @param animationType 动画类型
     * @return 数据包
     */
    public static Packet removeKite(int objId, int animationType) {
        return FieldPackets.removeKite(objId, animationType);
    }

    /**
     * 发送无法生成风筝
     * @return 数据包
     */
    public static Packet sendCannotSpawnKite() {
        return FieldPackets.sendCannotSpawnKite();
    }

    /**
     * 生成怪物迷雾
     * @param objId 对象ID
     * @param ownerMobId 拥有者怪物ID
     * @param msId 怪物技能ID
     * @param mist 迷雾对象
     * @return 数据包
     */
    public static Packet spawnMobMist(int objId, int ownerMobId, MobSkillId msId, Mist mist) {
        return FieldPackets.spawnMobMist(objId, ownerMobId, msId, mist);
    }

    /**
     * 生成迷雾
     * @param objId 对象ID
     * @param ownerId 拥有者ID
     * @param skill 技能ID
     * @param level 等级
     * @param mist 迷雾对象
     * @return 数据包
     */
    public static Packet spawnMist(int objId, int ownerId, int skill, int level, Mist mist) {
        return FieldPackets.spawnMist(objId, ownerId, skill, level, mist);
    }

    /**
     * 移除迷雾
     * @param objId 对象ID
     * @return 数据包
     */
    public static Packet removeMist(int objId) {
        return FieldPackets.removeMist(objId);
    }

    /**
     * 生成反应堆
     * @param reactor 反应堆对象
     * @return 数据包
     */
    public static Packet spawnReactor(Reactor reactor) {
        return FieldPackets.spawnReactor(reactor);
    }

    /**
     * 触发反应堆
     * @param reactor 反应堆对象
     * @param stance 姿态
     * @return 数据包
     */
    public static Packet triggerReactor(Reactor reactor, int stance) {
        return FieldPackets.triggerReactor(reactor, stance);
    }

    /**
     * 销毁反应堆
     * @param reactor 反应堆对象
     * @return 数据包
     */
    public static Packet destroyReactor(Reactor reactor) {
        return FieldPackets.destroyReactor(reactor);
    }

    /**
     * 环境变化
     * @param env 环境名称
     * @param mode 模式
     * @return 数据包
     */
    public static Packet environmentChange(String env, int mode) {
        return FieldPackets.environmentChange(env, mode);
    }

    /**
     * 音乐变化
     * @param song 音乐名称
     * @return 数据包
     */
    public static Packet musicChange(String song) {
        return FieldPackets.musicChange(song);
    }

    /**
     * 显示特效
     * @param effect 特效名称
     * @return 数据包
     */
    public static Packet showEffect(String effect) {
        return FieldPackets.showEffect(effect);
    }

    /**
     * 播放声音
     * @param sound 声音名称
     * @return 数据包
     */
    public static Packet playSound(String sound) {
        return FieldPackets.playSound(sound);
    }

    /**
     * 环境移动
     * @param env 环境名称
     * @param mode 模式
     * @return 数据包
     */
    public static Packet environmentMove(String env, int mode) {
        return FieldPackets.environmentMove(env, mode);
    }

    /**
     * 环境移动列表
     * @param envList 环境列表
     * @return 数据包
     */
    public static Packet environmentMoveList(Set<Map.Entry<String, Integer>> envList) {
        return FieldPackets.environmentMoveList(envList);
    }

    /**
     * 环境移动重置
     * @return 数据包
     */
    public static Packet environmentMoveReset() {
        return FieldPackets.environmentMoveReset();
    }

    /**
     * 开始地图特效
     * @param msg 消息
     * @param itemId 物品ID
     * @param active 是否激活
     * @return 数据包
     */
    public static Packet startMapEffect(String msg, int itemId, boolean active) {
        return FieldPackets.startMapEffect(msg, itemId, active);
    }

    /**
     * 移除地图特效
     * @return 数据包
     */
    public static Packet removeMapEffect() {
        return FieldPackets.removeMapEffect();
    }

    /**
     * 地图特效
     * @param path 路径
     * @return 数据包
     */
    public static Packet mapEffect(String path) {
        return FieldPackets.mapEffect(path);
    }

    /**
     * 地图声音
     * @param path 路径
     * @return 数据包
     */
    public static Packet mapSound(String path) {
        return FieldPackets.mapSound(path);
    }

    /**
     * 震动特效
     * @param type 类型
     * @param delay 延迟
     * @return 数据包
     */
    public static Packet trembleEffect(int type, int delay) {
        return FieldPackets.trembleEffect(type, delay);
    }

    /**
     * 显示特殊特效
     * @param effect 特效ID
     * @return 数据包
     */
    public static Packet showSpecialEffect(int effect) {
        return FieldPackets.showSpecialEffect(effect);
    }

    /**
     * 播放传送门声音
     * @return 数据包
     */
    public static Packet playPortalSound() {
        return FieldPackets.playPortalSound();
    }

    /**
     * 显示怪物图鉴拾取
     * @return 数据包
     */
    public static Packet showMonsterBookPickup() {
        return FieldPackets.showMonsterBookPickup();
    }

    /**
     * 显示装备升级
     * @return 数据包
     */
    public static Packet showEquipmentLevelUp() {
        return FieldPackets.showEquipmentLevelUp();
    }

    /**
     * 显示物品升级
     * @return 数据包
     */
    public static Packet showItemLevelup() {
        return FieldPackets.showItemLevelup();
    }

    /**
     * 显示外部特效
     * @param effect 特效ID
     * @return 数据包
     */
    public static Packet showForeignEffect(int effect) {
        return FieldPackets.showForeignEffect(effect);
    }

    /**
     * 显示外部特效（指定角色）
     * @param chrId 角色ID
     * @param effect 特效ID
     * @return 数据包
     */
    public static Packet showForeignEffect(int chrId, int effect) {
        return FieldPackets.showForeignEffect(chrId, effect);
    }

    /**
     * 显示Buff特效
     * @param chrId 角色ID
     * @param skillId 技能ID
     * @param effectId 特效ID
     * @return 数据包
     */
    public static Packet showBuffEffect(int chrId, int skillId, int effectId) {
        return FieldPackets.showBuffEffect(chrId, skillId, effectId);
    }

    /**
     * 显示Buff特效（带方向）
     * @param chrId 角色ID
     * @param skillId 技能ID
     * @param effectId 特效ID
     * @param direction 方向
     * @return 数据包
     */
    public static Packet showBuffEffect(int chrId, int skillId, int effectId, byte direction) {
        return FieldPackets.showBuffEffect(chrId, skillId, effectId, direction);
    }

    /**
     * 显示Buff特效（带等级和方向）
     * @param chrId 角色ID
     * @param skillId 技能ID
     * @param skillLv 技能等级
     * @param effectId 特效ID
     * @param direction 方向
     * @return 数据包
     */
    public static Packet showBuffEffect(int chrId, int skillId, int skillLv, int effectId, byte direction) {
        return FieldPackets.showBuffEffect(chrId, skillId, skillLv, effectId, direction);
    }

    /**
     * 显示自身Buff特效
     * @param skillId 技能ID
     * @param effectId 特效ID
     * @return 数据包
     */
    public static Packet showOwnBuffEffect(int skillId, int effectId) {
        return FieldPackets.showOwnBuffEffect(skillId, effectId);
    }

    /**
     * 显示自身狂暴
     * @param skilllevel 技能等级
     * @param Berserk 是否狂暴
     * @return 数据包
     */
    public static Packet showOwnBerserk(int skilllevel, boolean Berserk) {
        return FieldPackets.showOwnBerserk(skilllevel, Berserk);
    }

    /**
     * 显示狂暴
     * @param chrId 角色ID
     * @param skillLv 技能等级
     * @param berserk 是否狂暴
     * @return 数据包
     */
    public static Packet showBerserk(int chrId, int skillLv, boolean berserk) {
        return FieldPackets.showBerserk(chrId, skillLv, berserk);
    }

    /**
     * 技能特效
     * @param from 来源角色
     * @param skillId 技能ID
     * @param level 等级
     * @param flags 标志
     * @param speed 速度
     * @param direction 方向
     * @return 数据包
     */
    public static Packet skillEffect(Character from, int skillId, int level, byte flags, int speed, byte direction) {
        return FieldPackets.skillEffect(from, skillId, level, flags, speed, direction);
    }

    /**
     * 取消技能
     * @param from 来源角色
     * @param skillId 技能ID
     * @return 数据包
     */
    public static Packet skillCancel(Character from, int skillId) {
        return FieldPackets.skillCancel(from, skillId);
    }

    /**
     * 获取时钟
     * @param time 时间
     * @return 数据包
     */
    public static Packet getClock(Number time) {
        return FieldPackets.getClock(time);
    }

    /**
     * 获取时钟时间
     * @param hour 小时
     * @param min 分钟
     * @param sec 秒
     * @return 数据包
     */
    public static Packet getClockTime(int hour, int min, int sec) {
        return FieldPackets.getClockTime(hour, min, sec);
    }

    /**
     * 移除时钟
     * @return 数据包
     */
    public static Packet removeClock() {
        return FieldPackets.removeClock();
    }

    /**
     * 生成向导
     * @param spawn 是否生成
     * @return 数据包
     */
    public static Packet spawnGuide(boolean spawn) {
        return FieldPackets.spawnGuide(spawn);
    }

    /**
     * 向导对话
     * @param talk 对话内容
     * @return 数据包
     */
    public static Packet talkGuide(String talk) {
        return FieldPackets.talkGuide(talk);
    }

    /**
     * 向导提示
     * @param hint 提示内容
     * @return 数据包
     */
    public static Packet guideHint(int hint) {
        return FieldPackets.guideHint(hint);
    }

    /**
     * 改变背景特效
     * @param remove 是否移除
     * @param layer 层级
     * @param transition 过渡
     * @return 数据包
     */
    public static Packet changeBackgroundEffect(boolean remove, int layer, int transition) {
        return FieldPackets.changeBackgroundEffect(remove, layer, transition);
    }

    /**
     * 生成龙
     * @param dragon 龙对象
     * @return 数据包
     */
    public static Packet spawnDragon(Dragon dragon) {
        return FieldPackets.spawnDragon(dragon);
    }

    /**
     * 移动龙
     * @param dragon 龙对象
     * @param startPos 起始位置
     * @param movementPacket 移动数据包
     * @param movementDataLength 移动数据长度
     * @return 数据包
     */
    public static Packet moveDragon(Dragon dragon, Point startPos, InPacket movementPacket, long movementDataLength) {
        return FieldPackets.moveDragon(dragon, startPos, movementPacket, movementDataLength);
    }

    /**
     * 移除龙
     * @param chrId 角色ID
     * @return 数据包
     */
    public static Packet removeDragon(int chrId) {
        return FieldPackets.removeDragon(chrId);
    }

    /**
     * 移动玩家
     * @param chrId 角色ID
     * @param movementPacket 移动数据包
     * @param movementDataLength 移动数据长度
     * @return 数据包
     */
    public static Packet movePlayer(int chrId, InPacket movementPacket, long movementDataLength) {
        return FieldPackets.movePlayer(chrId, movementPacket, movementDataLength);
    }

    /**
     * 移动召唤物
     * @param cid 角色ID
     * @param oid 对象ID
     * @param startPos 起始位置
     * @param movementPacket 移动数据包
     * @param movementDataLength 移动数据长度
     * @return 数据包
     */
    public static Packet moveSummon(int cid, int oid, Point startPos, InPacket movementPacket, long movementDataLength) {
        return FieldPackets.moveSummon(cid, oid, startPos, movementPacket, movementDataLength);
    }

    /**
     * 召唤物攻击
     * @param cid 角色ID
     * @param summonOid 召唤物对象ID
     * @param direction 方向
     * @param allDamage 所有伤害
     * @return 数据包
     */
    public static Packet summonAttack(int cid, int summonOid, byte direction, List<SummonAttackEntry> allDamage) {
        return FieldPackets.summonAttack(cid, summonOid, direction, allDamage);
    }

    /**
     * 伤害召唤物
     * @param cid 角色ID
     * @param oid 对象ID
     * @param damage 伤害
     * @param monsterIdFrom 来源怪物ID
     * @return 数据包
     */
    public static Packet damageSummon(int cid, int oid, int damage, int monsterIdFrom) {
        return FieldPackets.damageSummon(cid, oid, damage, monsterIdFrom);
    }

    /**
     * 召唤技能
     * @param cid 角色ID
     * @param summonSkillId 召唤技能ID
     * @param newStance 新姿态
     * @return 数据包
     */
    public static Packet summonSkill(int cid, int summonSkillId, int newStance) {
        return FieldPackets.summonSkill(cid, summonSkillId, newStance);
    }

    /**
     * 近战攻击
     * @param chr 角色对象
     * @param skill 技能ID
     * @param skilllevel 技能等级
     * @param stance 姿态
     * @param numAttackedAndDamage 攻击数量和伤害
     * @param damage 伤害列表
     * @param speed 速度
     * @param direction 方向
     * @param display 显示
     * @return 数据包
     */
    public static Packet closeRangeAttack(Character chr, int skill, int skilllevel, int stance, int numAttackedAndDamage, Map<Integer, List<Integer>> damage, int speed, int direction, int display) {
        return FieldPackets.closeRangeAttack(chr, skill, skilllevel, stance, numAttackedAndDamage, damage, speed, direction, display);
    }

    /**
     * 远程攻击
     * @param chr 角色对象
     * @param skill 技能ID
     * @param skilllevel 技能等级
     * @param stance 姿态
     * @param numAttackedAndDamage 攻击数量和伤害
     * @param projectile 投掷物
     * @param damage 伤害列表
     * @param speed 速度
     * @param direction 方向
     * @param display 显示
     * @return 数据包
     */
    public static Packet rangedAttack(Character chr, int skill, int skilllevel, int stance, int numAttackedAndDamage, int projectile, Map<Integer, List<Integer>> damage, int speed, int direction, int display) {
        return FieldPackets.rangedAttack(chr, skill, skilllevel, stance, numAttackedAndDamage, projectile, damage, speed, direction, display);
    }

    /**
     * 魔法攻击
     * @param chr 角色对象
     * @param skill 技能ID
     * @param skilllevel 技能等级
     * @param stance 姿态
     * @param numAttackedAndDamage 攻击数量和伤害
     * @param damage 伤害列表
     * @param charge 充能
     * @param speed 速度
     * @param direction 方向
     * @param display 显示
     * @return 数据包
     */
    public static Packet magicAttack(Character chr, int skill, int skilllevel, int stance, int numAttackedAndDamage, Map<Integer, List<Integer>> damage, int charge, int speed, int direction, int display) {
        return FieldPackets.magicAttack(chr, skill, skilllevel, stance, numAttackedAndDamage, damage, charge, speed, direction, display);
    }

    /**
     * 投掷手榴弹
     * @param cid 角色ID
     * @param pos 坐标
     * @param keyDown 按键按下
     * @param skillId 技能ID
     * @param skillLevel 技能等级
     * @return 数据包
     */
    public static Packet throwGrenade(int cid, Point pos, int keyDown, int skillId, int skillLevel) {
        return FieldPackets.throwGrenade(cid, pos, keyDown, skillId, skillLevel);
    }

    /**
     * 伤害玩家
     * @param skill 技能ID
     * @param monsteridfrom 来源怪物ID
     * @param cid 角色ID
     * @param damage 伤害
     * @param fake 假伤害
     * @param direction 方向
     * @param pgmr pgmr
     * @param pgmr_1 pgmr_1
     * @param is_pg is_pg
     * @param oid 对象ID
     * @param pos_x X坐标
     * @param pos_y Y坐标
     * @return 数据包
     */
    public static Packet damagePlayer(int skill, int monsteridfrom, int cid, int damage, int fake, int direction, boolean pgmr, int pgmr_1, boolean is_pg, int oid, int pos_x, int pos_y) {
        return FieldPackets.damagePlayer(skill, monsteridfrom, cid, damage, fake, direction, pgmr, pgmr_1, is_pg, oid, pos_x, pos_y);
    }

    /**
     * 面部表情
     * @param from 来源角色
     * @param expression 表情ID
     * @return 数据包
     */
    public static Packet facialExpression(Character from, int expression) {
        return FieldPackets.facialExpression(from, expression);
    }

    /**
     * 显示椅子
     * @param characterid 角色ID
     * @param itemid 物品ID
     * @return 数据包
     */
    public static Packet showChair(int characterid, int itemid) {
        return FieldPackets.showChair(characterid, itemid);
    }

    /**
     * 取消椅子
     * @param id ID
     * @return 数据包
     */
    public static Packet cancelChair(int id) {
        return FieldPackets.cancelChair(id);
    }

    /**
     * 给予外部椅子技能特效
     * @param cid 角色ID
     * @return 数据包
     */
    public static Packet giveForeignChairSkillEffect(int cid) {
        return FieldPackets.giveForeignChairSkillEffect(cid);
    }

    /**
     * 取消外部椅子技能特效
     * @param chrId 角色ID
     * @return 数据包
     */
    public static Packet cancelForeignChairSkillEffect(int chrId) {
        return FieldPackets.cancelForeignChairSkillEffect(chrId);
    }

    /**
     * 生成玩家地图对象
     * @param target 目标客户端
     * @param chr 角色对象
     * @param enteringField 是否进入地图
     * @return 数据包
     */
    public static Packet spawnPlayerMapObject(Client target, Character chr, boolean enteringField) {
        return FieldPackets.spawnPlayerMapObject(target, chr, enteringField);
    }

    /**
     * 从地图移除玩家
     * @param chrId 角色ID
     * @return 数据包
     */
    public static Packet removePlayerFromMap(int chrId) {
        return FieldPackets.removePlayerFromMap(chrId);
    }

    /**
     * 更新角色外观
     * @param target 目标客户端
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet updateCharLook(Client target, Character chr) {
        return FieldPackets.updateCharLook(target, chr);
    }

    /**
     * 显示外部信息
     * @param cid 角色ID
     * @param path 路径
     * @return 数据包
     */
    public static Packet showForeignInfo(int cid, String path) {
        return FieldPackets.showForeignInfo(cid, path);
    }

    /**
     * 显示信息
     * @param path 路径
     * @return 数据包
     */
    public static Packet showInfo(String path) {
        return FieldPackets.showInfo(path);
    }

    /**
     * 显示介绍
     * @param path 路径
     * @return 数据包
     */
    public static Packet showIntro(String path) {
        return FieldPackets.showIntro(path);
    }

    /**
     * 显示信息文本
     * @param text 文本内容
     * @return 数据包
     */
    public static Packet showInfoText(String text) {
        return FieldPackets.showInfoText(text);
    }

    /**
     * 阻挡消息
     * @param type 类型
     * @return 数据包
     */
    public static Packet blockedMessage(int type) {
        return FieldPackets.blockedMessage(type);
    }

    /**
     * 阻挡消息2
     * @param type 类型
     * @return 数据包
     */
    public static Packet blockedMessage2(int type) {
        return FieldPackets.blockedMessage2(type);
    }

    /**
     * 船只数据包
     * @param type 类型
     * @return 数据包
     */
    public static Packet boatPacket(boolean type) {
        return FieldPackets.boatPacket(type);
    }

    /**
     * 蝙蝠魔船只数据包
     * @param type 类型
     * @return 数据包
     */
    public static Packet crogBoatPacket(boolean type) {
        return FieldPackets.crogBoatPacket(type);
    }

    /**
     * 显示强制装备
     * @param team 队伍
     * @return 数据包
     */
    public static Packet showForcedEquip(int team) {
        return FieldPackets.showForcedEquip(team);
    }

    // NpcPackets
    /**
     * 生成NPC
     * @param life NPC对象
     * @return 数据包
     */
    public static Packet spawnNPC(NPC life) {
        return NpcPackets.spawnNPC(life);
    }

    /**
     * 请求NPC控制器
     * @param life NPC对象
     * @param miniMap 是否显示在小地图
     * @return 数据包
     */
    public static Packet spawnNPCRequestController(NPC life, boolean miniMap) {
        return NpcPackets.spawnNPCRequestController(life, miniMap);
    }

    /**
     * 移除NPC
     * @param objId 对象ID
     * @return 数据包
     */
    public static Packet removeNPC(int objId) {
        return NpcPackets.removeNPC(objId);
    }

    /**
     * 移除NPC控制器
     * @param objId 对象ID
     * @return 数据包
     */
    public static Packet removeNPCController(int objId) {
        return NpcPackets.removeNPCController(objId);
    }

    /**
     * 获取NPC对话
     * @param npc NPC ID
     * @param msgType 消息类型
     * @param talk 对话内容
     * @param endBytes 结束字节
     * @param speaker 说话者
     * @return 数据包
     */
    public static Packet getNPCTalk(int npc, byte msgType, String talk, String endBytes, byte speaker) {
        return NpcPackets.getNPCTalk(npc, msgType, talk, endBytes, speaker);
    }

    /**
     * 获取次元之镜对话
     * @param talk 对话内容
     * @return 数据包
     */
    public static Packet getDimensionalMirror(String talk) {
        return NpcPackets.getDimensionalMirror(talk);
    }

    /**
     * 获取NPC对话样式
     * @param npc NPC ID
     * @param talk 对话内容
     * @param styles 样式数组
     * @return 数据包
     */
    public static Packet getNPCTalkStyle(int npc, String talk, int[] styles) {
        return NpcPackets.getNPCTalkStyle(npc, talk, styles);
    }

    /**
     * 获取NPC对话数字
     * @param npc NPC ID
     * @param talk 对话内容
     * @param def 默认值
     * @param min 最小值
     * @param max 最大值
     * @return 数据包
     */
    public static Packet getNPCTalkNum(int npc, String talk, int def, int min, int max) {
        return NpcPackets.getNPCTalkNum(npc, talk, def, min, max);
    }

    /**
     * 获取NPC对话数字（带说话者）
     * @param npc NPC ID
     * @param talk 对话内容
     * @param def 默认值
     * @param min 最小值
     * @param max 最大值
     * @param speaker 说话者
     * @return 数据包
     */
    public static Packet getNPCTalkNum(int npc, String talk, int def, int min, int max, byte speaker) {
        return NpcPackets.getNPCTalkNum(npc, talk, def, min, max, speaker);
    }

    /**
     * 获取NPC对话文本
     * @param npc NPC ID
     * @param talk 对话内容
     * @param def 默认文本
     * @return 数据包
     */
    public static Packet getNPCTalkText(int npc, String talk, String def) {
        return NpcPackets.getNPCTalkText(npc, talk, def);
    }

    /**
     * 获取NPC对话文本（带说话者）
     * @param npc NPC ID
     * @param talk 对话内容
     * @param def 默认文本
     * @param speaker 说话者
     * @return 数据包
     */
    public static Packet getNPCTalkText(int npc, String talk, String def, byte speaker) {
        return NpcPackets.getNPCTalkText(npc, talk, def, speaker);
    }

    /**
     * 提问测验
     * @param nSpeakerTypeID 说话者类型ID
     * @param nSpeakerTemplateID 说话者模板ID
     * @param nResCode 结果代码
     * @param sTitle 标题
     * @param sProblemText 问题文本
     * @param sHintText 提示文本
     * @param nMinInput 最小输入
     * @param nMaxInput 最大输入
     * @param tRemainInitialQuiz 剩余初始测验时间
     * @return 数据包
     */
    public static Packet OnAskQuiz(int nSpeakerTypeID, int nSpeakerTemplateID, int nResCode, String sTitle, String sProblemText, String sHintText, int nMinInput, int nMaxInput, int tRemainInitialQuiz) {
        return NpcPackets.OnAskQuiz(nSpeakerTypeID, nSpeakerTemplateID, nResCode, sTitle, sProblemText, sHintText, nMinInput, nMaxInput, tRemainInitialQuiz);
    }

    /**
     * 提问速度测验
     * @param nSpeakerTypeID 说话者类型ID
     * @param nSpeakerTemplateID 说话者模板ID
     * @param nResCode 结果代码
     * @param nType 类型
     * @param dwAnswer 答案
     * @param nCorrect 正确数
     * @param nRemain 剩余数
     * @param tRemainInitialQuiz 剩余初始测验时间
     * @return 数据包
     */
    public static Packet OnAskSpeedQuiz(int nSpeakerTypeID, int nSpeakerTemplateID, int nResCode, int nType, int dwAnswer, int nCorrect, int nRemain, int tRemainInitialQuiz) {
        return NpcPackets.OnAskSpeedQuiz(nSpeakerTypeID, nSpeakerTemplateID, nResCode, nType, dwAnswer, nCorrect, nRemain, tRemainInitialQuiz);
    }

    /**
     * 获取NPC商店
     * @param c 客户端对象
     * @param sid 商店ID
     * @param items 商品列表
     * @return 数据包
     */
    public static Packet getNPCShop(Client c, int sid, List<ShopItem> items) {
        return NpcPackets.getNPCShop(c, sid, items);
    }

    /**
     * 商店交易
     * @param code 代码
     * @return 数据包
     */
    public static Packet shopTransaction(byte code) {
        return NpcPackets.shopTransaction(code);
    }

    /**
     * 商店错误消息
     * @param error 错误代码
     * @param type 类型
     * @return 数据包
     */
    public static Packet shopErrorMessage(int error, int type) {
        return NpcPackets.shopErrorMessage(error, type);
    }

    /**
     * 生成玩家NPC
     * @param npc 玩家NPC对象
     * @return 数据包
     */
    public static Packet spawnPlayerNPC(PlayerNPC npc) {
        return NpcPackets.spawnPlayerNPC(npc);
    }

    /**
     * 获取玩家NPC
     * @param npc 玩家NPC对象
     * @return 数据包
     */
    public static Packet getPlayerNPC(PlayerNPC npc) {
        return NpcPackets.getPlayerNPC(npc);
    }

    /**
     * 移除玩家NPC
     * @param oid 对象ID
     * @return 数据包
     */
    public static Packet removePlayerNPC(int oid) {
        return NpcPackets.removePlayerNPC(oid);
    }

    /**
     * 设置NPC可脚本化
     * @param scriptableNpcIds 可脚本化NPC ID映射
     * @return 数据包
     */
    public static Packet setNPCScriptable(Map<Integer, String> scriptableNpcIds) {
        return NpcPackets.setNPCScriptable(scriptableNpcIds);
    }

    // InventoryPackets
    /**
     * 修改背包
     * @param updateTick 是否更新Tick
     * @param mods 修改列表
     * @return 数据包
     */
    public static Packet modifyInventory(boolean updateTick, final List<ModifyInventory> mods) {
        return InventoryPackets.modifyInventory(updateTick, mods);
    }

    /**
     * 更新背包槽位限制
     * @param type 类型
     * @param newLimit 新限制
     * @return 数据包
     */
    public static Packet updateInventorySlotLimit(int type, int newLimit) {
        return InventoryPackets.updateInventorySlotLimit(type, newLimit);
    }

    /**
     * 获取背包已满
     * @return 数据包
     */
    public static Packet getInventoryFull() {
        return InventoryPackets.getInventoryFull();
    }

    /**
     * 获取显示背包已满
     * @return 数据包
     */
    public static Packet getShowInventoryFull() {
        return InventoryPackets.getShowInventoryFull();
    }

    /**
     * 显示物品不可用
     * @return 数据包
     */
    public static Packet showItemUnavailable() {
        return InventoryPackets.showItemUnavailable();
    }

    /**
     * 获取显示背包状态
     * @param mode 模式
     * @return 数据包
     */
    public static Packet getShowInventoryStatus(int mode) {
        return InventoryPackets.getShowInventoryStatus(mode);
    }

    /**
     * 获取卷轴效果
     * @param chr 角色ID
     * @param scrollSuccess 卷轴结果
     * @param legendarySpirit 传说灵魂
     * @param whiteScroll 白卷
     * @return 数据包
     */
    public static Packet getScrollEffect(int chr, ScrollResult scrollSuccess, boolean legendarySpirit, boolean whiteScroll) {
        return InventoryPackets.getScrollEffect(chr, scrollSuccess, legendarySpirit, whiteScroll);
    }

    /**
     * 发送锤子数据
     * @param hammerUsed 已使用锤子数
     * @return 数据包
     */
    public static Packet sendHammerData(int hammerUsed) {
        return InventoryPackets.sendHammerData(hammerUsed);
    }

    /**
     * 发送锤子消息
     * @return 数据包
     */
    public static Packet sendHammerMessage() {
        return InventoryPackets.sendHammerMessage();
    }

    /**
     * 获取仓库
     * @param npcId NPC ID
     * @param slots 槽位数
     * @param items 物品列表
     * @param meso 金币
     * @return 数据包
     */
    public static Packet getStorage(int npcId, byte slots, Collection<Item> items, int meso) {
        return InventoryPackets.getStorage(npcId, slots, items, meso);
    }

    /**
     * 获取仓库错误
     * @param i 错误代码
     * @return 数据包
     */
    public static Packet getStorageError(byte i) {
        return InventoryPackets.getStorageError(i);
    }

    /**
     * 仓库金币操作
     * @param slots 槽位数
     * @param meso 金币
     * @return 数据包
     */
    public static Packet mesoStorage(byte slots, int meso) {
        return InventoryPackets.mesoStorage(slots, meso);
    }

    /**
     * 存入仓库
     * @param slots 槽位数
     * @param type 背包类型
     * @param items 物品列表
     * @return 数据包
     */
    public static Packet storeStorage(byte slots, InventoryType type, Collection<Item> items) {
        return InventoryPackets.storeStorage(slots, type, items);
    }

    /**
     * 取出仓库
     * @param slots 槽位数
     * @param type 背包类型
     * @param items 物品列表
     * @return 数据包
     */
    public static Packet takeOutStorage(byte slots, InventoryType type, Collection<Item> items) {
        return InventoryPackets.takeOutStorage(slots, type, items);
    }

    /**
     * 整理仓库
     * @param slots 槽位数
     * @param items 物品列表
     * @return 数据包
     */
    public static Packet arrangeStorage(byte slots, Collection<Item> items) {
        return InventoryPackets.arrangeStorage(slots, items);
    }

    /**
     * 完成整理
     * @param inv 背包类型
     * @return 数据包
     */
    public static Packet finishedSort(int inv) {
        return InventoryPackets.finishedSort(inv);
    }

    /**
     * 完成整理2
     * @param inv 背包类型
     * @return 数据包
     */
    public static Packet finishedSort2(int inv) {
        return InventoryPackets.finishedSort2(inv);
    }

    /**
     * 物品特效
     * @param characterid 角色ID
     * @param itemid 物品ID
     * @return 数据包
     */
    public static Packet itemEffect(int characterid, int itemid) {
        return InventoryPackets.itemEffect(characterid, itemid);
    }

    /**
     * 物品过期
     * @param itemid 物品ID
     * @return 数据包
     */
    public static Packet itemExpired(int itemid) {
        return InventoryPackets.itemExpired(itemid);
    }

    /**
     * 获取物品消息
     * @param itemid 物品ID
     * @return 数据包
     */
    public static Packet getItemMessage(int itemid) {
        return InventoryPackets.getItemMessage(itemid);
    }

    /**
     * 静默移除地图物品
     * @param objId 对象ID
     * @return 数据包
     */
    public static Packet silentRemoveItemFromMap(int objId) {
        return InventoryPackets.silentRemoveItemFromMap(objId);
    }

    /**
     * 移除地图物品
     * @param objId 对象ID
     * @param animation 动画
     * @param chrId 角色ID
     * @return 数据包
     */
    public static Packet removeItemFromMap(int objId, int animation, int chrId) {
        return InventoryPackets.removeItemFromMap(objId, animation, chrId);
    }

    /**
     * 移除地图物品（带宠物）
     * @param objId 对象ID
     * @param animation 动画
     * @param chrId 角色ID
     * @param pet 是否宠物
     * @param slot 槽位
     * @return 数据包
     */
    public static Packet removeItemFromMap(int objId, int animation, int chrId, boolean pet, int slot) {
        return InventoryPackets.removeItemFromMap(objId, animation, chrId, pet, slot);
    }

    /**
     * 从地图对象掉落物品
     * @param player 玩家
     * @param drop 掉落物
     * @param dropfrom 掉落起始点
     * @param dropto 掉落终点
     * @param mod 模式
     * @return 数据包
     */
    public static Packet dropItemFromMapObject(Character player, MapItem drop, Point dropfrom, Point dropto, byte mod) {
        return InventoryPackets.dropItemFromMapObject(player, drop, dropfrom, dropto, mod);
    }

    /**
     * 更新地图物品对象
     * @param drop 掉落物
     * @param giveOwnership 是否给予所有权
     * @return 数据包
     */
    public static Packet updateMapItemObject(MapItem drop, boolean giveOwnership) {
        return InventoryPackets.updateMapItemObject(drop, giveOwnership);
    }

    /**
     * 获取显示物品获得
     * @param itemId 物品ID
     * @param quantity 数量
     * @return 数据包
     */
    public static Packet getShowItemGain(int itemId, short quantity) {
        return InventoryPackets.getShowItemGain(itemId, quantity);
    }

    /**
     * 获取显示物品获得（带聊天）
     * @param itemId 物品ID
     * @param quantity 数量
     * @param inChat 是否在聊天框显示
     * @return 数据包
     */
    public static Packet getShowItemGain(int itemId, short quantity, boolean inChat) {
        return InventoryPackets.getShowItemGain(itemId, quantity, inChat);
    }

    // SocialPackets
    /**
     * 获取聊天文本
     * @param cidfrom 发送者ID
     * @param text 文本
     * @param gm 是否GM
     * @param show 显示
     * @return 数据包
     */
    public static Packet getChatText(int cidfrom, String text, boolean gm, int show) {
        return SocialPackets.getChatText(cidfrom, text, gm, show);
    }

    /**
     * 多人聊天
     * @param name 名称
     * @param chattext 聊天文本
     * @param mode 模式
     * @return 数据包
     */
    public static Packet multiChat(String name, String chattext, int mode) {
        return SocialPackets.multiChat(name, chattext, mode);
    }

    /**
     * 获取多重喇叭
     * @param messages 消息数组
     * @param channel 频道
     * @param showEar 是否显示耳朵
     * @return 数据包
     */
    public static Packet getMultiMegaphone(String[] messages, int channel, boolean showEar) {
        return SocialPackets.getMultiMegaphone(messages, channel, showEar);
    }

    /**
     * 服务器消息
     * @param message 消息内容
     * @return 数据包
     */
    public static Packet serverMessage(String message) {
        return SocialPackets.serverMessage(message);
    }

    /**
     * 服务器通知
     * @param type 类型
     * @param message 消息内容
     * @return 数据包
     */
    public static Packet serverNotice(int type, String message) {
        return SocialPackets.serverNotice(type, message);
    }

    /**
     * 服务器通知（带NPC）
     * @param type 类型
     * @param message 消息内容
     * @param npc NPC ID
     * @return 数据包
     */
    public static Packet serverNotice(int type, String message, int npc) {
        return SocialPackets.serverNotice(type, message, npc);
    }

    /**
     * 服务器通知（带频道）
     * @param type 类型
     * @param channel 频道
     * @param message 消息内容
     * @return 数据包
     */
    public static Packet serverNotice(int type, int channel, String message) {
        return SocialPackets.serverNotice(type, channel, message);
    }

    /**
     * 服务器通知（带频道和耳朵）
     * @param type 类型
     * @param channel 频道
     * @param message 消息内容
     * @param smegaEar 是否显示耳朵
     * @return 数据包
     */
    public static Packet serverNotice(int type, int channel, String message, boolean smegaEar) {
        return SocialPackets.serverNotice(type, channel, message, smegaEar);
    }

    /**
     * 获取头像喇叭
     * @param chr 角色对象
     * @param medal 勋章
     * @param channel 频道
     * @param itemId 物品ID
     * @param message 消息列表
     * @param ear 是否显示耳朵
     * @return 数据包
     */
    public static Packet getAvatarMega(Character chr, String medal, int channel, int itemId, List<String> message, boolean ear) {
        return SocialPackets.getAvatarMega(chr, medal, channel, itemId, message, ear);
    }

    /**
     * 关闭头像喇叭
     * @return 数据包
     */
    public static Packet byeAvatarMega() {
        return SocialPackets.byeAvatarMega();
    }

    /**
     * 物品喇叭
     * @param msg 消息
     * @param whisper 是否私聊
     * @param channel 频道
     * @param item 物品对象
     * @return 数据包
     */
    public static Packet itemMegaphone(String msg, boolean whisper, int channel, Item item) {
        return SocialPackets.itemMegaphone(msg, whisper, channel, item);
    }

    /**
     * 队伍创建
     * @param party 队伍对象
     * @param partycharid 队伍角色ID
     * @return 数据包
     */
    public static Packet partyCreated(Party party, int partycharid) {
        return SocialPackets.partyCreated(party, partycharid);
    }

    /**
     * 队伍邀请
     * @param from 邀请者
     * @return 数据包
     */
    public static Packet partyInvite(Character from) {
        return SocialPackets.partyInvite(from);
    }

    /**
     * 队伍搜索邀请
     * @param from 邀请者
     * @return 数据包
     */
    public static Packet partySearchInvite(Character from) {
        return SocialPackets.partySearchInvite(from);
    }

    /**
     * 队伍状态消息
     * @param message 消息代码
     * @return 数据包
     */
    public static Packet partyStatusMessage(int message) {
        return SocialPackets.partyStatusMessage(message);
    }

    /**
     * 队伍状态消息（带角色名）
     * @param message 消息代码
     * @param charname 角色名
     * @return 数据包
     */
    public static Packet partyStatusMessage(int message, String charname) {
        return SocialPackets.partyStatusMessage(message, charname);
    }

    /**
     * 更新队伍
     * @param forChannel 频道
     * @param party 队伍对象
     * @param op 操作
     * @param target 目标角色
     * @return 数据包
     */
    public static Packet updateParty(int forChannel, Party party, PartyOperation op, PartyCharacter target) {
        return SocialPackets.updateParty(forChannel, party, op, target);
    }

    /**
     * 队伍传送门
     * @param townId 城镇ID
     * @param targetId 目标ID
     * @param position 位置
     * @return 数据包
     */
    public static Packet partyPortal(int townId, int targetId, Point position) {
        return SocialPackets.partyPortal(townId, targetId, position);
    }

    /**
     * 更新队伍成员HP
     * @param cid 角色ID
     * @param curhp 当前HP
     * @param maxhp 最大HP
     * @return 数据包
     */
    public static Packet updatePartyMemberHP(int cid, int curhp, int maxhp) {
        return SocialPackets.updatePartyMemberHP(cid, curhp, maxhp);
    }

    /**
     * 更新好友列表
     * @param buddylist 好友列表
     * @return 数据包
     */
    public static Packet updateBuddylist(Collection<BuddylistEntry> buddylist) {
        return SocialPackets.updateBuddylist(buddylist);
    }

    /**
     * 好友列表消息
     * @param message 消息代码
     * @return 数据包
     */
    public static Packet buddylistMessage(byte message) {
        return SocialPackets.buddylistMessage(message);
    }

    /**
     * 请求添加好友
     * @param chrIdFrom 来源ID
     * @param chrId 目标ID
     * @param nameFrom 来源名称
     * @return 数据包
     */
    public static Packet requestBuddylistAdd(int chrIdFrom, int chrId, String nameFrom) {
        return SocialPackets.requestBuddylistAdd(chrIdFrom, chrId, nameFrom);
    }

    /**
     * 更新好友频道
     * @param characterid 角色ID
     * @param channel 频道
     * @return 数据包
     */
    public static Packet updateBuddyChannel(int characterid, int channel) {
        return SocialPackets.updateBuddyChannel(characterid, channel);
    }

    /**
     * 更新好友容量
     * @param capacity 容量
     * @return 数据包
     */
    public static Packet updateBuddyCapacity(int capacity) {
        return SocialPackets.updateBuddyCapacity(capacity);
    }

    /**
     * 加载家族
     * @param player 玩家
     * @return 数据包
     */
    public static Packet loadFamily(Character player) {
        return SocialPackets.loadFamily(player);
    }

    /**
     * 发送家族消息
     * @param type 类型
     * @param mesos 金币
     * @return 数据包
     */
    public static Packet sendFamilyMessage(int type, int mesos) {
        return SocialPackets.sendFamilyMessage(type, mesos);
    }

    /**
     * 获取家族信息
     * @param f 家族条目
     * @return 数据包
     */
    public static Packet getFamilyInfo(FamilyEntry f) {
        return SocialPackets.getFamilyInfo(f);
    }

    /**
     * 显示家谱
     * @param entry 家族条目
     * @return 数据包
     */
    public static Packet showPedigree(FamilyEntry entry) {
        return SocialPackets.showPedigree(entry);
    }

    /**
     * 发送家族邀请
     * @param playerId 玩家ID
     * @param inviter 邀请者
     * @return 数据包
     */
    public static Packet sendFamilyInvite(int playerId, String inviter) {
        return SocialPackets.sendFamilyInvite(playerId, inviter);
    }

    /**
     * 发送家族召唤请求
     * @param familyName 家族名称
     * @param from 来源
     * @return 数据包
     */
    public static Packet sendFamilySummonRequest(String familyName, String from) {
        return SocialPackets.sendFamilySummonRequest(familyName, from);
    }

    /**
     * 发送家族登录通知
     * @param name 名称
     * @param loggedIn 是否登录
     * @return 数据包
     */
    public static Packet sendFamilyLoginNotice(String name, boolean loggedIn) {
        return SocialPackets.sendFamilyLoginNotice(name, loggedIn);
    }

    /**
     * 发送家族加入响应
     * @param accepted 是否接受
     * @param added 添加者
     * @return 数据包
     */
    public static Packet sendFamilyJoinResponse(boolean accepted, String added) {
        return SocialPackets.sendFamilyJoinResponse(accepted, added);
    }

    /**
     * 获取长辈消息
     * @param name 名称
     * @return 数据包
     */
    public static Packet getSeniorMessage(String name) {
        return SocialPackets.getSeniorMessage(name);
    }

    /**
     * 发送获得声望
     * @param gain 获得量
     * @param from 来源
     * @return 数据包
     */
    public static Packet sendGainRep(int gain, String from) {
        return SocialPackets.sendGainRep(gain, from);
    }

    /**
     * 家族Buff
     * @param type 类型
     * @param buffnr Buff编号
     * @param amount 数量
     * @param time 时间
     * @return 数据包
     */
    public static Packet familyBuff(int type, int buffnr, int amount, int time) {
        return SocialPackets.familyBuff(type, buffnr, amount, time);
    }

    /**
     * 取消家族Buff
     * @return 数据包
     */
    public static Packet cancelFamilyBuff() {
        return SocialPackets.cancelFamilyBuff();
    }

    /**
     * 升级消息
     * @param type 类型
     * @param level 等级
     * @param charname 角色名
     * @return 数据包
     */
    public static Packet levelUpMessage(int type, int level, String charname) {
        return SocialPackets.levelUpMessage(type, level, charname);
    }

    /**
     * 结婚消息
     * @param type 类型
     * @param charname 角色名
     * @return 数据包
     */
    public static Packet marriageMessage(int type, String charname) {
        return SocialPackets.marriageMessage(type, charname);
    }

    /**
     * 转职消息
     * @param type 类型
     * @param job 职业
     * @param charname 角色名
     * @return 数据包
     */
    public static Packet jobMessage(int type, int job, String charname) {
        return SocialPackets.jobMessage(type, job, charname);
    }

    /**
     * 信使邀请
     * @param from 邀请者
     * @param messengerid 信使ID
     * @return 数据包
     */
    public static Packet messengerInvite(String from, int messengerid) {
        return SocialPackets.messengerInvite(from, messengerid);
    }

    /**
     * 伴侣消息
     * @param fiance 未婚夫/妻
     * @param text 文本
     * @param spouse 是否配偶
     * @return 数据包
     */
    public static Packet OnCoupleMessage(String fiance, String text, boolean spouse) {
        return SocialPackets.OnCoupleMessage(fiance, text, spouse);
    }

    /**
     * 添加信使玩家
     * @param from 来源
     * @param chr 角色对象
     * @param position 位置
     * @param channel 频道
     * @return 数据包
     */
    public static Packet addMessengerPlayer(String from, Character chr, int position, int channel) {
        return SocialPackets.addMessengerPlayer(from, chr, position, channel);
    }

    /**
     * 移除信使玩家
     * @param position 位置
     * @return 数据包
     */
    public static Packet removeMessengerPlayer(int position) {
        return SocialPackets.removeMessengerPlayer(position);
    }

    /**
     * 更新信使玩家
     * @param from 来源
     * @param chr 角色对象
     * @param position 位置
     * @param channel 频道
     * @return 数据包
     */
    public static Packet updateMessengerPlayer(String from, Character chr, int position, int channel) {
        return SocialPackets.updateMessengerPlayer(from, chr, position, channel);
    }

    /**
     * 加入信使
     * @param position 位置
     * @return 数据包
     */
    public static Packet joinMessenger(int position) {
        return SocialPackets.joinMessenger(position);
    }

    /**
     * 信使聊天
     * @param text 文本
     * @return 数据包
     */
    public static Packet messengerChat(String text) {
        return SocialPackets.messengerChat(text);
    }

    /**
     * 信使备注
     * @param text 文本
     * @param mode 模式
     * @param mode2 模式2
     * @return 数据包
     */
    public static Packet messengerNote(String text, int mode, int mode2) {
        return SocialPackets.messengerNote(text, mode, mode2);
    }

    /**
     * 获取私聊结果
     * @param target 目标
     * @param success 是否成功
     * @return 数据包
     */
    public static Packet getWhisperResult(String target, boolean success) {
        return SocialPackets.getWhisperResult(target, success);
    }

    /**
     * 获取私聊接收
     * @param sender 发送者
     * @param channel 频道
     * @param fromAdmin 是否来自管理员
     * @param message 消息
     * @return 数据包
     */
    public static Packet getWhisperReceive(String sender, int channel, boolean fromAdmin, String message) {
        return SocialPackets.getWhisperReceive(sender, channel, fromAdmin, message);
    }

    /**
     * 获取查找结果
     * @param target 目标角色
     * @param type 类型
     * @param fieldOrChannel 地图或频道
     * @param flag 标志
     * @return 数据包
     */
    public static Packet getFindResult(Character target, byte type, int fieldOrChannel, byte flag) {
        return SocialPackets.getFindResult(target, type, fieldOrChannel, flag);
    }

    /**
     * 备注错误
     * @param error 错误代码
     * @return 数据包
     */
    public static Packet noteError(byte error) {
        return SocialPackets.noteError(error);
    }

    /**
     * 发送快递
     * @param operation 操作
     * @param packages 包裹列表
     * @return 数据包
     */
    public static Packet sendDuey(int operation, List<DueyPackage> packages) {
        return SocialPackets.sendDuey(operation, packages);
    }

    /**
     * 发送快递消息
     * @param operation 操作
     * @return 数据包
     */
    public static Packet sendDueyMSG(byte operation) {
        return SocialPackets.sendDueyMSG(operation);
    }

    /**
     * 发送快递包裹通知
     * @param quick 是否快速
     * @return 数据包
     */
    public static Packet sendDueyParcelNotification(boolean quick) {
        return SocialPackets.sendDueyParcelNotification(quick);
    }

    /**
     * 发送快递包裹已接收
     * @param from 来源
     * @param quick 是否快速
     * @return 数据包
     */
    public static Packet sendDueyParcelReceived(String from, boolean quick) {
        return SocialPackets.sendDueyParcelReceived(from, quick);
    }

    /**
     * 从快递移除物品
     * @param remove 是否移除
     * @param Package 包裹ID
     * @return 数据包
     */
    public static Packet removeItemFromDuey(boolean remove, int Package) {
        return SocialPackets.removeItemFromDuey(remove, Package);
    }

    // CashShopPackets
    /**
     * 打开商城
     * @param c 客户端对象
     * @param mts 是否MTS
     * @return 数据包
     * @throws Exception 异常
     */
    public static Packet openCashShop(Client c, boolean mts) throws Exception {
        return CashShopPackets.openCashShop(c, mts);
    }

    /**
     * 显示点券
     * @param mc 角色对象
     * @return 数据包
     */
    public static Packet showCash(Character mc) {
        return CashShopPackets.showCash(mc);
    }

    /**
     * 启用商城使用
     * @param mc 角色对象
     * @return 数据包
     */
    public static Packet enableCSUse(Character mc) {
        return CashShopPackets.enableCSUse(mc);
    }

    /**
     * 显示商城背包
     * @param c 客户端对象
     * @return 数据包
     */
    public static Packet showCashInventory(Client c) {
        return CashShopPackets.showCashInventory(c);
    }

    /**
     * 显示购买的商城物品
     * @param item 物品对象
     * @param accountId 账号ID
     * @return 数据包
     */
    public static Packet showBoughtCashItem(Item item, int accountId) {
        return CashShopPackets.showBoughtCashItem(item, accountId);
    }

    /**
     * 显示购买的商城礼包
     * @param cashPackage 礼包列表
     * @param accountId 账号ID
     * @return 数据包
     */
    public static Packet showBoughtCashPackage(List<Item> cashPackage, int accountId) {
        return CashShopPackets.showBoughtCashPackage(cashPackage, accountId);
    }

    /**
     * 显示购买的商城戒指
     * @param ring 戒指物品
     * @param recipient 接收者
     * @param accountId 账号ID
     * @return 数据包
     */
    public static Packet showBoughtCashRing(Item ring, String recipient, int accountId) {
        return CashShopPackets.showBoughtCashRing(ring, recipient, accountId);
    }

    /**
     * 显示购买的任务物品
     * @param itemId 物品ID
     * @return 数据包
     */
    public static Packet showBoughtQuestItem(int itemId) {
        return CashShopPackets.showBoughtQuestItem(itemId);
    }

    /**
     * 显示购买的背包槽位
     * @param type 类型
     * @param slots 槽位数
     * @return 数据包
     */
    public static Packet showBoughtInventorySlots(int type, short slots) {
        return CashShopPackets.showBoughtInventorySlots(type, slots);
    }

    /**
     * 显示购买的仓库槽位
     * @param slots 槽位数
     * @return 数据包
     */
    public static Packet showBoughtStorageSlots(short slots) {
        return CashShopPackets.showBoughtStorageSlots(slots);
    }

    /**
     * 显示购买的角色槽位
     * @param slots 槽位数
     * @return 数据包
     */
    public static Packet showBoughtCharacterSlot(short slots) {
        return CashShopPackets.showBoughtCharacterSlot(slots);
    }

    /**
     * 显示礼物成功
     * @param to 接收者
     * @param item 物品对象
     * @return 数据包
     */
    public static Packet showGiftSucceed(String to, ModifiedCashItemDO item) {
        return CashShopPackets.showGiftSucceed(to, item);
    }

    /**
     * 显示礼物列表
     * @param gifts 礼物列表
     * @return 数据包
     */
    public static Packet showGifts(List<Pair<Item, String>> gifts) {
        return CashShopPackets.showGifts(gifts);
    }

    /**
     * 从商城背包取出
     * @param item 物品对象
     * @return 数据包
     */
    public static Packet takeFromCashInventory(Item item) {
        return CashShopPackets.takeFromCashInventory(item);
    }

    /**
     * 放入商城背包
     * @param item 物品对象
     * @param accountId 账号ID
     * @return 数据包
     */
    public static Packet putIntoCashInventory(Item item, int accountId) {
        return CashShopPackets.putIntoCashInventory(item, accountId);
    }

    /**
     * 删除商城物品
     * @param item 物品对象
     * @return 数据包
     */
    public static Packet deleteCashItem(Item item) {
        return CashShopPackets.deleteCashItem(item);
    }

    /**
     * 退款商城物品
     * @param item 物品对象
     * @param maplePoints 抵用券
     * @return 数据包
     */
    public static Packet refundCashItem(Item item, int maplePoints) {
        return CashShopPackets.refundCashItem(item, maplePoints);
    }

    /**
     * 显示商城消息
     * @param message 消息代码
     * @return 数据包
     */
    public static Packet showCashShopMessage(byte message) {
        return CashShopPackets.showCashShopMessage(message);
    }

    /**
     * 显示愿望清单
     * @param mc 角色对象
     * @param update 是否更新
     * @return 数据包
     */
    public static Packet showWishList(Character mc, boolean update) {
        return CashShopPackets.showWishList(mc, update);
    }

    /**
     * 显示兑换券兑换物品
     * @param accountId 账号ID
     * @param maplePoints 抵用券
     * @param mesos 金币
     * @param cashItems 现金物品列表
     * @param items 物品列表
     * @return 数据包
     */
    public static Packet showCouponRedeemedItems(int accountId, int maplePoints, int mesos, List<Item> cashItems, List<Pair<Integer, Integer>> items) {
        return CashShopPackets.showCouponRedeemedItems(accountId, maplePoints, mesos, cashItems, items);
    }

    /**
     * 现金物品转蛋打开失败
     * @return 数据包
     */
    public static Packet onCashItemGachaponOpenFailed() {
        return CashShopPackets.onCashItemGachaponOpenFailed();
    }

    /**
     * 现金物品转蛋打开成功
     * @param accountid 账号ID
     * @param boxCashId 盒子现金ID
     * @param remainingBoxes 剩余盒子数
     * @param reward 奖励物品
     * @param rewardItemId 奖励物品ID
     * @param rewardQuantity 奖励数量
     * @param bJackpot 是否大奖
     * @return 数据包
     */
    public static Packet onCashGachaponOpenSuccess(int accountid, long boxCashId, int remainingBoxes, Item reward, int rewardItemId, int rewardQuantity, boolean bJackpot) {
        return CashShopPackets.onCashGachaponOpenSuccess(accountid, boxCashId, remainingBoxes, reward, rewardItemId, rewardQuantity, bJackpot);
    }

    /**
     * 发送世界转移规则
     * @param error 错误代码
     * @param c 客户端对象
     * @return 数据包
     */
    public static Packet sendWorldTransferRules(int error, Client c) {
        return CashShopPackets.sendWorldTransferRules(error, c);
    }

    /**
     * 显示世界转移成功
     * @param item 物品对象
     * @param accountId 账号ID
     * @return 数据包
     */
    public static Packet showWorldTransferSuccess(Item item, int accountId) {
        return CashShopPackets.showWorldTransferSuccess(item, accountId);
    }

    /**
     * 显示世界转移取消
     * @param success 是否成功
     * @return 数据包
     */
    public static Packet showWorldTransferCancel(boolean success) {
        return CashShopPackets.showWorldTransferCancel(success);
    }

    /**
     * 发送名称转移规则
     * @param error 错误代码
     * @return 数据包
     */
    public static Packet sendNameTransferRules(int error) {
        return CashShopPackets.sendNameTransferRules(error);
    }

    /**
     * 发送名称转移检查
     * @param availableName 可用名称
     * @param canUseName 是否可用
     * @return 数据包
     */
    public static Packet sendNameTransferCheck(String availableName, boolean canUseName) {
        return CashShopPackets.sendNameTransferCheck(availableName, canUseName);
    }

    /**
     * 显示名称更改成功
     * @param item 物品对象
     * @param accountId 账号ID
     * @return 数据包
     */
    public static Packet showNameChangeSuccess(Item item, int accountId) {
        return CashShopPackets.showNameChangeSuccess(item, accountId);
    }

    /**
     * 显示名称更改取消
     * @param success 是否成功
     * @return 数据包
     */
    public static Packet showNameChangeCancel(boolean success) {
        return CashShopPackets.showNameChangeCancel(success);
    }

    /**
     * 显示MTS点券
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet showMTSCash(Character chr) {
        return CashShopPackets.showMTSCash(chr);
    }

    /**
     * 发送MTS
     * @param items 物品列表
     * @param tab 标签
     * @param type 类型
     * @param page 页码
     * @param pages 总页数
     * @return 数据包
     */
    public static Packet sendMTS(List<MTSItemInfo> items, int tab, int type, int page, int pages) {
        return CashShopPackets.sendMTS(items, tab, type, page, pages);
    }

    /**
     * MTS求购列表结束
     * @param nx 点券
     * @param items 物品数
     * @return 数据包
     */
    public static Packet MTSWantedListingOver(int nx, int items) {
        return CashShopPackets.MTSWantedListingOver(nx, items);
    }

    /**
     * MTS确认出售
     * @return 数据包
     */
    public static Packet MTSConfirmSell() {
        return CashShopPackets.MTSConfirmSell();
    }

    /**
     * MTS确认购买
     * @return 数据包
     */
    public static Packet MTSConfirmBuy() {
        return CashShopPackets.MTSConfirmBuy();
    }

    /**
     * MTS购买失败
     * @return 数据包
     */
    public static Packet MTSFailBuy() {
        return CashShopPackets.MTSFailBuy();
    }

    /**
     * MTS确认转移
     * @param quantity 数量
     * @param pos 位置
     * @return 数据包
     */
    public static Packet MTSConfirmTransfer(int quantity, int pos) {
        return CashShopPackets.MTSConfirmTransfer(quantity, pos);
    }

    /**
     * 未售出物品
     * @param items 物品列表
     * @return 数据包
     */
    public static Packet notYetSoldInv(List<MTSItemInfo> items) {
        return CashShopPackets.notYetSoldInv(items);
    }

    /**
     * 转移背包
     * @param items 物品列表
     * @return 数据包
     */
    public static Packet transferInventory(List<MTSItemInfo> items) {
        return CashShopPackets.transferInventory(items);
    }

    /**
     * 使用宝箱
     * @param type 类型
     * @return 数据包
     */
    public static Packet UseTreasureBox(int type) {
        return CashShopPackets.UseTreasureBox(type);
    }

    // MiniGamePackets
    /**
     * 获取小游戏
     * @param c 客户端对象
     * @param minigame 小游戏对象
     * @param owner 是否房主
     * @param piece 棋子
     * @return 数据包
     */
    public static Packet getMiniGame(Client c, MiniGame minigame, boolean owner, int piece) {
        return MiniGamePackets.getMiniGame(c, minigame, owner, piece);
    }

    /**
     * 小游戏准备
     * @param game 小游戏对象
     * @return 数据包
     */
    public static Packet getMiniGameReady(MiniGame game) {
        return MiniGamePackets.getMiniGameReady(game);
    }

    /**
     * 小游戏取消准备
     * @param game 小游戏对象
     * @return 数据包
     */
    public static Packet getMiniGameUnReady(MiniGame game) {
        return MiniGamePackets.getMiniGameUnReady(game);
    }

    /**
     * 小游戏开始
     * @param game 小游戏对象
     * @param loser 输者
     * @return 数据包
     */
    public static Packet getMiniGameStart(MiniGame game, int loser) {
        return MiniGamePackets.getMiniGameStart(game, loser);
    }

    /**
     * 小游戏房主跳过
     * @param game 小游戏对象
     * @return 数据包
     */
    public static Packet getMiniGameSkipOwner(MiniGame game) {
        return MiniGamePackets.getMiniGameSkipOwner(game);
    }

    /**
     * 小游戏访客跳过
     * @param game 小游戏对象
     * @return 数据包
     */
    public static Packet getMiniGameSkipVisitor(MiniGame game) {
        return MiniGamePackets.getMiniGameSkipVisitor(game);
    }

    /**
     * 小游戏请求平局
     * @param game 小游戏对象
     * @return 数据包
     */
    public static Packet getMiniGameRequestTie(MiniGame game) {
        return MiniGamePackets.getMiniGameRequestTie(game);
    }

    /**
     * 小游戏拒绝平局
     * @param game 小游戏对象
     * @return 数据包
     */
    public static Packet getMiniGameDenyTie(MiniGame game) {
        return MiniGamePackets.getMiniGameDenyTie(game);
    }

    /**
     * 小游戏移动五子棋
     * @param game 小游戏对象
     * @param move1 移动1
     * @param move2 移动2
     * @param move3 移动3
     * @return 数据包
     */
    public static Packet getMiniGameMoveOmok(MiniGame game, int move1, int move2, int move3) {
        return MiniGamePackets.getMiniGameMoveOmok(game, move1, move2, move3);
    }

    /**
     * 小游戏新访客
     * @param minigame 小游戏对象
     * @param chr 角色对象
     * @param slot 槽位
     * @return 数据包
     */
    public static Packet getMiniGameNewVisitor(MiniGame minigame, Character chr, int slot) {
        return MiniGamePackets.getMiniGameNewVisitor(minigame, chr, slot);
    }

    /**
     * 小游戏移除访客
     * @return 数据包
     */
    public static Packet getMiniGameRemoveVisitor() {
        return MiniGamePackets.getMiniGameRemoveVisitor();
    }

    /**
     * 小游戏房主胜利
     * @param game 小游戏对象
     * @param forfeit 是否弃权
     * @return 数据包
     */
    public static Packet getMiniGameOwnerWin(MiniGame game, boolean forfeit) {
        return MiniGamePackets.getMiniGameOwnerWin(game, forfeit);
    }

    /**
     * 小游戏访客胜利
     * @param game 小游戏对象
     * @param forfeit 是否弃权
     * @return 数据包
     */
    public static Packet getMiniGameVisitorWin(MiniGame game, boolean forfeit) {
        return MiniGamePackets.getMiniGameVisitorWin(game, forfeit);
    }

    /**
     * 小游戏平局
     * @param game 小游戏对象
     * @return 数据包
     */
    public static Packet getMiniGameTie(MiniGame game) {
        return MiniGamePackets.getMiniGameTie(game);
    }

    /**
     * 小游戏关闭
     * @param visitor 是否访客
     * @param type 类型
     * @return 数据包
     */
    public static Packet getMiniGameClose(boolean visitor, int type) {
        return MiniGamePackets.getMiniGameClose(visitor, type);
    }

    /**
     * 获取配对卡
     * @param c 客户端对象
     * @param minigame 小游戏对象
     * @param owner 是否房主
     * @param piece 棋子
     * @return 数据包
     */
    public static Packet getMatchCard(Client c, MiniGame minigame, boolean owner, int piece) {
        return MiniGamePackets.getMatchCard(c, minigame, owner, piece);
    }

    /**
     * 配对卡开始
     * @param game 小游戏对象
     * @param loser 输者
     * @return 数据包
     */
    public static Packet getMatchCardStart(MiniGame game, int loser) {
        return MiniGamePackets.getMatchCardStart(game, loser);
    }

    /**
     * 配对卡新访客
     * @param minigame 小游戏对象
     * @param chr 角色对象
     * @param slot 槽位
     * @return 数据包
     */
    public static Packet getMatchCardNewVisitor(MiniGame minigame, Character chr, int slot) {
        return MiniGamePackets.getMatchCardNewVisitor(minigame, chr, slot);
    }

    /**
     * 配对卡选择
     * @param game 小游戏对象
     * @param turn 回合
     * @param slot 槽位
     * @param firstslot 第一槽位
     * @param type 类型
     * @return 数据包
     */
    public static Packet getMatchCardSelect(MiniGame game, int turn, int slot, int firstslot, int type) {
        return MiniGamePackets.getMatchCardSelect(game, turn, slot, firstslot, type);
    }

    /**
     * 获取迷你房间错误
     * @param status 状态
     * @return 数据包
     */
    public static Packet getMiniRoomError(int status) {
        return MiniGamePackets.getMiniRoomError(status);
    }

    /**
     * 添加五子棋盒
     * @param chr 角色对象
     * @param amount 数量
     * @param type 类型
     * @return 数据包
     */
    public static Packet addOmokBox(Character chr, int amount, int type) {
        return MiniGamePackets.addOmokBox(chr, amount, type);
    }

    /**
     * 添加配对卡盒
     * @param chr 角色对象
     * @param amount 数量
     * @param type 类型
     * @return 数据包
     */
    public static Packet addMatchCardBox(Character chr, int amount, int type) {
        return MiniGamePackets.addMatchCardBox(chr, amount, type);
    }

    /**
     * 移除小游戏盒
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet removeMinigameBox(Character chr) {
        return MiniGamePackets.removeMinigameBox(chr);
    }

    /**
     * 获取玩家商店
     * @param shop 商店对象
     * @param owner 是否房主
     * @return 数据包
     */
    public static Packet getPlayerShop(PlayerShop shop, boolean owner) {
        return MiniGamePackets.getPlayerShop(shop, owner);
    }

    /**
     * 获取玩家商店聊天
     * @param chr 角色对象
     * @param chat 聊天内容
     * @param owner 是否房主
     * @return 数据包
     */
    public static Packet getPlayerShopChat(Character chr, String chat, boolean owner) {
        return MiniGamePackets.getPlayerShopChat(chr, chat, owner);
    }

    /**
     * 获取玩家商店聊天（带槽位）
     * @param chr 角色对象
     * @param chat 聊天内容
     * @param slot 槽位
     * @return 数据包
     */
    public static Packet getPlayerShopChat(Character chr, String chat, byte slot) {
        return MiniGamePackets.getPlayerShopChat(chr, chat, slot);
    }

    /**
     * 获取玩家商店新访客
     * @param chr 角色对象
     * @param slot 槽位
     * @return 数据包
     */
    public static Packet getPlayerShopNewVisitor(Character chr, int slot) {
        return MiniGamePackets.getPlayerShopNewVisitor(chr, slot);
    }

    /**
     * 获取玩家商店移除访客
     * @param slot 槽位
     * @return 数据包
     */
    public static Packet getPlayerShopRemoveVisitor(int slot) {
        return MiniGamePackets.getPlayerShopRemoveVisitor(slot);
    }

    /**
     * 获取玩家商店物品更新
     * @param shop 商店对象
     * @return 数据包
     */
    public static Packet getPlayerShopItemUpdate(PlayerShop shop) {
        return MiniGamePackets.getPlayerShopItemUpdate(shop);
    }

    /**
     * 获取玩家商店所有者更新
     * @param item 售出物品
     * @param position 位置
     * @return 数据包
     */
    public static Packet getPlayerShopOwnerUpdate(PlayerShop.SoldItem item, int position) {
        return MiniGamePackets.getPlayerShopOwnerUpdate(item, position);
    }

    /**
     * 更新玩家商店盒
     * @param shop 商店对象
     * @return 数据包
     */
    public static Packet updatePlayerShopBox(PlayerShop shop) {
        return MiniGamePackets.updatePlayerShopBox(shop);
    }

    /**
     * 移除玩家商店盒
     * @param shop 商店对象
     * @return 数据包
     */
    public static Packet removePlayerShopBox(PlayerShop shop) {
        return MiniGamePackets.removePlayerShopBox(shop);
    }

    /**
     * 获取交易开始
     * @param c 客户端对象
     * @param trade 交易对象
     * @param number 编号
     * @return 数据包
     */
    public static Packet getTradeStart(Client c, Trade trade, byte number) {
        return MiniGamePackets.getTradeStart(c, trade, number);
    }

    /**
     * 获取交易确认
     * @return 数据包
     */
    public static Packet getTradeConfirmation() {
        return MiniGamePackets.getTradeConfirmation();
    }

    /**
     * 获取交易结果
     * @param number 编号
     * @param operation 操作
     * @return 数据包
     */
    public static Packet getTradeResult(byte number, byte operation) {
        return MiniGamePackets.getTradeResult(number, operation);
    }

    /**
     * 获取交易伙伴添加
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet getTradePartnerAdd(Character chr) {
        return MiniGamePackets.getTradePartnerAdd(chr);
    }

    /**
     * 交易邀请
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet tradeInvite(Character chr) {
        return MiniGamePackets.tradeInvite(chr);
    }

    /**
     * 获取交易金币设置
     * @param number 编号
     * @param meso 金币
     * @return 数据包
     */
    public static Packet getTradeMesoSet(byte number, int meso) {
        return MiniGamePackets.getTradeMesoSet(number, meso);
    }

    /**
     * 获取交易物品添加
     * @param number 编号
     * @param item 物品对象
     * @return 数据包
     */
    public static Packet getTradeItemAdd(byte number, Item item) {
        return MiniGamePackets.getTradeItemAdd(number, item);
    }

    /**
     * 获取交易聊天
     * @param chr 角色对象
     * @param chat 聊天内容
     * @param owner 是否房主
     * @return 数据包
     */
    public static Packet getTradeChat(Character chr, String chat, boolean owner) {
        return MiniGamePackets.getTradeChat(chr, chat, owner);
    }

    /**
     * 雇佣商人盒
     * @return 数据包
     */
    public static Packet hiredMerchantBox() {
        return MiniGamePackets.hiredMerchantBox();
    }

    /**
     * 获取雇佣商人
     * @param chr 角色对象
     * @param hm 雇佣商人对象
     * @param firstTime 是否首次
     * @return 数据包
     */
    public static Packet getHiredMerchant(Character chr, HiredMerchant hm, boolean firstTime) {
        return MiniGamePackets.getHiredMerchant(chr, hm, firstTime);
    }

    /**
     * 更新雇佣商人
     * @param hm 雇佣商人对象
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet updateHiredMerchant(HiredMerchant hm, Character chr) {
        return MiniGamePackets.updateHiredMerchant(hm, chr);
    }

    /**
     * 雇佣商人聊天
     * @param message 消息
     * @param slot 槽位
     * @return 数据包
     */
    public static Packet hiredMerchantChat(String message, byte slot) {
        return MiniGamePackets.hiredMerchantChat(message, slot);
    }

    /**
     * 雇佣商人访客离开
     * @param slot 槽位
     * @return 数据包
     */
    public static Packet hiredMerchantVisitorLeave(int slot) {
        return MiniGamePackets.hiredMerchantVisitorLeave(slot);
    }

    /**
     * 雇佣商人房主离开
     * @return 数据包
     */
    public static Packet hiredMerchantOwnerLeave() {
        return MiniGamePackets.hiredMerchantOwnerLeave();
    }

    /**
     * 雇佣商人房主维护离开
     * @return 数据包
     */
    public static Packet hiredMerchantOwnerMaintenanceLeave() {
        return MiniGamePackets.hiredMerchantOwnerMaintenanceLeave();
    }

    /**
     * 雇佣商人维护消息
     * @return 数据包
     */
    public static Packet hiredMerchantMaintenanceMessage() {
        return MiniGamePackets.hiredMerchantMaintenanceMessage();
    }

    /**
     * 离开雇佣商人
     * @param slot 槽位
     * @param status2 状态2
     * @return 数据包
     */
    public static Packet leaveHiredMerchant(int slot, int status2) {
        return MiniGamePackets.leaveHiredMerchant(slot, status2);
    }

    /**
     * 查看商人访客历史
     * @param pastVisitors 访客历史列表
     * @return 数据包
     */
    public static Packet viewMerchantVisitorHistory(List<HiredMerchant.PastVisitor> pastVisitors) {
        return MiniGamePackets.viewMerchantVisitorHistory(pastVisitors);
    }

    /**
     * 查看商人黑名单
     * @param chrNames 角色名集合
     * @return 数据包
     */
    public static Packet viewMerchantBlacklist(Set<String> chrNames) {
        return MiniGamePackets.viewMerchantBlacklist(chrNames);
    }

    /**
     * 雇佣商人添加访客
     * @param chr 角色对象
     * @param slot 槽位
     * @return 数据包
     */
    public static Packet hiredMerchantVisitorAdd(Character chr, int slot) {
        return MiniGamePackets.hiredMerchantVisitorAdd(chr, slot);
    }

    /**
     * 生成雇佣商人盒
     * @param hm 雇佣商人对象
     * @return 数据包
     */
    public static Packet spawnHiredMerchantBox(HiredMerchant hm) {
        return MiniGamePackets.spawnHiredMerchantBox(hm);
    }

    /**
     * 移除雇佣商人盒
     * @param id ID
     * @return 数据包
     */
    public static Packet removeHiredMerchantBox(int id) {
        return MiniGamePackets.removeHiredMerchantBox(id);
    }

    /**
     * 更新雇佣商人盒
     * @param hm 雇佣商人对象
     * @return 数据包
     */
    public static Packet updateHiredMerchantBox(HiredMerchant hm) {
        return MiniGamePackets.updateHiredMerchantBox(hm);
    }

    /**
     * 获取弗雷德里克
     * @param op 操作
     * @return 数据包
     */
    public static Packet getFredrick(byte op) {
        return MiniGamePackets.getFredrick(op);
    }

    /**
     * 获取弗雷德里克（带物品）
     * @param chr 角色对象
     * @param merchants 商人列表
     * @return 数据包
     */
    public static Packet getFredrick(Character chr, List<HiredMerchantsDO> merchants) {
        return MiniGamePackets.getFredrick(chr, merchants);
    }

    /**
     * 弗雷德里克消息
     * @param operation 操作
     * @return 数据包
     */
    public static Packet fredrickMessage(byte operation) {
        return MiniGamePackets.fredrickMessage(operation);
    }

    /**
     * 打开RPS NPC
     * @return 数据包
     */
    public static Packet openRPSNPC() {
        return MiniGamePackets.openRPSNPC();
    }

    /**
     * RPS金币错误
     * @param mesos 金币
     * @return 数据包
     */
    public static Packet rpsMesoError(int mesos) {
        return MiniGamePackets.rpsMesoError(mesos);
    }

    /**
     * RPS选择
     * @param selection 选择
     * @param answer 答案
     * @return 数据包
     */
    public static Packet rpsSelection(byte selection, byte answer) {
        return MiniGamePackets.rpsSelection(selection, answer);
    }

    /**
     * RPS模式
     * @param mode 模式
     * @return 数据包
     */
    public static Packet rpsMode(byte mode) {
        return MiniGamePackets.rpsMode(mode);
    }

    /**
     * 获取猫头鹰消息
     * @param msg 消息
     * @return 数据包
     */
    public static Packet getOwlMessage(int msg) {
        return MiniGamePackets.getOwlMessage(msg);
    }

    /**
     * 密涅瓦猫头鹰
     * @param c 客户端对象
     * @param itemId 物品ID
     * @param hmsAvailable 可用商人列表
     * @return 数据包
     */
    public static Packet owlOfMinerva(Client c, int itemId, List<Pair<PlayerShopItem, AbstractMapObject>> hmsAvailable) {
        return MiniGamePackets.owlOfMinerva(c, itemId, hmsAvailable);
    }

    /**
     * 获取猫头鹰打开
     * @param owlLeaderboards 排行榜
     * @return 数据包
     */
    public static Packet getOwlOpen(List<Integer> owlLeaderboards) {
        return MiniGamePackets.getOwlOpen(owlLeaderboards);
    }

    /**
     * 检索第一条消息
     * @return 数据包
     */
    public static Packet retrieveFirstMessage() {
        return MiniGamePackets.retrieveFirstMessage();
    }

    /**
     * 远程频道更改
     * @param ch 频道
     * @return 数据包
     */
    public static Packet remoteChannelChange(byte ch) {
        return MiniGamePackets.remoteChannelChange(ch);
    }

    // MobPackets
    /**
     * 生成怪物
     * @param life 怪物对象
     * @param newSpawn 是否新生成
     * @return 数据包
     */
    public static Packet spawnMonster(Monster life, boolean newSpawn) {
        return MobPackets.spawnMonster(life, newSpawn);
    }

    /**
     * 生成怪物（带特效）
     * @param life 怪物对象
     * @param newSpawn 是否新生成
     * @param effect 特效
     * @return 数据包
     */
    public static Packet spawnMonster(Monster life, boolean newSpawn, int effect) {
        return MobPackets.spawnMonster(life, newSpawn, effect);
    }

    /**
     * 控制怪物
     * @param life 怪物对象
     * @param newSpawn 是否新生成
     * @param aggro 是否主动攻击
     * @return 数据包
     */
    public static Packet controlMonster(Monster life, boolean newSpawn, boolean aggro) {
        return MobPackets.controlMonster(life, newSpawn, aggro);
    }

    /**
     * 停止控制怪物
     * @param oid 对象ID
     * @return 数据包
     */
    public static Packet stopControllingMonster(int oid) {
        return MobPackets.stopControllingMonster(oid);
    }

    /**
     * 移动怪物
     * @param oid 对象ID
     * @param skillPossible 是否可能使用技能
     * @param skill 技能
     * @param skillId 技能ID
     * @param skillLevel 技能等级
     * @param pOption 选项
     * @param startPos 起始位置
     * @param movementPacket 移动数据包
     * @param movementDataLength 移动数据长度
     * @return 数据包
     */
    public static Packet moveMonster(int oid, boolean skillPossible, int skill, int skillId, int skillLevel, int pOption, Point startPos, InPacket movementPacket, long movementDataLength) {
        return MobPackets.moveMonster(oid, skillPossible, skill, skillId, skillLevel, pOption, startPos, movementPacket, movementDataLength);
    }

    /**
     * 移动怪物响应
     * @param objectid 对象ID
     * @param moveid 移动ID
     * @param currentMp 当前MP
     * @param useSkills 是否使用技能
     * @return 数据包
     */
    public static Packet moveMonsterResponse(int objectid, short moveid, int currentMp, boolean useSkills) {
        return MobPackets.moveMonsterResponse(objectid, moveid, currentMp, useSkills);
    }

    /**
     * 移动怪物响应（带技能）
     * @param objectid 对象ID
     * @param moveid 移动ID
     * @param currentMp 当前MP
     * @param useSkills 是否使用技能
     * @param skillId 技能ID
     * @param skillLevel 技能等级
     * @return 数据包
     */
    public static Packet moveMonsterResponse(int objectid, short moveid, int currentMp, boolean useSkills, int skillId, int skillLevel) {
        return MobPackets.moveMonsterResponse(objectid, moveid, currentMp, useSkills, skillId, skillLevel);
    }

    /**
     * 杀死怪物
     * @param objId 对象ID
     * @param animation 是否有动画
     * @return 数据包
     */
    public static Packet killMonster(int objId, boolean animation) {
        return MobPackets.killMonster(objId, animation);
    }

    /**
     * 杀死怪物（带动画类型）
     * @param objId 对象ID
     * @param animation 动画类型
     * @return 数据包
     */
    public static Packet killMonster(int objId, int animation) {
        return MobPackets.killMonster(objId, animation);
    }

    /**
     * 伤害怪物
     * @param oid 对象ID
     * @param damage 伤害
     * @return 数据包
     */
    public static Packet damageMonster(int oid, int damage) {
        return MobPackets.damageMonster(oid, damage);
    }

    /**
     * 治疗怪物
     * @param oid 对象ID
     * @param heal 治疗量
     * @param curhp 当前HP
     * @param maxhp 最大HP
     * @return 数据包
     */
    public static Packet healMonster(int oid, int heal, int curhp, int maxhp) {
        return MobPackets.healMonster(oid, heal, curhp, maxhp);
    }

    /**
     * 显示怪物HP
     * @param oid 对象ID
     * @param remhppercentage 剩余HP百分比
     * @return 数据包
     */
    public static Packet showMonsterHP(int oid, int remhppercentage) {
        return MobPackets.showMonsterHP(oid, remhppercentage);
    }

    /**
     * 显示Boss HP
     * @param oid 对象ID
     * @param currHP 当前HP
     * @param maxHP 最大HP
     * @param tagColor 标签颜色
     * @param tagBgColor 标签背景颜色
     * @return 数据包
     */
    public static Packet showBossHP(int oid, int currHP, int maxHP, byte tagColor, byte tagBgColor) {
        return MobPackets.showBossHP(oid, currHP, maxHP, tagColor, tagBgColor);
    }

    /**
     * 自定义显示Boss HP
     * @param call 调用
     * @param oid 对象ID
     * @param currHP 当前HP
     * @param maxHP 最大HP
     * @param tagColor 标签颜色
     * @param tagBgColor 标签背景颜色
     * @return 数据包
     */
    public static Packet customShowBossHP(byte call, int oid, long currHP, long maxHP, byte tagColor, byte tagBgColor) {
        return MobPackets.customShowBossHP(call, oid, currHP, maxHP, tagColor, tagBgColor);
    }

    /**
     * 应用怪物状态
     * @param oid 对象ID
     * @param mse 怪物状态效果
     * @param reflection 反射
     * @return 数据包
     */
    public static Packet applyMonsterStatus(final int oid, final MonsterStatusEffect mse, final List<Integer> reflection) {
        return MobPackets.applyMonsterStatus(oid, mse, reflection);
    }

    /**
     * 取消怪物状态
     * @param oid 对象ID
     * @param stats 状态映射
     * @return 数据包
     */
    public static Packet cancelMonsterStatus(int oid, Map<MonsterStatus, Integer> stats) {
        return MobPackets.cancelMonsterStatus(oid, stats);
    }

    /**
     * 捕捉怪物
     * @param mobOid 怪物对象ID
     * @param success 是否成功
     * @return 数据包
     */
    public static Packet catchMonster(int mobOid, byte success) {
        return MobPackets.catchMonster(mobOid, success);
    }

    /**
     * 捕捉怪物（带物品）
     * @param mobOid 怪物对象ID
     * @param itemid 物品ID
     * @param success 是否成功
     * @return 数据包
     */
    public static Packet catchMonster(int mobOid, int itemid, byte success) {
        return MobPackets.catchMonster(mobOid, itemid, success);
    }

    /**
     * 捕捉消息
     * @param message 消息
     * @return 数据包
     */
    public static Packet catchMessage(int message) {
        return MobPackets.catchMessage(message);
    }

    /**
     * 生成假怪物
     * @param life 怪物对象
     * @param effect 特效
     * @return 数据包
     */
    public static Packet spawnFakeMonster(Monster life, int effect) {
        return MobPackets.spawnFakeMonster(life, effect);
    }

    /**
     * 使怪物变真
     * @param life 怪物对象
     * @return 数据包
     */
    public static Packet makeMonsterReal(Monster life) {
        return MobPackets.makeMonsterReal(life);
    }

    /**
     * 移除怪物隐身
     * @param life 怪物对象
     * @return 数据包
     */
    public static Packet removeMonsterInvisibility(Monster life) {
        return MobPackets.removeMonsterInvisibility(life);
    }

    /**
     * 使怪物隐身
     * @param life 怪物对象
     * @return 数据包
     */
    public static Packet makeMonsterInvisible(Monster life) {
        return MobPackets.makeMonsterInvisible(life);
    }

    /**
     * 怪物伤害怪物（友好）
     * @param mob 怪物对象
     * @param damage 伤害
     * @param remainingHp 剩余HP
     * @return 数据包
     */
    public static Packet MobDamageMobFriendly(Monster mob, int damage, int remainingHp) {
        return MobPackets.MobDamageMobFriendly(mob, damage, remainingHp);
    }

    // PetPackets
    /**
     * 显示宠物
     * @param chr 角色对象
     * @param pet 宠物对象
     * @param remove 是否移除
     * @param hunger 是否饥饿
     * @return 数据包
     */
    public static Packet showPet(Character chr, Pet pet, boolean remove, boolean hunger) {
        return PetPackets.showPet(chr, pet, remove, hunger);
    }

    /**
     * 移动宠物
     * @param cid 角色ID
     * @param pid 宠物ID
     * @param slot 槽位
     * @param moves 移动列表
     * @return 数据包
     */
    public static Packet movePet(int cid, int pid, byte slot, List<LifeMovementFragment> moves) {
        return PetPackets.movePet(cid, pid, slot, moves);
    }

    /**
     * 宠物聊天
     * @param cid 角色ID
     * @param index 索引
     * @param act 动作
     * @param text 文本
     * @return 数据包
     */
    public static Packet petChat(int cid, byte index, int act, String text) {
        return PetPackets.petChat(cid, index, act, text);
    }

    /**
     * 宠物食物响应
     * @param cid 角色ID
     * @param index 索引
     * @param success 是否成功
     * @param balloonType 气泡类型
     * @return 数据包
     */
    public static Packet petFoodResponse(int cid, byte index, boolean success, boolean balloonType) {
        return PetPackets.petFoodResponse(cid, index, success, balloonType);
    }

    /**
     * 命令响应
     * @param cid 角色ID
     * @param index 索引
     * @param talk 是否说话
     * @param animation 动画
     * @param balloonType 气泡类型
     * @return 数据包
     */
    public static Packet commandResponse(int cid, byte index, boolean talk, int animation, boolean balloonType) {
        return PetPackets.commandResponse(cid, index, talk, animation, balloonType);
    }

    /**
     * 显示自身宠物升级
     * @param index 索引
     * @return 数据包
     */
    public static Packet showOwnPetLevelUp(byte index) {
        return PetPackets.showOwnPetLevelUp(index);
    }

    /**
     * 显示宠物升级
     * @param chr 角色对象
     * @param index 索引
     * @return 数据包
     */
    public static Packet showPetLevelUp(Character chr, byte index) {
        return PetPackets.showPetLevelUp(chr, index);
    }

    /**
     * 更改宠物名称
     * @param chr 角色对象
     * @param newname 新名称
     * @param slot 槽位
     * @return 数据包
     */
    public static Packet changePetName(Character chr, String newname, int slot) {
        return PetPackets.changePetName(chr, newname, slot);
    }

    /**
     * 加载例外列表
     * @param cid 角色ID
     * @param petId 宠物ID
     * @param petIdx 宠物索引
     * @param data 数据列表
     * @return 数据包
     */
    public static Packet loadExceptionList(final int cid, final int petId, final byte petIdx, final List<Integer> data) {
        return PetPackets.loadExceptionList(cid, petId, petIdx, data);
    }

    /**
     * 宠物状态更新
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet petStatUpdate(Character chr) {
        return PetPackets.petStatUpdate(chr);
    }

    // AdminPackets
    /**
     * 获取GM特效
     * @param type 类型
     * @param mode 模式
     * @return 数据包
     */
    public static Packet getGMEffect(int type, byte mode) {
        return AdminPackets.getGMEffect(type, mode);
    }

    /**
     * 获取永久封禁
     * @param reason 原因
     * @return 数据包
     */
    public static Packet getPermBan(byte reason) {
        return AdminPackets.getPermBan(reason);
    }

    /**
     * 获取临时封禁
     * @param timestampTill 截止时间戳
     * @param reason 原因
     * @return 数据包
     */
    public static Packet getTempBan(long timestampTill, byte reason) {
        return AdminPackets.getTempBan(timestampTill, reason);
    }

    /**
     * 发送警察消息
     * @return 数据包
     */
    public static Packet sendPolice() {
        return AdminPackets.sendPolice();
    }

    /**
     * 发送警察消息（带文本）
     * @param text 文本
     * @return 数据包
     */
    public static Packet sendPolice(String text) {
        return AdminPackets.sendPolice(text);
    }

    /**
     * 查找商人响应
     * @param map 是否地图
     * @param extra 额外信息
     * @return 数据包
     */
    public static Packet findMerchantResponse(boolean map, int extra) {
        return AdminPackets.findMerchantResponse(map, extra);
    }

    /**
     * 禁用小地图
     * @return 数据包
     */
    public static Packet disableMinimap() {
        return AdminPackets.disableMinimap();
    }

    // MiscPackets
    /**
     * 启用电视
     * @return 数据包
     */
    public static Packet enableTV() {
        return MiscPackets.enableTV();
    }

    /**
     * 移除电视
     * @return 数据包
     */
    public static Packet removeTV() {
        return MiscPackets.removeTV();
    }

    /**
     * 发送电视
     * @param chr 角色对象
     * @param messages 消息列表
     * @param type 类型
     * @param partner 伙伴
     * @return 数据包
     */
    public static Packet sendTV(Character chr, List<String> messages, int type, Character partner) {
        return MiscPackets.sendTV(chr, messages, type, partner);
    }

    /**
     * 启用动作
     * @return 数据包
     */
    public static Packet enableActions() {
        return MiscPackets.enableActions();
    }

    /**
     * 更新玩家状态
     * @param stats 状态列表
     * @param enableActions 是否启用动作
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet updatePlayerStats(List<Pair<Stat, Integer>> stats, boolean enableActions, Character chr) {
        return MiscPackets.updatePlayerStats(stats, enableActions, chr);
    }

    /**
     * 获取角色信息
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet getCharInfo(Character chr) {
        return MiscPackets.getCharInfo(chr);
    }

    /**
     * 角色信息
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet charInfo(Character chr) {
        return MiscPackets.charInfo(chr);
    }

    /**
     * 给予Buff
     * @param buffid Buff ID
     * @param bufflength Buff时长
     * @param statups 状态提升列表
     * @return 数据包
     */
    public static Packet giveBuff(int buffid, int bufflength, List<Pair<BuffStat, Integer>> statups) {
        return MiscPackets.giveBuff(buffid, bufflength, statups);
    }

    /**
     * 给予外部Buff
     * @param chrId 角色ID
     * @param statups 状态提升列表
     * @return 数据包
     */
    public static Packet giveForeignBuff(int chrId, List<Pair<BuffStat, Integer>> statups) {
        return MiscPackets.giveForeignBuff(chrId, statups);
    }

    /**
     * 取消Buff
     * @param statups 状态列表
     * @return 数据包
     */
    public static Packet cancelBuff(List<BuffStat> statups) {
        return MiscPackets.cancelBuff(statups);
    }

    /**
     * 取消外部Buff
     * @param chrId 角色ID
     * @param statups 状态列表
     * @return 数据包
     */
    public static Packet cancelForeignBuff(int chrId, List<BuffStat> statups) {
        return MiscPackets.cancelForeignBuff(chrId, statups);
    }

    /**
     * 给予Debuff
     * @param statups 状态列表
     * @param skill 技能
     * @return 数据包
     */
    public static Packet giveDebuff(List<Pair<Disease, Integer>> statups, MobSkill skill) {
        return MiscPackets.giveDebuff(statups, skill);
    }

    /**
     * 给予外部Debuff
     * @param chrId 角色ID
     * @param statups 状态列表
     * @param skill 技能
     * @return 数据包
     */
    public static Packet giveForeignDebuff(int chrId, List<Pair<Disease, Integer>> statups, MobSkill skill) {
        return MiscPackets.giveForeignDebuff(chrId, statups, skill);
    }

    /**
     * 取消Debuff
     * @param mask 掩码
     * @return 数据包
     */
    public static Packet cancelDebuff(long mask) {
        return MiscPackets.cancelDebuff(mask);
    }

    /**
     * 取消外部Debuff
     * @param cid 角色ID
     * @param mask 掩码
     * @return 数据包
     */
    public static Packet cancelForeignDebuff(int cid, long mask) {
        return MiscPackets.cancelForeignDebuff(cid, mask);
    }

    /**
     * 取消外部首个Debuff
     * @param cid 角色ID
     * @param mask 掩码
     * @return 数据包
     */
    public static Packet cancelForeignFirstDebuff(int cid, long mask) {
        return MiscPackets.cancelForeignFirstDebuff(cid, mask);
    }

    /**
     * 给予外部缓慢Debuff
     * @param chrId 角色ID
     * @param statups 状态列表
     * @param skill 技能
     * @return 数据包
     */
    public static Packet giveForeignSlowDebuff(int chrId, List<Pair<Disease, Integer>> statups, MobSkill skill) {
        return MiscPackets.giveForeignSlowDebuff(chrId, statups, skill);
    }

    /**
     * 取消外部缓慢Debuff
     * @param chrId 角色ID
     * @return 数据包
     */
    public static Packet cancelForeignSlowDebuff(int chrId) {
        return MiscPackets.cancelForeignSlowDebuff(chrId);
    }

    /**
     * 给予外部WK充能特效
     * @param cid 角色ID
     * @param buffid Buff ID
     * @param statups 状态列表
     * @return 数据包
     */
    public static Packet giveForeignWKChargeEffect(int cid, int buffid, List<Pair<BuffStat, Integer>> statups) {
        return MiscPackets.giveForeignWKChargeEffect(cid, buffid, statups);
    }

    /**
     * 给予海盗Buff
     * @param statups 状态列表
     * @param buffid Buff ID
     * @param duration 持续时间
     * @return 数据包
     */
    public static Packet givePirateBuff(List<Pair<BuffStat, Integer>> statups, int buffid, int duration) {
        return MiscPackets.givePirateBuff(statups, buffid, duration);
    }

    /**
     * 给予外部海盗Buff
     * @param cid 角色ID
     * @param buffid Buff ID
     * @param time 时间
     * @param statups 状态列表
     * @return 数据包
     */
    public static Packet giveForeignPirateBuff(int cid, int buffid, int time, List<Pair<BuffStat, Integer>> statups) {
        return MiscPackets.giveForeignPirateBuff(cid, buffid, time, statups);
    }

    /**
     * 给予终极攻击
     * @param skillid 技能ID
     * @param time 时间
     * @return 数据包
     */
    public static Packet giveFinalAttack(int skillid, int time) {
        return MiscPackets.giveFinalAttack(skillid, time);
    }

    /**
     * 更新技能
     * @param skillId 技能ID
     * @param level 等级
     * @param masterlevel 大师等级
     * @param expiration 过期时间
     * @return 数据包
     */
    public static Packet updateSkill(int skillId, int level, int masterlevel, long expiration) {
        return MiscPackets.updateSkill(skillId, level, masterlevel, expiration);
    }

    /**
     * 技能冷却
     * @param sid 技能ID
     * @param time 时间
     * @return 数据包
     */
    public static Packet skillCooldown(int sid, int time) {
        return MiscPackets.skillCooldown(sid, time);
    }

    /**
     * 技能书结果
     * @param chr 角色对象
     * @param skillid 技能ID
     * @param maxlevel 最大等级
     * @param canuse 是否可用
     * @param success 是否成功
     * @return 数据包
     */
    public static Packet skillBookResult(Character chr, int skillid, int maxlevel, boolean canuse, boolean success) {
        return MiscPackets.skillBookResult(chr, skillid, maxlevel, canuse, success);
    }

    /**
     * 获取宏
     * @param macros 宏数组
     * @return 数据包
     */
    public static Packet getMacros(SkillMacro[] macros) {
        return MiscPackets.getMacros(macros);
    }

    /**
     * 更新坐骑
     * @param charid 角色ID
     * @param mount 坐骑对象
     * @param levelup 是否升级
     * @return 数据包
     */
    public static Packet updateMount(int charid, Mount mount, boolean levelup) {
        return MiscPackets.updateMount(charid, mount, levelup);
    }

    /**
     * 显示怪物骑乘
     * @param cid 角色ID
     * @param mount 坐骑对象
     * @return 数据包
     */
    public static Packet showMonsterRiding(int cid, Mount mount) {
        return MiscPackets.showMonsterRiding(cid, mount);
    }

    /**
     * 使用黑板
     * @param chr 角色对象
     * @param close 是否关闭
     * @return 数据包
     */
    public static Packet useChalkboard(Character chr, boolean close) {
        return MiscPackets.useChalkboard(chr, close);
    }

    /**
     * 打开UI
     * @param ui UI ID
     * @return 数据包
     */
    public static Packet openUI(byte ui) {
        return MiscPackets.openUI(ui);
    }

    /**
     * 锁定UI
     * @param enable 是否启用
     * @return 数据包
     */
    public static Packet lockUI(boolean enable) {
        return MiscPackets.lockUI(enable);
    }

    /**
     * 禁用UI
     * @param enable 是否启用
     * @return 数据包
     */
    public static Packet disableUI(boolean enable) {
        return MiscPackets.disableUI(enable);
    }

    /**
     * 获取键位映射
     * @param keybindings 键位映射
     * @return 数据包
     */
    public static Packet getKeymap(Map<Integer, KeyBinding> keybindings) {
        return MiscPackets.getKeymap(keybindings);
    }

    /**
     * 快捷键初始化
     * @param pQuickslot 快捷键绑定
     * @return 数据包
     */
    public static Packet QuickslotMappedInit(QuickslotBinding pQuickslot) {
        return MiscPackets.QuickslotMappedInit(pQuickslot);
    }

    /**
     * 显示连击
     * @param count 连击数
     * @return 数据包
     */
    public static Packet showCombo(int count) {
        return MiscPackets.showCombo(count);
    }

    /**
     * 重置强制状态
     * @return 数据包
     */
    public static Packet resetForcedStats() {
        return MiscPackets.resetForcedStats();
    }

    /**
     * 战神神级状态
     * @return 数据包
     */
    public static Packet aranGodlyStats() {
        return MiscPackets.aranGodlyStats();
    }

    /**
     * 更新区域信息
     * @param area 区域
     * @param info 信息
     * @return 数据包
     */
    public static Packet updateAreaInfo(int area, String info) {
        return MiscPackets.updateAreaInfo(area, info);
    }

    /**
     * 获取GP消息
     * @param gpChange GP变化
     * @return 数据包
     */
    public static Packet getGPMessage(int gpChange) {
        return MiscPackets.getGPMessage(gpChange);
    }

    /**
     * 添加卡片
     * @param full 是否满
     * @param cardid 卡片ID
     * @param level 等级
     * @return 数据包
     */
    public static Packet addCard(boolean full, int cardid, int level) {
        return MiscPackets.addCard(full, cardid, level);
    }

    /**
     * 显示获得卡片
     * @return 数据包
     */
    public static Packet showGainCard() {
        return MiscPackets.showGainCard();
    }

    /**
     * 显示外部卡片特效
     * @param id ID
     * @return 数据包
     */
    public static Packet showForeignCardEffect(int id) {
        return MiscPackets.showForeignCardEffect(id);
    }

    /**
     * 更改封面
     * @param cardid 卡片ID
     * @return 数据包
     */
    public static Packet changeCover(int cardid) {
        return MiscPackets.changeCover(cardid);
    }

    /**
     * 新年卡片响应
     * @param user 用户
     * @param cardId 卡片ID
     * @param mode 模式
     * @param msg 消息
     * @return 数据包
     */
    public static Packet onNewYearCardRes(Character user, int cardId, int mode, int msg) {
        return MiscPackets.onNewYearCardRes(user, cardId, mode, msg);
    }

    /**
     * 新年卡片响应（带记录）
     * @param user 用户
     * @param newyear 新年卡片记录
     * @param mode 模式
     * @param msg 消息
     * @return 数据包
     */
    public static Packet onNewYearCardRes(Character user, NewYearCardRecord newyear, int mode, int msg) {
        return PacketHelper.onNewYearCardRes(user, newyear, mode, msg);
    }

    /**
     * 获得称号消息
     * @param msg 消息
     * @return 数据包
     */
    public static Packet earnTitleMessage(String msg) {
        return MiscPackets.earnTitleMessage(msg);
    }

    /**
     * 发送黄色提示
     * @param tip 提示内容
     * @return 数据包
     */
    public static Packet sendYellowTip(String tip) {
        return MiscPackets.sendYellowTip(tip);
    }

    /**
     * 扭蛋消息
     * @param item 物品对象
     * @param town 城镇
     * @param player 玩家
     * @return 数据包
     */
    public static Packet gachaponMessage(Item item, String town, Character player) {
        return MiscPackets.gachaponMessage(item, town, player);
    }

    /**
     * 显示活动说明
     * @return 数据包
     */
    public static Packet showEventInstructions() {
        return MiscPackets.showEventInstructions();
    }

    /**
     * 兔子包
     * @return 数据包
     */
    public static Packet bunnyPacket() {
        return MiscPackets.bunnyPacket();
    }

    /**
     * HPQ消息
     * @param text 文本
     * @return 数据包
     */
    public static Packet hpqMessage(String text) {
        return MiscPackets.hpqMessage(text);
    }

    /**
     * 滚雪球
     * @param entermap 是否进入地图
     * @param state 状态
     * @param ball0 雪球0
     * @param ball1 雪球1
     * @return 数据包
     */
    public static Packet rollSnowBall(boolean entermap, int state, Snowball ball0, Snowball ball1) {
        return MiscPackets.rollSnowBall(entermap, state, ball0, ball1);
    }

    /**
     * 击中雪球
     * @param what 什么
     * @param damage 伤害
     * @return 数据包
     */
    public static Packet hitSnowBall(int what, int damage) {
        return MiscPackets.hitSnowBall(what, damage);
    }

    /**
     * 雪球消息
     * @param team 队伍
     * @param message 消息
     * @return 数据包
     */
    public static Packet snowballMessage(int team, int message) {
        return MiscPackets.snowballMessage(team, message);
    }

    /**
     * 椰子得分
     * @param team1 队伍1
     * @param team2 队伍2
     * @return 数据包
     */
    public static Packet coconutScore(int team1, int team2) {
        return MiscPackets.coconutScore(team1, team2);
    }

    /**
     * 击中椰子
     * @param spawn 是否生成
     * @param id ID
     * @param type 类型
     * @return 数据包
     */
    public static Packet hitCoconut(boolean spawn, int id, int type) {
        return MiscPackets.hitCoconut(spawn, id, type);
    }

    /**
     * CP更新
     * @param party 是否队伍
     * @param curCP 当前CP
     * @param totalCP 总CP
     * @param team 队伍
     * @return 数据包
     */
    public static Packet CPUpdate(boolean party, int curCP, int totalCP, int team) {
        return MiscPackets.CPUpdate(party, curCP, totalCP, team);
    }

    /**
     * CPQ消息
     * @param message 消息
     * @return 数据包
     */
    public static Packet CPQMessage(byte message) {
        return MiscPackets.CPQMessage(message);
    }

    /**
     * 玩家召唤
     * @param name 名称
     * @param tab 标签
     * @param number 编号
     * @return 数据包
     */
    public static Packet playerSummoned(String name, int tab, int number) {
        return MiscPackets.playerSummoned(name, tab, number);
    }

    /**
     * 玩家死亡消息
     * @param name 名称
     * @param lostCP 损失CP
     * @param team 队伍
     * @return 数据包
     */
    public static Packet playerDiedMessage(String name, int lostCP, int team) {
        return MiscPackets.playerDiedMessage(name, lostCP, team);
    }

    /**
     * 开始怪物嘉年华
     * @param chr 角色对象
     * @param team 队伍
     * @param opposition 对手
     * @return 数据包
     */
    public static Packet startMonsterCarnival(Character chr, int team, int opposition) {
        return MiscPackets.startMonsterCarnival(chr, team, opposition);
    }

    /**
     * 牧羊场信息
     * @param wolf 狼
     * @param sheep 羊
     * @return 数据包
     */
    public static Packet sheepRanchInfo(byte wolf, byte sheep) {
        return MiscPackets.sheepRanchInfo(wolf, sheep);
    }

    /**
     * 牧羊场衣服
     * @param id ID
     * @param clothes 衣服
     * @return 数据包
     */
    public static Packet sheepRanchClothes(int id, byte clothes) {
        return MiscPackets.sheepRanchClothes(id, clothes);
    }

    /**
     * 金字塔计量条
     * @param gauge 计量值
     * @return 数据包
     */
    public static Packet pyramidGauge(int gauge) {
        return MiscPackets.pyramidGauge(gauge);
    }

    /**
     * 金字塔得分
     * @param score 得分
     * @param exp 经验
     * @return 数据包
     */
    public static Packet pyramidScore(byte score, int exp) {
        return MiscPackets.pyramidScore(score, exp);
    }

    /**
     * 孵化器结果
     * @return 数据包
     */
    public static Packet incubatorResult() {
        return MiscPackets.incubatorResult();
    }

    /**
     * 获取道场信息
     * @param info 信息
     * @return 数据包
     */
    public static Packet getDojoInfo(String info) {
        return MiscPackets.getDojoInfo(info);
    }

    /**
     * 获取道场信息消息
     * @param message 消息
     * @return 数据包
     */
    public static Packet getDojoInfoMessage(String message) {
        return MiscPackets.getDojoInfoMessage(message);
    }

    /**
     * 发送道场动画
     * @param firstByte 首字节
     * @param animation 动画
     * @return 数据包
     */
    public static Packet sendDojoAnimation(byte firstByte, String animation) {
        return MiscPackets.sendDojoAnimation(firstByte, animation);
    }

    /**
     * 更新道场状态
     * @param chr 角色对象
     * @param belt 腰带
     * @return 数据包
     */
    public static Packet updateDojoStats(Character chr, int belt) {
        return MiscPackets.updateDojoStats(chr, belt);
    }

    /**
     * 道场传送
     * @return 数据包
     */
    public static Packet dojoWarpUp() {
        return MiscPackets.dojoWarpUp();
    }

    /**
     * 获取能量
     * @param info 信息
     * @param amount 数量
     * @return 数据包
     */
    public static Packet getEnergy(String info, int amount) {
        return MiscPackets.getEnergy(info, amount);
    }

    /**
     * 显示阿里安特计分板
     * @return 数据包
     */
    public static Packet showAriantScoreBoard() {
        return MiscPackets.showAriantScoreBoard();
    }

    /**
     * 更新阿里安特PQ排名
     * @param playerScore 玩家得分映射
     * @return 数据包
     */
    public static Packet updateAriantPQRanking(Map<Character, Integer> playerScore) {
        return MiscPackets.updateAriantPQRanking(playerScore);
    }

    /**
     * 更新女巫塔得分
     * @param score 得分
     * @return 数据包
     */
    public static Packet updateWitchTowerScore(int score) {
        return MiscPackets.updateWitchTowerScore(score);
    }

    /**
     * 制造者结果
     * @param success 是否成功
     * @param itemMade 制造物品
     * @param itemCount 物品数量
     * @param mesos 金币
     * @param itemsLost 消耗物品列表
     * @param catalystID 催化剂ID
     * @param INCBuffGems 增益宝石列表
     * @return 数据包
     */
    public static Packet makerResult(boolean success, int itemMade, int itemCount, int mesos, List<Pair<Integer, Integer>> itemsLost, int catalystID, List<Integer> INCBuffGems) {
        return MiscPackets.makerResult(success, itemMade, itemCount, mesos, itemsLost, catalystID, INCBuffGems);
    }

    /**
     * 制造者结果（水晶）
     * @param itemIdGained 获得物品ID
     * @param itemIdLost 消耗物品ID
     * @return 数据包
     */
    public static Packet makerResultCrystal(int itemIdGained, int itemIdLost) {
        return MiscPackets.makerResultCrystal(itemIdGained, itemIdLost);
    }

    /**
     * 制造者结果（分解）
     * @param itemId 物品ID
     * @param mesos 金币
     * @param itemsGained 获得物品列表
     * @return 数据包
     */
    public static Packet makerResultDesynth(int itemId, int mesos, List<Pair<Integer, Integer>> itemsGained) {
        return MiscPackets.makerResultDesynth(itemId, mesos, itemsGained);
    }

    /**
     * 制造者启用动作
     * @return 数据包
     */
    public static Packet makerEnableActions() {
        return MiscPackets.makerEnableActions();
    }

    /**
     * 显示制造者特效
     * @param makerSucceeded 是否成功
     * @return 数据包
     */
    public static Packet showMakerEffect(boolean makerSucceeded) {
        return MiscPackets.showMakerEffect(makerSucceeded);
    }

    /**
     * 显示外部制造者特效
     * @param cid 角色ID
     * @param makerSucceeded 是否成功
     * @return 数据包
     */
    public static Packet showForeignMakerEffect(int cid, boolean makerSucceeded) {
        return MiscPackets.showForeignMakerEffect(cid, makerSucceeded);
    }

    /**
     * 显示恢复
     * @param chrId 角色ID
     * @param amount 数量
     * @return 数据包
     */
    public static Packet showRecovery(int chrId, byte amount) {
        return MiscPackets.showRecovery(chrId, amount);
    }

    /**
     * 显示自身恢复
     * @param heal 治疗量
     * @return 数据包
     */
    public static Packet showOwnRecovery(byte heal) {
        return MiscPackets.showOwnRecovery(heal);
    }

    /**
     * 显示剩余轮子
     * @param left 剩余数
     * @return 数据包
     */
    public static Packet showWheelsLeft(int left) {
        return MiscPackets.showWheelsLeft(left);
    }

    /**
     * 任务错误
     * @param quest 任务ID
     * @return 数据包
     */
    public static Packet questError(short quest) {
        return MiscPackets.questError(quest);
    }

    /**
     * 任务失败
     * @param type 类型
     * @return 数据包
     */
    public static Packet questFailure(byte type) {
        return MiscPackets.questFailure(type);
    }

    /**
     * 任务过期
     * @param quest 任务ID
     * @return 数据包
     */
    public static Packet questExpire(short quest) {
        return MiscPackets.questExpire(quest);
    }

    /**
     * 更新任务
     * @param chr 角色对象
     * @param qs 任务状态
     * @param infoUpdate 是否信息更新
     * @return 数据包
     */
    public static Packet updateQuest(Character chr, QuestStatus qs, boolean infoUpdate) {
        return MiscPackets.updateQuest(chr, qs, infoUpdate);
    }

    /**
     * 更新任务信息
     * @param quest 任务ID
     * @param npc NPC ID
     * @return 数据包
     */
    public static Packet updateQuestInfo(short quest, int npc) {
        return MiscPackets.updateQuestInfo(quest, npc);
    }

    /**
     * 更新任务完成
     * @param quest 任务ID
     * @param npc NPC ID
     * @param nextquest 下一个任务ID
     * @return 数据包
     */
    public static Packet updateQuestFinish(short quest, int npc, short nextquest) {
        return MiscPackets.updateQuestFinish(quest, npc, nextquest);
    }

    /**
     * 添加任务时间限制
     * @param quest 任务ID
     * @param time 时间
     * @return 数据包
     */
    public static Packet addQuestTimeLimit(final short quest, final int time) {
        return MiscPackets.addQuestTimeLimit(quest, time);
    }

    /**
     * 移除任务时间限制
     * @param quest 任务ID
     * @return 数据包
     */
    public static Packet removeQuestTimeLimit(final short quest) {
        return MiscPackets.removeQuestTimeLimit(quest);
    }

    /**
     * 放弃任务
     * @param quest 任务ID
     * @return 数据包
     */
    public static Packet forfeitQuest(short quest) {
        return MiscPackets.forfeitQuest(quest);
    }

    /**
     * 完成任务
     * @param quest 任务ID
     * @param time 时间
     * @return 数据包
     */
    public static Packet completeQuest(short quest, long time) {
        return MiscPackets.completeQuest(quest, time);
    }

    /**
     * 获取显示任务完成
     * @param id ID
     * @return 数据包
     */
    public static Packet getShowQuestCompletion(int id) {
        return MiscPackets.getShowQuestCompletion(id);
    }

    /**
     * 字段HP减少通知
     * @param change 变化量
     * @return 数据包
     */
    public static Packet onNotifyHPDecByField(int change) {
        return MiscPackets.onNotifyHPDecByField(change);
    }

    /**
     * 自定义数据包（字符串）
     * @param packet 数据包内容
     * @return 数据包
     */
    public static Packet customPacket(String packet) {
        return MiscPackets.customPacket(packet);
    }

    /**
     * 自定义数据包（字节数组）
     * @param packet 数据包内容
     * @return 数据包
     */
    public static Packet customPacket(byte[] packet) {
        return MiscPackets.customPacket(packet);
    }

    /**
     * 发送提示
     * @param hint 提示内容
     * @param width 宽度
     * @param height 高度
     * @return 数据包
     */
    public static Packet sendHint(String hint, int width, int height) {
        return FieldPackets.sendHint(hint, width, height);
    }

    /**
     * 获取显示经验获得
     * @param gain 获得量
     * @param equip 装备
     * @param party 队伍
     * @param inChat 是否在聊天框显示
     * @param white 是否白色
     * @return 数据包
     */
    public static Packet getShowExpGain(int gain, int equip, int party, boolean inChat, boolean white) {
        return PacketHelper.getShowExpGain(gain, equip, party, inChat, white);
    }

    /**
     * 给予名声响应
     * @param mode 模式
     * @param charname 角色名
     * @param newfame 新名声
     * @return 数据包
     */
    public static Packet giveFameResponse(int mode, String charname, int newfame) {
        return PacketHelper.giveFameResponse(mode, charname, newfame);
    }

    /**
     * 接收名声
     * @param mode 模式
     * @param charnameFrom 来源角色名
     * @return 数据包
     */
    public static Packet receiveFame(int mode, String charnameFrom) {
        return PacketHelper.receiveFame(mode, charnameFrom);
    }

    /**
     * 获取显示名声获得
     * @param gain 获得量
     * @return 数据包
     */
    public static Packet getShowFameGain(int gain) {
        return PacketHelper.getShowFameGain(gain);
    }

    /**
     * 获取显示金币获得
     * @param gain 获得量
     * @param inChat 是否在聊天框显示
     * @return 数据包
     */
    public static Packet getShowMesoGain(int gain, boolean inChat) {
        return PacketHelper.getShowMesoGain(gain, inChat);
    }

    /**
     * 显示OX测验
     * @param questionSet 问题集
     * @param questionId 问题ID
     * @param askQuestion 是否提问
     * @return 数据包
     */
    public static Packet showOXQuiz(int questionSet, int questionId, boolean askQuestion) {
        return PacketHelper.showOXQuiz(questionSet, questionId, askQuestion);
    }

    /**
     * 刷新传送地图列表
     * @param chr 角色对象
     * @param delete 是否删除
     * @param vip 是否VIP
     * @return 数据包
     */
    public static Packet trockRefreshMapList(Character chr, boolean delete, boolean vip) {
        return PacketHelper.trockRefreshMapList(chr, delete, vip);
    }

    /**
     * 给予名声错误响应
     * @param status 状态
     * @return 数据包
     */
    public static Packet giveFameErrorResponse(int status) {
        return PacketHelper.giveFameErrorResponse(status);
    }

    /**
     * 左侧击退
     * @return 数据包
     */
    public static Packet leftKnockBack() {
        return PacketHelper.leftKnockBack();
    }

    /**
     * 发送自动HP药水
     * @param itemId 物品ID
     * @return 数据包
     */
    public static Packet sendAutoHpPot(int itemId) {
        return PacketHelper.sendAutoHpPot(itemId);
    }

    /**
     * 发送自动MP药水
     * @param itemId 物品ID
     * @return 数据包
     */
    public static Packet sendAutoMpPot(int itemId) {
        return PacketHelper.sendAutoMpPot(itemId);
    }

    /**
     * 发送Vega卷轴
     * @param op 操作
     * @return 数据包
     */
    public static Packet sendVegaScroll(int op) {
        return PacketHelper.sendVegaScroll(op);
    }

    // WeddingPackets
    /**
     * 通知婚礼伴侣传送
     * @param mapid 地图ID
     * @param channel 频道
     * @return 数据包
     */
    public static Packet OnNotifyWeddingPartnerTransfer(int mapid, int channel) {
        return WeddingPackets.OnNotifyWeddingPartnerTransfer(mapid, channel);
    }

    /**
     * 婚礼礼物结果
     * @param mode 模式
     * @param names 名称列表
     * @param items 物品列表
     * @return 数据包
     */
    public static Packet onWeddingGiftResult(byte mode, List<String> names, List<Item> items) {
        return WeddingPackets.onWeddingGiftResult(mode, names, items);
    }

    /**
     * 发送愿望清单
     * @return 数据包
     */
    public static Packet sendWishList() {
        return WeddingPackets.sendWishList();
    }

    /**
     * 婚礼进度
     * @param start 是否开始
     * @param groomId 新郎ID
     * @param brideId 新娘ID
     * @param state 状态
     * @return 数据包
     */
    public static Packet OnWeddingProgress(boolean start, int groomId, int brideId, byte state) {
        return WeddingPackets.OnWeddingProgress(start, groomId, brideId, state);
    }

    /**
     * 结婚结果
     * @param mode 模式
     * @return 数据包
     */
    public static Packet OnMarriageResult(byte mode) {
        return WeddingPackets.OnMarriageResult(mode);
    }

    /**
     * 结婚结果（带角色）
     * @param mode 模式
     * @param chr 角色对象
     * @param success 是否成功
     * @return 数据包
     */
    public static Packet OnMarriageResult(int mode, Character chr, boolean success) {
        return WeddingPackets.OnMarriageResult(mode, chr, success);
    }

    /**
     * 结婚请求
     * @param name 名称
     * @param id ID
     * @return 数据包
     */
    public static Packet onMarriageRequest(String name, int id) {
        return WeddingPackets.onMarriageRequest(name, id);
    }

    /**
     * 发送婚礼邀请
     * @param groom 新郎
     * @param bride 新娘
     * @return 数据包
     */
    public static Packet sendWeddingInvitation(String groom, String bride) {
        return WeddingPackets.sendWeddingInvitation(groom, bride);
    }

    /**
     * 拍照
     * @param ReservedGroomName 预定新郎名
     * @param ReservedBrideName 预定新娘名
     * @param m_dwField 地图ID
     * @param m_dwUsers 用户列表
     * @return 数据包
     */
    public static Packet onTakePhoto(String ReservedGroomName, String ReservedBrideName, int m_dwField, List<Character> m_dwUsers) {
        return WeddingPackets.onTakePhoto(ReservedGroomName, ReservedBrideName, m_dwField, m_dwUsers);
    }
}
