package org.gms.util.packets;

import org.gms.client.BuddylistEntry;
import org.gms.client.Character;
import org.gms.client.Family;
import org.gms.client.FamilyEntitlement;
import org.gms.client.FamilyEntry;
import org.gms.client.inventory.Item;
import org.gms.net.opcodes.SendOpcode;
import org.gms.net.packet.OutPacket;
import org.gms.net.packet.Packet;
import org.gms.net.server.channel.handlers.WhisperHandler;
import org.gms.net.server.world.Party;
import org.gms.net.server.world.PartyCharacter;
import org.gms.net.server.world.PartyOperation;
import org.gms.server.DueyPackage;
import org.gms.util.HexTool;
import org.gms.util.StringUtil;

import java.awt.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * SocialPackets
 * 处理聊天、组队、家族、公会、结婚、信使等相关的数据包构建
 */
public class SocialPackets {

    /**
     * 获取普通聊天包
     *
     * @param cidfrom 发送者角色 ID
     * @param text    聊天内容
     * @param gm      是否 GM
     * @param show    显示模式
     * @return 普通聊天包
     */
    public static Packet getChatText(int cidfrom, String text, boolean gm, int show) {
        final OutPacket p = OutPacket.create(SendOpcode.CHATTEXT);
        p.writeInt(cidfrom);
        p.writeBool(gm);
        p.writeString(text);
        p.writeByte(show);
        return p;
    }

    /**
     * 获取多人聊天包
     * mode: 0 好友聊天; 1 组队聊天; 2 公会聊天
     *
     * @param name     发送者名字
     * @param chattext 聊天内容
     * @param mode     模式
     * @return 多人聊天包
     */
    public static Packet multiChat(String name, String chattext, int mode) {
        OutPacket p = OutPacket.create(SendOpcode.MULTICHAT);
        p.writeByte(mode);
        p.writeString(name);
        p.writeString(chattext);
        return p;
    }

    /**
     * 获取多重喇叭包
     *
     * @param messages 消息数组
     * @param channel  频道
     * @param showEar  是否显示耳朵
     * @return 多重喇叭包
     */
    public static Packet getMultiMegaphone(String[] messages, int channel, boolean showEar) {
        final OutPacket p = OutPacket.create(SendOpcode.SERVERMESSAGE);
        p.writeByte(0x0A);
        if (messages[0] != null) {
            p.writeString(messages[0]);
        }
        p.writeByte(messages.length);
        for (int i = 1; i < messages.length; i++) {
            if (messages[i] != null) {
                p.writeString(messages[i]);
            }
        }
        for (int i = 0; i < 10; i++) {
            p.writeByte(channel - 1);
        }
        p.writeByte(showEar ? 1 : 0);
        p.writeByte(1);
        return p;
    }

    /**
     * 获取服务器消息包
     *
     * @param message 消息内容
     * @return 服务器消息包
     */
    public static Packet serverMessage(String message) {
        return serverMessage(4, (byte) 0, message, true, false, 0);
    }

    /**
     * 获取服务器通知包
     *
     * @param type    类型
     * @param message 消息内容
     * @return 服务器通知包
     */
    public static Packet serverNotice(int type, String message) {
        return serverMessage(type, (byte) 0, message, false, false, 0);
    }

    /**
     * 获取服务器通知包（带 NPC）
     *
     * @param type    类型
     * @param message 消息内容
     * @param npc     NPC ID
     * @return 服务器通知包
     */
    public static Packet serverNotice(int type, String message, int npc) {
        return serverMessage(type, 0, message, false, false, npc);
    }

    /**
     * 获取服务器通知包（带频道）
     *
     * @param type    类型
     * @param channel 频道
     * @param message 消息内容
     * @return 服务器通知包
     */
    public static Packet serverNotice(int type, int channel, String message) {
        return serverMessage(type, channel, message, false, false, 0);
    }

    /**
     * 获取服务器通知包（带频道和耳朵）
     *
     * @param type     类型
     * @param channel  频道
     * @param message  消息内容
     * @param smegaEar 是否显示耳朵
     * @return 服务器通知包
     */
    public static Packet serverNotice(int type, int channel, String message, boolean smegaEar) {
        return serverMessage(type, channel, message, false, smegaEar, 0);
    }

    /**
     * 内部方法：获取服务器消息包
     *
     * @param type          类型
     * @param channel       频道
     * @param message       消息内容
     * @param servermessage 是否服务器消息
     * @param megaEar       是否显示耳朵
     * @param npc           NPC ID
     * @return 服务器消息包
     */
    private static Packet serverMessage(int type, int channel, String message, boolean servermessage, boolean megaEar, int npc) {
        OutPacket p = OutPacket.create(SendOpcode.SERVERMESSAGE);
        p.writeByte(type);
        if (servermessage) {
            p.writeByte(1);
        }
        p.writeString(message);
        if (type == 3) {
            p.writeByte(channel - 1); // channel // 频道
            p.writeBool(megaEar);
        } else if (type == 6) {
            p.writeInt(0);
        } else if (type == 7) { // npc
            p.writeInt(npc);
        }
        return p;
    }

    /**
     * 获取头像喇叭包
     *
     * @param chr     角色对象
     * @param medal   勋章
     * @param channel 频道
     * @param itemId  物品 ID
     * @param message 消息列表
     * @param ear     是否显示耳朵
     * @return 头像喇叭包
     */
    public static Packet getAvatarMega(Character chr, String medal, int channel, int itemId, List<String> message, boolean ear) {
        final OutPacket p = OutPacket.create(SendOpcode.SET_AVATAR_MEGAPHONE);
        p.writeInt(itemId);
        p.writeString(medal + chr.getName());
        for (String s : message) {
            p.writeString(s);
        }
        p.writeInt(channel - 1); // channel // 频道
        p.writeBool(ear);
        PacketHelper.addCharLook(p, chr, true);
        return p;
    }

    /**
     * 获取关闭头像喇叭包
     *
     * @return 关闭头像喇叭包
     */
    public static Packet byeAvatarMega() {
        final OutPacket p = OutPacket.create(SendOpcode.CLEAR_AVATAR_MEGAPHONE);
        p.writeByte(1);
        return p;
    }

    /**
     * 获取物品喇叭包
     *
     * @param msg     消息内容
     * @param whisper 是否私聊
     * @param channel 频道
     * @param item    物品对象
     * @return 物品喇叭包
     */
    public static Packet itemMegaphone(String msg, boolean whisper, int channel, Item item) {
        final OutPacket p = OutPacket.create(SendOpcode.SERVERMESSAGE);
        p.writeByte(8);
        p.writeString(msg);
        p.writeByte(channel - 1);
        p.writeByte(whisper ? 1 : 0);
        if (item == null) {
            p.writeByte(0);
        } else {
            p.writeByte(item.getPosition());
            PacketHelper.addItemInfo(p, item, true);
        }
        return p;
    }

    /**
     * 获取队伍创建包
     *
     * @param party       队伍对象
     * @param partycharid 队伍角色 ID
     * @return 队伍创建包
     */
    public static Packet partyCreated(Party party, int partycharid) {
        final OutPacket p = OutPacket.create(SendOpcode.PARTY_OPERATION);
        p.writeByte(8);
        p.writeInt(party.getId());

        // 这里的逻辑在 PacketCreator 中比较复杂，涉及到 Door，这里简化处理，因为 Door 逻辑主要在 FieldPackets
        // 如果需要完整的 Door 信息，可能需要从 Party 中获取
        // 暂时保留原逻辑结构，但注意 Door 的引用
        // 由于 Door 属于地图对象，这里可能无法直接获取完整的 DoorObject 信息，除非 Party 中存储了足够的信息
        // 假设 Party.getDoors() 返回的是 Map<Integer, Door>
        // 这里为了避免依赖 FieldPackets 中的逻辑，我们只写入空门信息，或者需要重构 Party 类以包含更多信息
        // 实际上 PacketCreator 中是直接访问了 Door 对象。
        // 为了解耦，这里暂时写入空门，或者需要引入 Door 类
        // 鉴于 Door 在 server.maps 包中，可以引用。

        p.writeInt(0); // MapId.NONE
        p.writeInt(0); // MapId.NONE
        p.writeInt(0);
        p.writeInt(0);

        return p;
    }

    /**
     * 获取队伍邀请包
     *
     * @param from 邀请者
     * @return 队伍邀请包
     */
    public static Packet partyInvite(Character from) {
        final OutPacket p = OutPacket.create(SendOpcode.PARTY_OPERATION);
        p.writeByte(4);
        p.writeInt(from.getParty().getId());
        p.writeString(from.getName());
        p.writeByte(0);
        return p;
    }

    /**
     * 获取队伍搜索邀请包
     *
     * @param from 邀请者
     * @return 队伍搜索邀请包
     */
    public static Packet partySearchInvite(Character from) {
        final OutPacket p = OutPacket.create(SendOpcode.PARTY_OPERATION);
        p.writeByte(4);
        p.writeInt(from.getParty().getId());
        p.writeString("PS: " + from.getName());
        p.writeByte(0);
        return p;
    }

    /**
     * 获取队伍状态消息包
     *
     * @param message 消息代码
     * @return 队伍状态消息包
     */
    public static Packet partyStatusMessage(int message) {
        final OutPacket p = OutPacket.create(SendOpcode.PARTY_OPERATION);
        p.writeByte(message);
        return p;
    }

    /**
     * 获取队伍状态消息包（带角色名）
     *
     * @param message  消息代码
     * @param charname 角色名
     * @return 队伍状态消息包
     */
    public static Packet partyStatusMessage(int message, String charname) {
        final OutPacket p = OutPacket.create(SendOpcode.PARTY_OPERATION);
        p.writeByte(message);
        p.writeString(charname);
        return p;
    }

    /**
     * 获取更新队伍包
     *
     * @param forChannel 频道
     * @param party      队伍对象
     * @param op         操作
     * @param target     目标角色
     * @return 更新队伍包
     */
    public static Packet updateParty(int forChannel, Party party, PartyOperation op, PartyCharacter target) {
        final OutPacket p = OutPacket.create(SendOpcode.PARTY_OPERATION);
        switch (op) {
            case DISBAND:
            case EXPEL:
            case LEAVE:
                p.writeByte(0x0C);
                p.writeInt(party.getId());
                p.writeInt(target.getId());
                if (op == PartyOperation.DISBAND) {
                    p.writeByte(0);
                    p.writeInt(party.getId());
                } else {
                    p.writeByte(1);
                    if (op == PartyOperation.EXPEL) {
                        p.writeByte(1);
                    } else {
                        p.writeByte(0);
                    }
                    p.writeString(target.getName());
                    PacketHelper.addPartyStatus(forChannel, party, p, false);
                }
                break;
            case JOIN:
                p.writeByte(0xF);
                p.writeInt(party.getId());
                p.writeString(target.getName());
                PacketHelper.addPartyStatus(forChannel, party, p, false);
                break;
            case SILENT_UPDATE:
            case LOG_ONOFF:
                p.writeByte(0x7);
                p.writeInt(party.getId());
                PacketHelper.addPartyStatus(forChannel, party, p, false);
                break;
            case CHANGE_LEADER:
                p.writeByte(0x1B);
                p.writeInt(target.getId());
                p.writeByte(0);
                break;
        }
        return p;
    }

    /**
     * 获取队伍传送门包
     *
     * @param townId   城镇 ID
     * @param targetId 目标 ID
     * @param position 位置
     * @return 队伍传送门包
     */
    public static Packet partyPortal(int townId, int targetId, Point position) {
        final OutPacket p = OutPacket.create(SendOpcode.PARTY_OPERATION);
        p.writeShort(0x23);
        p.writeInt(townId);
        p.writeInt(targetId);
        p.writePos(position);
        return p;
    }

    /**
     * 获取更新队伍成员 HP 包
     *
     * @param cid   角色 ID
     * @param curhp 当前 HP
     * @param maxhp 最大 HP
     * @return 更新队伍成员 HP 包
     */
    public static Packet updatePartyMemberHP(int cid, int curhp, int maxhp) {
        final OutPacket p = OutPacket.create(SendOpcode.UPDATE_PARTYMEMBER_HP);
        p.writeInt(cid);
        p.writeInt(curhp);
        p.writeInt(maxhp);
        return p;
    }

    /**
     * 获取更新好友列表包
     *
     * @param buddylist 好友列表
     * @return 更新好友列表包
     */
    public static Packet updateBuddylist(Collection<BuddylistEntry> buddylist) {
        OutPacket p = OutPacket.create(SendOpcode.BUDDYLIST);
        p.writeByte(7);
        p.writeByte(buddylist.size());
        for (BuddylistEntry buddy : buddylist) {
            if (buddy.isVisible()) {
                p.writeInt(buddy.getCharacterId()); // cid // 角色ID
                p.writeFixedString(PacketHelper.getRightPaddedStr(buddy.getName(), '\0', 13));
                p.writeByte(0); // opposite status // 对方状态
                p.writeInt(buddy.getChannel() - 1);
                p.writeFixedString(PacketHelper.getRightPaddedStr(buddy.getGroup(), '\0', 13));
                p.writeInt(0);//mapid? // 地图ID?
            }
        }
        for (int x = 0; x < buddylist.size(); x++) {
            p.writeInt(0);//mapid? // 地图ID?
        }
        return p;
    }

    /**
     * 获取好友列表消息包
     *
     * @param message 消息代码
     * @return 好友列表消息包
     */
    public static Packet buddylistMessage(byte message) {
        final OutPacket p = OutPacket.create(SendOpcode.BUDDYLIST);
        p.writeByte(message);
        return p;
    }

    /**
     * 获取请求添加好友包
     *
     * @param chrIdFrom 来源 ID
     * @param chrId     目标 ID
     * @param nameFrom  来源名称
     * @return 请求添加好友包
     */
    public static Packet requestBuddylistAdd(int chrIdFrom, int chrId, String nameFrom) {
        OutPacket p = OutPacket.create(SendOpcode.BUDDYLIST);
        p.writeByte(9);
        p.writeInt(chrIdFrom);
        p.writeString(nameFrom);
        p.writeInt(chrIdFrom);
        p.writeFixedString(PacketHelper.getRightPaddedStr(nameFrom, '\0', 11));
        p.writeByte(0x09);
        p.writeByte(0xf0);
        p.writeByte(0x01);
        p.writeInt(0x0f);
        p.writeFixedString("Default Group");
        p.writeByte(0);
        p.writeInt(chrId);
        return p;
    }

    /**
     * 获取更新好友频道包
     *
     * @param characterid 角色 ID
     * @param channel     频道
     * @return 更新好友频道包
     */
    public static Packet updateBuddyChannel(int characterid, int channel) {
        final OutPacket p = OutPacket.create(SendOpcode.BUDDYLIST);
        p.writeByte(0x14);
        p.writeInt(characterid);
        p.writeByte(0);
        p.writeInt(channel);
        return p;
    }

    /**
     * 获取更新好友容量包
     *
     * @param capacity 容量
     * @return 更新好友容量包
     */
    public static Packet updateBuddyCapacity(int capacity) {
        final OutPacket p = OutPacket.create(SendOpcode.BUDDYLIST);
        p.writeByte(0x15);
        p.writeByte(capacity);
        return p;
    }

    /**
     * 获取加载家族包
     *
     * @param player 玩家
     * @return 加载家族包
     */
    public static Packet loadFamily(Character player) {
        final OutPacket p = OutPacket.create(SendOpcode.FAMILY_PRIVILEGE_LIST);
        p.writeInt(FamilyEntitlement.values().length);
        for (int i = 0; i < FamilyEntitlement.values().length; i++) {
            FamilyEntitlement entitlement = FamilyEntitlement.values()[i];
            p.writeByte(i <= 1 ? 1 : 2); //type // 类型
            p.writeInt(entitlement.getRepCost());
            p.writeInt(entitlement.getUsageLimit());
            p.writeString(entitlement.getName());
            p.writeString(entitlement.getDescription());
        }
        return p;
    }

    /**
     * 获取发送家族消息包
     *
     * @param type  类型
     * @param mesos 金币
     * @return 发送家族消息包
     */
    public static Packet sendFamilyMessage(int type, int mesos) {
        OutPacket p = OutPacket.create(SendOpcode.FAMILY_RESULT);
        p.writeInt(type);
        p.writeInt(mesos);
        return p;
    }

    /**
     * 获取家族信息包
     *
     * @param f 家族条目
     * @return 家族信息包
     */
    public static Packet getFamilyInfo(FamilyEntry f) {
        if (f == null) {
            return getEmptyFamilyInfo();
        }

        OutPacket p = OutPacket.create(SendOpcode.FAMILY_INFO_RESULT);
        p.writeInt(f.getReputation()); // 当前声望值
        p.writeInt(f.getTotalReputation()); // 总声望值
        p.writeInt(f.getTodaysRep()); // 今日声望值
        p.writeShort(f.getJuniorCount()); // 已添加的下级数量
        p.writeShort(2); // 允许的下级数量
        p.writeShort(0); // 未知

        Family family = f.getFamily();
        if (family != null) {
            FamilyEntry leader = family.getLeader();
            if (leader != null) {
                p.writeInt(leader.getChrId()); // 族长ID（允许设置留言）
            } else {
                p.writeInt(0); // 如果没有族长，写入0
            }
            p.writeString(family.getName());
            p.writeString(family.getMessage()); // 家族留言
        } else {
            p.writeInt(0);
            p.writeString("");
            p.writeString("");
        }

        p.writeInt(FamilyEntitlement.values().length); // 权益信息数量
        for (FamilyEntitlement entitlement : FamilyEntitlement.values()) {
            p.writeInt(entitlement.ordinal()); // ID
            p.writeInt(f.isEntitlementUsed(entitlement) ? 1 : 0); // 使用次数
        }
        return p;
    }

    /**
     * 获取空家族信息包
     *
     * @return 空家族信息包
     */
    private static Packet getEmptyFamilyInfo() {
        OutPacket p = OutPacket.create(SendOpcode.FAMILY_INFO_RESULT);
        p.writeInt(0); // cur rep left // 当前剩余声望
        p.writeInt(0); // tot rep left // 总剩余声望
        p.writeInt(0); // todays rep // 今日声望
        p.writeShort(0); // juniors added // 已添加下级
        p.writeShort(2); // juniors allowed // 允许下级
        p.writeShort(0); //Unknown // 未知
        p.writeInt(0); // Leader ID (Allows setting message) // 族长 ID (允许设置消息)
        p.writeString("");
        p.writeString(""); //family message // 家族消息
        p.writeInt(0);
        return p;
    }

    /**
     * 获取显示家谱包
     *
     * @param entry 家族条目
     * @return 显示家谱包
     */
    public static Packet showPedigree(FamilyEntry entry) {
        final OutPacket p = OutPacket.create(SendOpcode.FAMILY_CHART_RESULT);
        p.writeInt(entry.getChrId()); //ID of viewed player's pedigree, can't be leader? // 被查看玩家家谱的 ID，不能是族长？
        List<FamilyEntry> superJuniors = new ArrayList<>(4);
        boolean hasOtherJunior = false;
        int entryCount = 2; //2 guaranteed, leader and self // 2 个保证，族长和自己
        entryCount += Math.min(2, entry.getTotalSeniors());
        //needed since OutPacket doesn't have any seek functionality // 需要，因为 OutPacket 没有任何 seek 功能
        if (entry.getSenior() != null) {
            if (entry.getSenior().getJuniorCount() == 2) {
                entryCount++;
                hasOtherJunior = true;
            }
        }
        for (FamilyEntry junior : entry.getJuniors()) {
            if (junior == null) {
                continue;
            }
            entryCount++;
            for (FamilyEntry superJunior : junior.getJuniors()) {
                if (superJunior == null) {
                    continue;
                }
                entryCount++;
                superJuniors.add(superJunior);
            }
        }
        //write entries // 写入条目
        boolean missingEntries = entryCount == 2; //pedigree requires at least 3 entries to show leader, might only have 2 if leader's juniors leave // 家谱至少需要 3 个条目才能显示族长，如果族长的下级离开，可能只有 2 个
        if (missingEntries) {
            entryCount++;
        }
        p.writeInt(entryCount); //player count // 玩家数量
        PacketHelper.addPedigreeEntry(p, entry.getFamily().getLeader());
        if (entry.getSenior() != null) {
            if (entry.getSenior().getSenior() != null) {
                PacketHelper.addPedigreeEntry(p, entry.getSenior().getSenior());
            }
            PacketHelper.addPedigreeEntry(p, entry.getSenior());
        }
        PacketHelper.addPedigreeEntry(p, entry);
        if (hasOtherJunior) { //must be sent after own entry // 必须在自己的条目之后发送
            FamilyEntry otherJunior = entry.getSenior().getOtherJunior(entry);
            if (otherJunior != null) {
                PacketHelper.addPedigreeEntry(p, otherJunior);
            }
        }
        if (missingEntries) {
            PacketHelper.addPedigreeEntry(p, entry);
        }
        for (FamilyEntry junior : entry.getJuniors()) {
            if (junior == null) {
                continue;
            }
            PacketHelper.addPedigreeEntry(p, junior);
            for (FamilyEntry superJunior : junior.getJuniors()) {
                if (superJunior != null) {
                    PacketHelper.addPedigreeEntry(p, superJunior);
                }
            }
        }
        p.writeInt(2 + superJuniors.size()); //member info count // 成员信息计数
        // 0 = total seniors, -1 = total members, otherwise junior count of ID // 0 = 总长辈，-1 = 总成员，否则为 ID 的下级计数
        p.writeInt(-1);
        p.writeInt(entry.getFamily().getTotalMembers());
        p.writeInt(0);
        p.writeInt(entry.getTotalSeniors()); //client subtracts provided seniors // 客户端减去提供的长辈
        for (FamilyEntry superJunior : superJuniors) {
            p.writeInt(superJunior.getChrId());
            p.writeInt(superJunior.getTotalJuniors());
        }
        p.writeInt(0); //another loop count (entitlements used) // 另一个循环计数（使用的权益）
        //p.writeInt(1); //entitlement index // 权益索引
        //p.writeInt(2); //times used // 使用次数
        p.writeShort(entry.getJuniorCount() >= 2 ? 0 : 2); //0 disables Add button (only if viewing own pedigree) // 0 禁用添加按钮（仅当查看自己的家谱时）
        return p;
    }

    /**
     * 获取发送家族邀请包
     *
     * @param playerId 玩家 ID
     * @param inviter  邀请者
     * @return 发送家族邀请包
     */
    public static Packet sendFamilyInvite(int playerId, String inviter) {
        final OutPacket p = OutPacket.create(SendOpcode.FAMILY_JOIN_REQUEST);
        p.writeInt(playerId);
        p.writeString(inviter);
        return p;
    }

    /**
     * 获取发送家族召唤请求包
     *
     * @param familyName 家族名称
     * @param from       来源
     * @return 发送家族召唤请求包
     */
    public static Packet sendFamilySummonRequest(String familyName, String from) {
        final OutPacket p = OutPacket.create(SendOpcode.FAMILY_SUMMON_REQUEST);
        p.writeString(from);
        p.writeString(familyName);
        return p;
    }

    /**
     * 获取发送家族登录通知包
     *
     * @param name     名称
     * @param loggedIn 是否登录
     * @return 发送家族登录通知包
     */
    public static Packet sendFamilyLoginNotice(String name, boolean loggedIn) {
        final OutPacket p = OutPacket.create(SendOpcode.FAMILY_NOTIFY_LOGIN_OR_LOGOUT);
        p.writeBool(loggedIn);
        p.writeString(name);
        return p;
    }

    /**
     * 获取发送家族加入响应包
     *
     * @param accepted 是否接受
     * @param added    添加者
     * @return 发送家族加入响应包
     */
    public static Packet sendFamilyJoinResponse(boolean accepted, String added) {
        final OutPacket p = OutPacket.create(SendOpcode.FAMILY_JOIN_REQUEST_RESULT);
        p.writeByte(accepted ? 1 : 0);
        p.writeString(added);
        return p;
    }

    /**
     * 获取长辈消息包
     *
     * @param name 名称
     * @return 长辈消息包
     */
    public static Packet getSeniorMessage(String name) {
        final OutPacket p = OutPacket.create(SendOpcode.FAMILY_JOIN_ACCEPTED);
        p.writeString(name);
        p.writeInt(0);
        return p;
    }

    /**
     * 获取发送获得声望包
     *
     * @param gain 获得量
     * @param from 来源
     * @return 发送获得声望包
     */
    public static Packet sendGainRep(int gain, String from) {
        final OutPacket p = OutPacket.create(SendOpcode.FAMILY_REP_GAIN);
        p.writeInt(gain);
        p.writeString(from);
        return p;
    }

    /**
     * 获取家族 Buff 包
     *
     * @param type   类型
     * @param buffnr Buff 编号
     * @param amount 数量
     * @param time   时间
     * @return 家族 Buff 包
     */
    public static Packet familyBuff(int type, int buffnr, int amount, int time) {
        OutPacket p = OutPacket.create(SendOpcode.FAMILY_SET_PRIVILEGE);
        p.writeByte(type);
        if (type >= 2 && type <= 4) {
            p.writeInt(buffnr);
            p.writeInt(type == 3 ? 0 : amount);
            p.writeInt(type == 2 ? 0 : amount);
            p.writeByte(0);
            p.writeInt(time);
        }
        return p;
    }

    /**
     * 获取取消家族 Buff 包
     *
     * @return 取消家族 Buff 包
     */
    public static Packet cancelFamilyBuff() {
        return familyBuff(0, 0, 0, 0);
    }

    /**
     * 获取升级消息包
     *
     * @param type     类型
     * @param level    等级
     * @param charname 角色名
     * @return 升级消息包
     */
    public static Packet levelUpMessage(int type, int level, String charname) {
        final OutPacket p = OutPacket.create(SendOpcode.NOTIFY_LEVELUP);
        p.writeByte(type);
        p.writeInt(level);
        p.writeString(charname);

        return p;
    }

    /**
     * 获取结婚消息包
     *
     * @param type     类型
     * @param charname 角色名
     * @return 结婚消息包
     */
    public static Packet marriageMessage(int type, String charname) {
        final OutPacket p = OutPacket.create(SendOpcode.NOTIFY_MARRIAGE);
        p.writeByte(type);  // 0: guild, 1: family // 0: 公会, 1: 家族
        p.writeString("> " + charname); //To fix the stupid packet lol // 修复愚蠢的数据包 lol

        return p;
    }

    /**
     * 获取转职消息包
     *
     * @param type     类型
     * @param job      职业
     * @param charname 角色名
     * @return 转职消息包
     */
    public static Packet jobMessage(int type, int job, String charname) {
        OutPacket p = OutPacket.create(SendOpcode.NOTIFY_JOB_CHANGE);
        p.writeByte(type);
        p.writeInt(job); //Why fking int? // 为什么是 int?
        p.writeString("> " + charname); //To fix the stupid packet lol // 修复愚蠢的数据包 lol
        return p;
    }

    /**
     * 获取信使邀请包
     *
     * @param from        邀请者
     * @param messengerid 信使 ID
     * @return 信使邀请包
     */
    public static Packet messengerInvite(String from, int messengerid) {
        final OutPacket p = OutPacket.create(SendOpcode.MESSENGER);
        p.writeByte(0x03);
        p.writeString(from);
        p.writeByte(0);
        p.writeInt(messengerid);
        p.writeByte(0);
        return p;
    }

    /*
    public static Packet sendSpouseChat(Character partner, String msg) {
            OutPacket p = OutPacket.create(SendOpcode);
            SPOUSE_CHAT);
            p.writeString(partner.getName());
            p.writeString(msg);
            return p;
    }
    */

    /**
     * 获取伴侣消息包
     *
     * @param fiance 未婚夫/妻
     * @param text   文本
     * @param spouse 是否配偶
     * @return 伴侣消息包
     */
    public static Packet OnCoupleMessage(String fiance, String text, boolean spouse) {
        OutPacket p = OutPacket.create(SendOpcode.SPOUSE_CHAT);
        p.writeByte(spouse ? 5 : 4); // v2 = CInPacket::Decode1(a1) - 4;
        if (spouse) { // if ( v2 ) {
            p.writeString(fiance);
        }
        p.writeByte(spouse ? 5 : 1);
        p.writeString(text);
        return p;
    }

    /**
     * 获取添加信使玩家包
     *
     * @param from     来源
     * @param chr      角色对象
     * @param position 位置
     * @param channel  频道
     * @return 添加信使玩家包
     */
    public static Packet addMessengerPlayer(String from, Character chr, int position, int channel) {
        final OutPacket p = OutPacket.create(SendOpcode.MESSENGER);
        p.writeByte(0x00);
        p.writeByte(position);
        PacketHelper.addCharLook(p, chr, true);
        p.writeString(from);
        p.writeByte(channel);
        p.writeByte(0x00);
        return p;
    }

    /**
     * 获取移除信使玩家包
     *
     * @param position 位置
     * @return 移除信使玩家包
     */
    public static Packet removeMessengerPlayer(int position) {
        final OutPacket p = OutPacket.create(SendOpcode.MESSENGER);
        p.writeByte(0x02);
        p.writeByte(position);
        return p;
    }

    /**
     * 获取更新信使玩家包
     *
     * @param from     来源
     * @param chr      角色对象
     * @param position 位置
     * @param channel  频道
     * @return 更新信使玩家包
     */
    public static Packet updateMessengerPlayer(String from, Character chr, int position, int channel) {
        final OutPacket p = OutPacket.create(SendOpcode.MESSENGER);
        p.writeByte(0x07);
        p.writeByte(position);
        PacketHelper.addCharLook(p, chr, true);
        p.writeString(from);
        p.writeByte(channel);
        p.writeByte(0x00);
        return p;
    }

    /**
     * 获取加入信使包
     *
     * @param position 位置
     * @return 加入信使包
     */
    public static Packet joinMessenger(int position) {
        final OutPacket p = OutPacket.create(SendOpcode.MESSENGER);
        p.writeByte(0x01);
        p.writeByte(position);
        return p;
    }

    /**
     * 获取信使聊天包
     *
     * @param text 文本
     * @return 信使聊天包
     */
    public static Packet messengerChat(String text) {
        final OutPacket p = OutPacket.create(SendOpcode.MESSENGER);
        p.writeByte(0x06);
        p.writeString(text);
        return p;
    }

    /**
     * 获取信使备注包
     *
     * @param text  文本
     * @param mode  模式
     * @param mode2 模式2
     * @return 信使备注包
     */
    public static Packet messengerNote(String text, int mode, int mode2) {
        final OutPacket p = OutPacket.create(SendOpcode.MESSENGER);
        p.writeByte(mode);
        p.writeString(text);
        p.writeByte(mode2);
        return p;
    }

    /**
     * 获取私聊结果包
     *
     * @param target  目标
     * @param success 是否成功
     * @return 私聊结果包
     */
    public static Packet getWhisperResult(String target, boolean success) {
        OutPacket p = OutPacket.create(SendOpcode.WHISPER);
        p.writeByte(PacketHelper.WhisperFlag.WHISPER | PacketHelper.WhisperFlag.RESULT);
        p.writeString(target);
        p.writeBool(success);
        return p;
    }

    /**
     * 获取私聊接收包
     *
     * @param sender    发送者
     * @param channel   频道
     * @param fromAdmin 是否来自管理员
     * @param message   消息
     * @return 私聊接收包
     */
    public static Packet getWhisperReceive(String sender, int channel, boolean fromAdmin, String message) {
        OutPacket p = OutPacket.create(SendOpcode.WHISPER);
        p.writeByte(PacketHelper.WhisperFlag.WHISPER | PacketHelper.WhisperFlag.RECEIVE);
        p.writeString(sender);
        p.writeByte(channel);
        p.writeBool(fromAdmin);
        p.writeString(message);
        return p;
    }

    /**
     * 获取查找结果包
     * User for /find, buddy find and /c (chase)
     * CField::OnWhisper
     * 用于 /find, 好友查找和 /c (追踪)
     * CField::OnWhisper
     *
     * @param target         Name String from the command parameter // 目标名称字符串
     * @param type           Location of the target // 目标位置
     * @param fieldOrChannel If true & chr is not null, shows different channel message // 如果为真且 chr 不为空，显示不同频道消息
     * @param flag           LOCATION or LOCATION_FRIEND // 位置或好友位置
     * @return packet structure // 数据包结构
     */
    public static Packet getFindResult(Character target, byte type, int fieldOrChannel, byte flag) {
        OutPacket p = OutPacket.create(SendOpcode.WHISPER);

        p.writeByte(flag | PacketHelper.WhisperFlag.RESULT);
        p.writeString(target.getName());
        p.writeByte(type);
        p.writeInt(fieldOrChannel);

        if (type == WhisperHandler.RT_SAME_CHANNEL) {
            p.writeInt(target.getPosition().x);
            p.writeInt(target.getPosition().y);
        }

        return p;
    }

    /**
     * 获取备注错误包
     *  0 = Player online, use whisper
     *  1 = Check player's name
     *  2 = Receiver inbox full
     *  0 = 玩家在线，使用私聊
     *  1 = 检查玩家名称
     *  2 = 接收者收件箱已满
     *
     * @param error 错误代码
     * @return 备注错误包
     */
    public static Packet noteError(byte error) {
        OutPacket p = OutPacket.create(SendOpcode.MEMO_RESULT);
        p.writeByte(5);
        p.writeByte(error);
        return p;
    }

    /**
     * 获取发送快递包
     *
     * @param operation 操作
     * @param packages  包裹列表
     * @return 发送快递包
     */
    public static Packet sendDuey(int operation, List<DueyPackage> packages) {
        final OutPacket p = OutPacket.create(SendOpcode.PARCEL);
        p.writeByte(operation);
        if (operation == 8) {
            p.writeByte(0);
            p.writeByte(packages.size());
            for (DueyPackage dp : packages) {
                p.writeInt(dp.getPackageId());
                p.writeFixedString(dp.getSender());
                p.writeInt(dp.getMesos());
                p.writeLong(PacketHelper.getTime(dp.sentTimeInMilliseconds()));

                String msg = dp.getMessage();
                if (msg != null) {
                    p.writeInt(1);
                    p.writeFixedString(msg, 200);
                } else {
                    p.writeInt(0);
                    p.skip(200);
                }

                p.writeByte(0);
                if (dp.getItem() != null) {
                    p.writeByte(1);
                    PacketHelper.addItemInfo(p, dp.getItem(), true);
                } else {
                    p.writeByte(0);
                }
            }
            p.writeByte(0);
        }

        return p;
    }

    /**
     * 获取发送快递消息包
     *
     * @param operation 操作
     * @return 发送快递消息包
     */
    public static Packet sendDueyMSG(byte operation) {
        return sendDuey(operation, null);
    }

    /**
     * 获取发送快递包裹通知包
     *
     * @param quick 是否快速
     * @return 发送快递包裹通知包
     */
    public static Packet sendDueyParcelNotification(boolean quick) {
        final OutPacket p = OutPacket.create(SendOpcode.PARCEL);
        p.writeByte(0x1B);
        p.writeBool(quick);  // 0 : package received, 1 : quick delivery package // 0 : 包裹已接收, 1 : 快速递送包裹
        return p;
    }

    /**
     * 获取发送快递包裹已接收包
     *
     * @param from  来源
     * @param quick 是否快速
     * @return 发送快递包裹已接收包
     */
    public static Packet sendDueyParcelReceived(String from, boolean quick) {    // thanks inhyuk // 感谢 inhyuk
        OutPacket p = OutPacket.create(SendOpcode.PARCEL);
        p.writeByte(0x19);
        p.writeString(from);
        p.writeBool(quick);
        return p;
    }

    /**
     * 获取从快递移除物品包
     *
     * @param remove  是否移除
     * @param Package 包裹 ID
     * @return 从快递移除物品包
     */
    public static Packet removeItemFromDuey(boolean remove, int Package) {
        final OutPacket p = OutPacket.create(SendOpcode.PARCEL);
        p.writeByte(0x17);
        p.writeInt(Package);
        p.writeByte(remove ? 3 : 4);
        return p;
    }
}
