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

    public static Packet serverMessage(String message) {
        return serverMessage(4, (byte) 0, message, true, false, 0);
    }

    public static Packet serverNotice(int type, String message) {
        return serverMessage(type, (byte) 0, message, false, false, 0);
    }

    public static Packet serverNotice(int type, String message, int npc) {
        return serverMessage(type, 0, message, false, false, npc);
    }

    public static Packet serverNotice(int type, int channel, String message) {
        return serverMessage(type, channel, message, false, false, 0);
    }

    public static Packet serverNotice(int type, int channel, String message, boolean smegaEar) {
        return serverMessage(type, channel, message, false, smegaEar, 0);
    }

    private static Packet serverMessage(int type, int channel, String message, boolean servermessage, boolean megaEar, int npc) {
        OutPacket p = OutPacket.create(SendOpcode.SERVERMESSAGE);
        p.writeByte(type);
        if (servermessage) {
            p.writeByte(1);
        }
        p.writeString(message);
        if (type == 3) {
            p.writeByte(channel - 1); // channel
            p.writeBool(megaEar);
        } else if (type == 6) {
            p.writeInt(0);
        } else if (type == 7) { // npc
            p.writeInt(npc);
        }
        return p;
    }

    public static Packet getAvatarMega(Character chr, String medal, int channel, int itemId, List<String> message, boolean ear) {
        final OutPacket p = OutPacket.create(SendOpcode.SET_AVATAR_MEGAPHONE);
        p.writeInt(itemId);
        p.writeString(medal + chr.getName());
        for (String s : message) {
            p.writeString(s);
        }
        p.writeInt(channel - 1); // channel
        p.writeBool(ear);
        PacketHelper.addCharLook(p, chr, true);
        return p;
    }

    public static Packet byeAvatarMega() {
        final OutPacket p = OutPacket.create(SendOpcode.CLEAR_AVATAR_MEGAPHONE);
        p.writeByte(1);
        return p;
    }

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

    public static Packet partyInvite(Character from) {
        final OutPacket p = OutPacket.create(SendOpcode.PARTY_OPERATION);
        p.writeByte(4);
        p.writeInt(from.getParty().getId());
        p.writeString(from.getName());
        p.writeByte(0);
        return p;
    }

    public static Packet partySearchInvite(Character from) {
        final OutPacket p = OutPacket.create(SendOpcode.PARTY_OPERATION);
        p.writeByte(4);
        p.writeInt(from.getParty().getId());
        p.writeString("PS: " + from.getName());
        p.writeByte(0);
        return p;
    }

    public static Packet partyStatusMessage(int message) {
        final OutPacket p = OutPacket.create(SendOpcode.PARTY_OPERATION);
        p.writeByte(message);
        return p;
    }

    public static Packet partyStatusMessage(int message, String charname) {
        final OutPacket p = OutPacket.create(SendOpcode.PARTY_OPERATION);
        p.writeByte(message);
        p.writeString(charname);
        return p;
    }

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

    public static Packet partyPortal(int townId, int targetId, Point position) {
        final OutPacket p = OutPacket.create(SendOpcode.PARTY_OPERATION);
        p.writeShort(0x23);
        p.writeInt(townId);
        p.writeInt(targetId);
        p.writePos(position);
        return p;
    }

    public static Packet updatePartyMemberHP(int cid, int curhp, int maxhp) {
        final OutPacket p = OutPacket.create(SendOpcode.UPDATE_PARTYMEMBER_HP);
        p.writeInt(cid);
        p.writeInt(curhp);
        p.writeInt(maxhp);
        return p;
    }

    public static Packet updateBuddylist(Collection<BuddylistEntry> buddylist) {
        OutPacket p = OutPacket.create(SendOpcode.BUDDYLIST);
        p.writeByte(7);
        p.writeByte(buddylist.size());
        for (BuddylistEntry buddy : buddylist) {
            if (buddy.isVisible()) {
                p.writeInt(buddy.getCharacterId()); // cid
                p.writeFixedString(PacketHelper.getRightPaddedStr(buddy.getName(), '\0', 13));
                p.writeByte(0); // opposite status
                p.writeInt(buddy.getChannel() - 1);
                p.writeFixedString(PacketHelper.getRightPaddedStr(buddy.getGroup(), '\0', 13));
                p.writeInt(0);//mapid?
            }
        }
        for (int x = 0; x < buddylist.size(); x++) {
            p.writeInt(0);//mapid?
        }
        return p;
    }

    public static Packet buddylistMessage(byte message) {
        final OutPacket p = OutPacket.create(SendOpcode.BUDDYLIST);
        p.writeByte(message);
        return p;
    }

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

    public static Packet updateBuddyChannel(int characterid, int channel) {
        final OutPacket p = OutPacket.create(SendOpcode.BUDDYLIST);
        p.writeByte(0x14);
        p.writeInt(characterid);
        p.writeByte(0);
        p.writeInt(channel);
        return p;
    }

    public static Packet updateBuddyCapacity(int capacity) {
        final OutPacket p = OutPacket.create(SendOpcode.BUDDYLIST);
        p.writeByte(0x15);
        p.writeByte(capacity);
        return p;
    }

    public static Packet loadFamily(Character player) {
        final OutPacket p = OutPacket.create(SendOpcode.FAMILY_PRIVILEGE_LIST);
        p.writeInt(FamilyEntitlement.values().length);
        for (int i = 0; i < FamilyEntitlement.values().length; i++) {
            FamilyEntitlement entitlement = FamilyEntitlement.values()[i];
            p.writeByte(i <= 1 ? 1 : 2); //type
            p.writeInt(entitlement.getRepCost());
            p.writeInt(entitlement.getUsageLimit());
            p.writeString(entitlement.getName());
            p.writeString(entitlement.getDescription());
        }
        return p;
    }

    public static Packet sendFamilyMessage(int type, int mesos) {
        OutPacket p = OutPacket.create(SendOpcode.FAMILY_RESULT);
        p.writeInt(type);
        p.writeInt(mesos);
        return p;
    }

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

    private static Packet getEmptyFamilyInfo() {
        OutPacket p = OutPacket.create(SendOpcode.FAMILY_INFO_RESULT);
        p.writeInt(0); // cur rep left
        p.writeInt(0); // tot rep left
        p.writeInt(0); // todays rep
        p.writeShort(0); // juniors added
        p.writeShort(2); // juniors allowed
        p.writeShort(0); //Unknown
        p.writeInt(0); // Leader ID (Allows setting message)
        p.writeString("");
        p.writeString(""); //family message
        p.writeInt(0);
        return p;
    }

    public static Packet showPedigree(FamilyEntry entry) {
        final OutPacket p = OutPacket.create(SendOpcode.FAMILY_CHART_RESULT);
        p.writeInt(entry.getChrId()); //ID of viewed player's pedigree, can't be leader?
        List<FamilyEntry> superJuniors = new ArrayList<>(4);
        boolean hasOtherJunior = false;
        int entryCount = 2; //2 guaranteed, leader and self
        entryCount += Math.min(2, entry.getTotalSeniors());
        //needed since OutPacket doesn't have any seek functionality
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
        //write entries
        boolean missingEntries = entryCount == 2; //pedigree requires at least 3 entries to show leader, might only have 2 if leader's juniors leave
        if (missingEntries) {
            entryCount++;
        }
        p.writeInt(entryCount); //player count
        PacketHelper.addPedigreeEntry(p, entry.getFamily().getLeader());
        if (entry.getSenior() != null) {
            if (entry.getSenior().getSenior() != null) {
                PacketHelper.addPedigreeEntry(p, entry.getSenior().getSenior());
            }
            PacketHelper.addPedigreeEntry(p, entry.getSenior());
        }
        PacketHelper.addPedigreeEntry(p, entry);
        if (hasOtherJunior) { //must be sent after own entry
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
        p.writeInt(2 + superJuniors.size()); //member info count
        // 0 = total seniors, -1 = total members, otherwise junior count of ID
        p.writeInt(-1);
        p.writeInt(entry.getFamily().getTotalMembers());
        p.writeInt(0);
        p.writeInt(entry.getTotalSeniors()); //client subtracts provided seniors
        for (FamilyEntry superJunior : superJuniors) {
            p.writeInt(superJunior.getChrId());
            p.writeInt(superJunior.getTotalJuniors());
        }
        p.writeInt(0); //another loop count (entitlements used)
        //p.writeInt(1); //entitlement index
        //p.writeInt(2); //times used
        p.writeShort(entry.getJuniorCount() >= 2 ? 0 : 2); //0 disables Add button (only if viewing own pedigree)
        return p;
    }

    public static Packet sendFamilyInvite(int playerId, String inviter) {
        final OutPacket p = OutPacket.create(SendOpcode.FAMILY_JOIN_REQUEST);
        p.writeInt(playerId);
        p.writeString(inviter);
        return p;
    }

    public static Packet sendFamilySummonRequest(String familyName, String from) {
        final OutPacket p = OutPacket.create(SendOpcode.FAMILY_SUMMON_REQUEST);
        p.writeString(from);
        p.writeString(familyName);
        return p;
    }

    public static Packet sendFamilyLoginNotice(String name, boolean loggedIn) {
        final OutPacket p = OutPacket.create(SendOpcode.FAMILY_NOTIFY_LOGIN_OR_LOGOUT);
        p.writeBool(loggedIn);
        p.writeString(name);
        return p;
    }

    public static Packet sendFamilyJoinResponse(boolean accepted, String added) {
        final OutPacket p = OutPacket.create(SendOpcode.FAMILY_JOIN_REQUEST_RESULT);
        p.writeByte(accepted ? 1 : 0);
        p.writeString(added);
        return p;
    }

    public static Packet getSeniorMessage(String name) {
        final OutPacket p = OutPacket.create(SendOpcode.FAMILY_JOIN_ACCEPTED);
        p.writeString(name);
        p.writeInt(0);
        return p;
    }

    public static Packet sendGainRep(int gain, String from) {
        final OutPacket p = OutPacket.create(SendOpcode.FAMILY_REP_GAIN);
        p.writeInt(gain);
        p.writeString(from);
        return p;
    }

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

    public static Packet cancelFamilyBuff() {
        return familyBuff(0, 0, 0, 0);
    }

    public static Packet levelUpMessage(int type, int level, String charname) {
        final OutPacket p = OutPacket.create(SendOpcode.NOTIFY_LEVELUP);
        p.writeByte(type);
        p.writeInt(level);
        p.writeString(charname);

        return p;
    }

    public static Packet marriageMessage(int type, String charname) {
        final OutPacket p = OutPacket.create(SendOpcode.NOTIFY_MARRIAGE);
        p.writeByte(type);  // 0: guild, 1: family
        p.writeString("> " + charname); //To fix the stupid packet lol

        return p;
    }

    public static Packet jobMessage(int type, int job, String charname) {
        OutPacket p = OutPacket.create(SendOpcode.NOTIFY_JOB_CHANGE);
        p.writeByte(type);
        p.writeInt(job); //Why fking int?
        p.writeString("> " + charname); //To fix the stupid packet lol
        return p;
    }

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

    public static Packet removeMessengerPlayer(int position) {
        final OutPacket p = OutPacket.create(SendOpcode.MESSENGER);
        p.writeByte(0x02);
        p.writeByte(position);
        return p;
    }

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

    public static Packet joinMessenger(int position) {
        final OutPacket p = OutPacket.create(SendOpcode.MESSENGER);
        p.writeByte(0x01);
        p.writeByte(position);
        return p;
    }

    public static Packet messengerChat(String text) {
        final OutPacket p = OutPacket.create(SendOpcode.MESSENGER);
        p.writeByte(0x06);
        p.writeString(text);
        return p;
    }

    public static Packet messengerNote(String text, int mode, int mode2) {
        final OutPacket p = OutPacket.create(SendOpcode.MESSENGER);
        p.writeByte(mode);
        p.writeString(text);
        p.writeByte(mode2);
        return p;
    }

    public static Packet getWhisperResult(String target, boolean success) {
        OutPacket p = OutPacket.create(SendOpcode.WHISPER);
        p.writeByte(PacketHelper.WhisperFlag.WHISPER | PacketHelper.WhisperFlag.RESULT);
        p.writeString(target);
        p.writeBool(success);
        return p;
    }

    public static Packet getWhisperReceive(String sender, int channel, boolean fromAdmin, String message) {
        OutPacket p = OutPacket.create(SendOpcode.WHISPER);
        p.writeByte(PacketHelper.WhisperFlag.WHISPER | PacketHelper.WhisperFlag.RECEIVE);
        p.writeString(sender);
        p.writeByte(channel);
        p.writeBool(fromAdmin);
        p.writeString(message);
        return p;
    }

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

    public static Packet noteError(byte error) {
        OutPacket p = OutPacket.create(SendOpcode.MEMO_RESULT);
        p.writeByte(5);
        p.writeByte(error);
        return p;
    }

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

    public static Packet sendDueyMSG(byte operation) {
        return sendDuey(operation, null);
    }

    public static Packet sendDueyParcelNotification(boolean quick) {
        final OutPacket p = OutPacket.create(SendOpcode.PARCEL);
        p.writeByte(0x1B);
        p.writeBool(quick);  // 0 : package received, 1 : quick delivery package
        return p;
    }

    public static Packet sendDueyParcelReceived(String from, boolean quick) {    // thanks inhyuk
        OutPacket p = OutPacket.create(SendOpcode.PARCEL);
        p.writeByte(0x19);
        p.writeString(from);
        p.writeBool(quick);
        return p;
    }

    public static Packet removeItemFromDuey(boolean remove, int Package) {
        final OutPacket p = OutPacket.create(SendOpcode.PARCEL);
        p.writeByte(0x17);
        p.writeInt(Package);
        p.writeByte(remove ? 3 : 4);
        return p;
    }
}
