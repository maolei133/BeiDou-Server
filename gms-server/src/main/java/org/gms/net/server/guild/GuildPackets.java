package org.gms.net.server.guild;

import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.dao.entity.BbsRepliesDO;
import org.gms.dao.entity.BbsThreadsDO;
import org.gms.net.opcodes.SendOpcode;
import org.gms.net.packet.OutPacket;
import org.gms.net.packet.Packet;
import org.gms.net.server.Server;
import org.gms.util.PacketCreator;
import org.gms.util.Pair;
import org.gms.util.StringUtil;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.List;

public class GuildPackets {
    public static Packet showGuildInfo(Character chr) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_OPERATION);
        p.writeByte(0x1A); // 显示家族信息
        if (chr == null) { // 显示空家族（用于离开、被驱逐）
            p.writeByte(0);
            return p;
        }
        Guild g = chr.getClient().getWorldServer().getGuild(chr.getMGC());
        if (g == null) { // 从数据库读取失败 - 不显示家族
            p.writeByte(0);
            return p;
        }
        if (g.getName() == null) {
            p.writeByte(0);
            return p;
        }
        p.writeByte(1); // bInGuild
        p.writeInt(g.getId());
        p.writeString(g.getName());
        for (int i = 1; i <= 5; i++) {
            p.writeString(g.getRankTitle(i));
        }
        Collection<GuildCharacter> members = g.getMembers();
        p.writeByte(members.size()); // 成员数量
        for (GuildCharacter mgc : members) { // 成员的角色ID
            p.writeInt(mgc.getId());
        }
        for (GuildCharacter mgc : members) {
            p.writeFixedString(StringUtil.getRightPaddedStr(mgc.getName(), '\0', 13));
            p.writeInt(mgc.getJobId());
            p.writeInt(mgc.getLevel());
            p.writeInt(mgc.getGuildRank());
            p.writeInt(mgc.isOnline() ? 1 : 0);
            p.writeInt(g.getSignature());
            p.writeInt(mgc.getAllianceRank());
        }
        p.writeInt(g.getCapacity());
        p.writeShort(g.getLogoBG());
        p.writeByte(g.getLogoBGColor());
        p.writeShort(g.getLogo());
        p.writeByte(g.getLogoColor());
        p.writeString(g.getNotice());
        p.writeInt(g.getGP());
        p.writeInt(g.getAllianceId());
        return p;
    }

    public static Packet guildMemberOnline(int guildId, int chrId, boolean bOnline) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_OPERATION);
        p.writeByte(0x3d);
        p.writeInt(guildId);
        p.writeInt(chrId);
        p.writeBool(bOnline);
        return p;
    }

    public static Packet guildInvite(int guildId, String charName) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_OPERATION);
        p.writeByte(0x05);
        p.writeInt(guildId);
        p.writeString(charName);
        return p;
    }

    public static Packet createGuildMessage(String masterName, String guildName) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_OPERATION);
        p.writeByte(0x3);
        p.writeInt(0);
        p.writeString(masterName);
        p.writeString(guildName);
        return p;
    }

    /**
     * 获取一个 Heracle/家族 消息数据包。
     * <p>
     * <code>code</code> 的可能值:<br> 28: 家族名称已存在<br>
     * 31: 协议期间定位玩家时出现问题<br> 33/40: 已加入家族<br>
     * 35: 无法创建家族<br> 36: 玩家协议期间出现问题<br> 38: 组建家族期间出现问题<br>
     * 41: 加入家族的玩家数量已达上限<br> 42: 在此频道找不到角色<br>
     * 45/48: 角色不在家族中<br> 52: 解散家族时出现问题<br> 56: 管理员无法创建家族<br>
     * 57: 增加家族规模时出现问题<br>
     *
     * @param code 响应码。
     * @return 家族消息数据包。
     */
    public static Packet genericGuildMessage(byte code) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_OPERATION);
        p.writeByte(code);
        return p;
    }

    /**
     * 获取一个附加了目标名称的家族消息数据包。
     * <p>
     * 53: 玩家不接受家族邀请<br>
     * 54: 玩家已在处理一个邀请<br> 55: 玩家拒绝了邀请<br>
     *
     * @param code       响应码。
     * @param targetName 邀请的初始目标玩家。
     * @return 家族消息数据包。
     */
    public static Packet responseGuildMessage(byte code, String targetName) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_OPERATION);
        p.writeByte(code);
        p.writeString(targetName);
        return p;
    }

    public static Packet newGuildMember(GuildCharacter mgc) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_OPERATION);
        p.writeByte(0x27);
        p.writeInt(mgc.getGuildId());
        p.writeInt(mgc.getId());
        p.writeFixedString(StringUtil.getRightPaddedStr(mgc.getName(), '\0', 13));
        p.writeInt(mgc.getJobId());
        p.writeInt(mgc.getLevel());
        p.writeInt(mgc.getGuildRank()); // 应该总是5，但无所谓
        p.writeInt(mgc.isOnline() ? 1 : 0); // 也应该总是1
        p.writeInt(1); // ? 可能是家族签名，但似乎不重要
        p.writeInt(3);
        return p;
    }

    // 有人离开, mode == 0x2c 为离开, 0x2f 为被驱逐
    public static Packet memberLeft(GuildCharacter mgc, boolean bExpelled) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_OPERATION);
        p.writeByte(bExpelled ? 0x2f : 0x2c);
        p.writeInt(mgc.getGuildId());
        p.writeInt(mgc.getId());
        p.writeString(mgc.getName());
        return p;
    }

    // 职位变更
    public static Packet changeRank(GuildCharacter mgc) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_OPERATION);
        p.writeByte(0x40);
        p.writeInt(mgc.getGuildId());
        p.writeInt(mgc.getId());
        p.writeByte(mgc.getGuildRank());
        return p;
    }

    public static Packet guildNotice(int guildId, String notice) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_OPERATION);
        p.writeByte(0x44);
        p.writeInt(guildId);
        p.writeString(notice);
        return p;
    }

    public static Packet guildMemberLevelJobUpdate(GuildCharacter mgc) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_OPERATION);
        p.writeByte(0x3C);
        p.writeInt(mgc.getGuildId());
        p.writeInt(mgc.getId());
        p.writeInt(mgc.getLevel());
        p.writeInt(mgc.getJobId());
        return p;
    }

    public static Packet rankTitleChange(int guildId, String[] ranks) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_OPERATION);
        p.writeByte(0x3E);
        p.writeInt(guildId);
        for (int i = 0; i < 5; i++) {
            p.writeString(ranks[i]);
        }
        return p;
    }

    public static Packet guildDisband(int guildId) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_OPERATION);
        p.writeByte(0x32);
        p.writeInt(guildId);
        p.writeByte(1);
        return p;
    }

    public static Packet guildQuestWaitingNotice(byte channel, int waitingPos) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_OPERATION);
        p.writeByte(0x4C);
        p.writeByte(channel - 1);
        p.writeByte(waitingPos);
        return p;
    }

    public static Packet guildEmblemChange(int guildId, short bg, byte bgcolor, short logo, byte logoColor) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_OPERATION);
        p.writeByte(0x42);
        p.writeInt(guildId);
        p.writeShort(bg);
        p.writeByte(bgcolor);
        p.writeShort(logo);
        p.writeByte(logoColor);
        return p;
    }

    public static Packet guildCapacityChange(int guildId, int capacity) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_OPERATION);
        p.writeByte(0x3A);
        p.writeInt(guildId);
        p.writeByte(capacity);
        return p;
    }

    public static void addThread(final OutPacket p, ResultSet rs) throws SQLException {
        p.writeInt(rs.getInt("localthreadid"));
        p.writeInt(rs.getInt("postercid"));
        p.writeString(rs.getString("name"));
        p.writeLong(PacketCreator.getTime(rs.getLong("timestamp")));
        p.writeInt(rs.getInt("icon"));
        p.writeInt(rs.getInt("replycount"));
    }

    public static void addThread(final OutPacket p, BbsThreadsDO thread) {
        p.writeInt(thread.getLocalthreadid().intValue());
        p.writeInt(thread.getPostercid().intValue());
        p.writeString(thread.getName());
        p.writeLong(PacketCreator.getTime(thread.getTimestamp().longValue()));
        p.writeInt(thread.getIcon());
        p.writeInt(thread.getReplycount());
    }

    public static Packet BBSThreadList(ResultSet rs, int start) throws SQLException {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_BBS_PACKET);
        p.writeByte(0x06);
        if (!rs.last()) {
            p.writeByte(0);
            p.writeInt(0);
            p.writeInt(0);
            return p;
        }
        int threadCount = rs.getRow();
        if (rs.getInt("localthreadid") == 0) { // 有公告
            p.writeByte(1);
            addThread(p, rs);
            threadCount--; // 有一个帖子不算（因为是公告）
        } else {
            p.writeByte(0);
        }
        if (!rs.absolute(start + 1)) { // 移动到我们开始位置之前的帖子
            rs.first(); // 呃，我们试图从一个不可能的位置开始
            start = 0;
        }
        p.writeInt(threadCount);
        p.writeInt(Math.min(10, threadCount - start));
        for (int i = 0; i < Math.min(10, threadCount - start); i++) {
            addThread(p, rs);
            rs.next();
        }
        return p;
    }

    public static Packet BBSThreadList(List<BbsThreadsDO> threads, int start) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_BBS_PACKET);
        p.writeByte(0x06);
        if (threads.isEmpty()) {
            p.writeByte(0);
            p.writeInt(0);
            p.writeInt(0);
            return p;
        }
        
        int threadCount = threads.size();
        BbsThreadsDO notice = null;
        
        // 检查公告 (localthreadid == 0)
        for (BbsThreadsDO t : threads) {
            if (t.getLocalthreadid() != null && t.getLocalthreadid() == 0) {
                notice = t;
                break;
            }
        }
        
        if (notice != null) {
            p.writeByte(1);
            addThread(p, notice);
            threadCount--;
        } else {
            p.writeByte(0);
        }
        
        int count = 0;
        int written = 0;
        
        p.writeInt(threadCount);
        
        int toWrite = Math.min(10, threadCount - start);
        p.writeInt(toWrite);
        
        for (BbsThreadsDO t : threads) {
            if (t.getLocalthreadid() != null && t.getLocalthreadid() == 0) continue; // 跳过公告
            
            if (count >= start && written < 10) {
                addThread(p, t);
                written++;
            }
            count++;
        }
        
        return p;
    }

    public static Packet showThread(int localthreadid, ResultSet threadRS, ResultSet repliesRS) throws SQLException, RuntimeException {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_BBS_PACKET);
        p.writeByte(0x07);
        p.writeInt(localthreadid);
        p.writeInt(threadRS.getInt("postercid"));
        p.writeLong(PacketCreator.getTime(threadRS.getLong("timestamp")));
        p.writeString(threadRS.getString("name"));
        p.writeString(threadRS.getString("startpost"));
        p.writeInt(threadRS.getInt("icon"));
        if (repliesRS != null) {
            int replyCount = threadRS.getInt("replycount");
            p.writeInt(replyCount);
            int i;
            for (i = 0; i < replyCount && repliesRS.next(); i++) {
                p.writeInt(repliesRS.getInt("replyid"));
                p.writeInt(repliesRS.getInt("postercid"));
                p.writeLong(PacketCreator.getTime(repliesRS.getLong("timestamp")));
                p.writeString(repliesRS.getString("content"));
            }
            if (i != replyCount || repliesRS.next()) {
                throw new RuntimeException(String.valueOf(threadRS.getInt("threadid")));
            }
        } else {
            p.writeInt(0);
        }
        return p;
    }

    public static Packet showThread(int localthreadid, BbsThreadsDO thread, List<BbsRepliesDO> replies) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_BBS_PACKET);
        p.writeByte(0x07);
        p.writeInt(localthreadid);
        p.writeInt(thread.getPostercid().intValue());
        p.writeLong(PacketCreator.getTime(thread.getTimestamp().longValue()));
        p.writeString(thread.getName());
        p.writeString(thread.getStartpost());
        p.writeInt(thread.getIcon());
        
        if (replies != null) {
            p.writeInt(replies.size());
            for (BbsRepliesDO reply : replies) {
                p.writeInt(reply.getReplyid().intValue());
                p.writeInt(reply.getPostercid().intValue());
                p.writeLong(PacketCreator.getTime(reply.getTimestamp().longValue()));
                p.writeString(reply.getContent());
            }
        } else {
            p.writeInt(0);
        }
        return p;
    }

    public static Packet showGuildRanks(int npcid, ResultSet rs) throws SQLException {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_OPERATION);
        p.writeByte(0x49);
        p.writeInt(npcid);
        if (!rs.last()) { // 没有家族
            p.writeInt(0);
            return p;
        }
        p.writeInt(rs.getRow()); // 条目数
        rs.beforeFirst();
        while (rs.next()) {
            p.writeString(rs.getString("name"));
            p.writeInt(rs.getInt("GP"));
            p.writeInt(rs.getInt("logo"));
            p.writeInt(rs.getInt("logoColor"));
            p.writeInt(rs.getInt("logoBG"));
            p.writeInt(rs.getInt("logoBGColor"));
        }
        return p;
    }

    public static Packet showPlayerRanks(int npcid, List<Pair<String, Integer>> worldRanking) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_OPERATION);
        p.writeByte(0x49);
        p.writeInt(npcid);
        if (worldRanking.isEmpty()) {
            p.writeInt(0);
            return p;
        }
        p.writeInt(worldRanking.size());
        for (Pair<String, Integer> wr : worldRanking) {
            p.writeString(wr.getLeft());
            p.writeInt(wr.getRight());
            p.writeInt(0);
            p.writeInt(0);
            p.writeInt(0);
            p.writeInt(0);
        }
        return p;
    }

    public static Packet updateGP(int guildId, int GP) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_OPERATION);
        p.writeByte(0x48);
        p.writeInt(guildId);
        p.writeInt(GP);
        return p;
    }

    public static void getGuildInfo(OutPacket p, Guild guild) {
        p.writeInt(guild.getId());
        p.writeString(guild.getName());
        for (int i = 1; i <= 5; i++) {
            p.writeString(guild.getRankTitle(i));
        }
        Collection<GuildCharacter> members = guild.getMembers();
        p.writeByte(members.size());
        for (GuildCharacter mgc : members) {
            p.writeInt(mgc.getId());
        }
        for (GuildCharacter mgc : members) {
            p.writeFixedString(StringUtil.getRightPaddedStr(mgc.getName(), '\0', 13));
            p.writeInt(mgc.getJobId());
            p.writeInt(mgc.getLevel());
            p.writeInt(mgc.getGuildRank());
            p.writeInt(mgc.isOnline() ? 1 : 0);
            p.writeInt(guild.getSignature());
            p.writeInt(mgc.getAllianceRank());
        }
        p.writeInt(guild.getCapacity());
        p.writeShort(guild.getLogoBG());
        p.writeByte(guild.getLogoBGColor());
        p.writeShort(guild.getLogo());
        p.writeByte(guild.getLogoColor());
        p.writeString(guild.getNotice());
        p.writeInt(guild.getGP());
        p.writeInt(guild.getAllianceId());
    }

    public static Packet getAllianceInfo(Alliance alliance) {
        OutPacket p = OutPacket.create(SendOpcode.ALLIANCE_OPERATION);
        p.writeByte(0x0C);
        p.writeByte(1);
        p.writeInt(alliance.getId());
        p.writeString(alliance.getName());
        for (int i = 1; i <= 5; i++) {
            p.writeString(alliance.getRankTitle(i));
        }
        p.writeByte(alliance.getGuilds().size());
        p.writeInt(alliance.getCapacity()); // 可能是容量
        for (Integer guild : alliance.getGuilds()) {
            p.writeInt(guild);
        }
        p.writeString(alliance.getNotice());
        return p;
    }

    public static Packet updateAllianceInfo(Alliance alliance, int world) {
        OutPacket p = OutPacket.create(SendOpcode.ALLIANCE_OPERATION);
        p.writeByte(0x0F);
        p.writeInt(alliance.getId());
        p.writeString(alliance.getName());
        for (int i = 1; i <= 5; i++) {
            p.writeString(alliance.getRankTitle(i));
        }
        p.writeByte(alliance.getGuilds().size());
        for (Integer guild : alliance.getGuilds()) {
            p.writeInt(guild);
        }
        p.writeInt(alliance.getCapacity()); // 可能是容量
        p.writeShort(0);
        for (Integer guildid : alliance.getGuilds()) {
            getGuildInfo(p, Server.getInstance().getGuild(guildid, world));
        }
        return p;
    }

    public static Packet getGuildAlliances(Alliance alliance, int worldId) {
        OutPacket p = OutPacket.create(SendOpcode.ALLIANCE_OPERATION);
        p.writeByte(0x0D);
        p.writeInt(alliance.getGuilds().size());
        for (Integer guild : alliance.getGuilds()) {
            getGuildInfo(p, Server.getInstance().getGuild(guild, worldId));
        }
        return p;
    }

    public static Packet addGuildToAlliance(Alliance alliance, int newGuild, Client c) {
        OutPacket p = OutPacket.create(SendOpcode.ALLIANCE_OPERATION);
        p.writeByte(0x12);
        p.writeInt(alliance.getId());
        p.writeString(alliance.getName());
        for (int i = 1; i <= 5; i++) {
            p.writeString(alliance.getRankTitle(i));
        }
        p.writeByte(alliance.getGuilds().size());
        for (Integer guild : alliance.getGuilds()) {
            p.writeInt(guild);
        }
        p.writeInt(alliance.getCapacity());
        p.writeString(alliance.getNotice());
        p.writeInt(newGuild);
        getGuildInfo(p, Server.getInstance().getGuild(newGuild, c.getWorld(), null));
        return p;
    }

    public static Packet allianceMemberOnline(Character mc, boolean online) {
        OutPacket p = OutPacket.create(SendOpcode.ALLIANCE_OPERATION);
        p.writeByte(0x0E);
        p.writeInt(mc.getGuild().getAllianceId());
        p.writeInt(mc.getGuildId());
        p.writeInt(mc.getId());
        p.writeBool(online);
        return p;
    }

    public static Packet allianceNotice(int id, String notice) {
        OutPacket p = OutPacket.create(SendOpcode.ALLIANCE_OPERATION);
        p.writeByte(0x1C);
        p.writeInt(id);
        p.writeString(notice);
        return p;
    }

    public static Packet changeAllianceRankTitle(int alliance, String[] ranks) {
        OutPacket p = OutPacket.create(SendOpcode.ALLIANCE_OPERATION);
        p.writeByte(0x1A);
        p.writeInt(alliance);
        for (int i = 0; i < 5; i++) {
            p.writeString(ranks[i]);
        }
        return p;
    }

    public static Packet updateAllianceJobLevel(Character mc) {
        OutPacket p = OutPacket.create(SendOpcode.ALLIANCE_OPERATION);
        p.writeByte(0x18);
        p.writeInt(mc.getGuild().getAllianceId());
        p.writeInt(mc.getGuildId());
        p.writeInt(mc.getId());
        p.writeInt(mc.getLevel());
        p.writeInt(mc.getJob().getId());
        return p;
    }

    public static Packet removeGuildFromAlliance(Alliance alliance, int expelledGuild, int worldId) {
        OutPacket p = OutPacket.create(SendOpcode.ALLIANCE_OPERATION);
        p.writeByte(0x10);
        p.writeInt(alliance.getId());
        p.writeString(alliance.getName());
        for (int i = 1; i <= 5; i++) {
            p.writeString(alliance.getRankTitle(i));
        }
        p.writeByte(alliance.getGuilds().size());
        for (Integer guild : alliance.getGuilds()) {
            p.writeInt(guild);
        }
        p.writeInt(alliance.getCapacity());
        p.writeString(alliance.getNotice());
        p.writeInt(expelledGuild);
        getGuildInfo(p, Server.getInstance().getGuild(expelledGuild, worldId, null));
        p.writeByte(0x01);
        return p;
    }

    public static Packet disbandAlliance(int alliance) {
        OutPacket p = OutPacket.create(SendOpcode.ALLIANCE_OPERATION);
        p.writeByte(0x1D);
        p.writeInt(alliance);
        return p;
    }

    public static Packet allianceInvite(int allianceid, Character chr) {
        OutPacket p = OutPacket.create(SendOpcode.ALLIANCE_OPERATION);
        p.writeByte(0x03);
        p.writeInt(allianceid);
        p.writeString(chr.getName());
        p.writeShort(0);
        return p;
    }

    public static Packet GuildBoss_HealerMove(short nY) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_BOSS_HEALER_MOVE);
        p.writeShort(nY); // 新的Y坐标
        return p;
    }

    public static Packet GuildBoss_PulleyStateChange(byte nState) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_BOSS_PULLEY_STATE_CHANGE);
        p.writeByte(nState);
        return p;
    }

    /**
     * 家族名称和标志更新数据包，感谢 Arnah (Vertisy)
     *
     * @param guildName 家族名称，如果为空则不更新。
     */
    public static Packet guildNameChanged(int chrid, String guildName) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_NAME_CHANGED);
        p.writeInt(chrid);
        p.writeString(guildName);
        return p;
    }

    public static Packet guildMarkChanged(int chrId, Guild guild) {
        OutPacket p = OutPacket.create(SendOpcode.GUILD_MARK_CHANGED);
        p.writeInt(chrId);
        p.writeShort(guild.getLogoBG());
        p.writeByte(guild.getLogoBGColor());
        p.writeShort(guild.getLogo());
        p.writeByte(guild.getLogoColor());
        return p;
    }


    public static Packet sendShowInfo(int allianceid, int playerid) {
        OutPacket p = OutPacket.create(SendOpcode.ALLIANCE_OPERATION);
        p.writeByte(0x02);
        p.writeInt(allianceid);
        p.writeInt(playerid);
        return p;
    }

    public static Packet sendInvitation(int allianceid, int playerid, final String guildname) {
        OutPacket p = OutPacket.create(SendOpcode.ALLIANCE_OPERATION);
        p.writeByte(0x05);
        p.writeInt(allianceid);
        p.writeInt(playerid);
        p.writeString(guildname);
        return p;
    }

    public static Packet sendChangeGuild(int allianceid, int playerid, int guildid, int option) {
        OutPacket p = OutPacket.create(SendOpcode.ALLIANCE_OPERATION);
        p.writeByte(0x07);
        p.writeInt(allianceid);
        p.writeInt(guildid);
        p.writeInt(playerid);
        p.writeByte(option);
        return p;
    }

    public static Packet sendChangeLeader(int allianceid, int playerid, int victim) {
        OutPacket p = OutPacket.create(SendOpcode.ALLIANCE_OPERATION);
        p.writeByte(0x08);
        p.writeInt(allianceid);
        p.writeInt(playerid);
        p.writeInt(victim);
        return p;
    }

    public static Packet sendChangeRank(int allianceid, int playerid, int int1, byte byte1) {
        OutPacket p = OutPacket.create(SendOpcode.ALLIANCE_OPERATION);
        p.writeByte(0x09);
        p.writeInt(allianceid);
        p.writeInt(playerid);
        p.writeInt(int1);
        p.writeInt(byte1);
        return p;
    }
}
