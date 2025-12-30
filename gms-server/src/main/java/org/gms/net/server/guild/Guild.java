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
package org.gms.net.server.guild;

import com.mybatisflex.core.query.QueryWrapper;
import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.config.GameConfig;
import org.gms.dao.entity.CharactersDO;
import org.gms.dao.entity.GuildsDO;
import org.gms.dao.mapper.CharactersMapper;
import org.gms.dao.mapper.GuildsMapper;
import org.gms.net.packet.Packet;
import org.gms.net.server.PlayerStorage;
import org.gms.net.server.Server;
import org.gms.net.server.channel.Channel;
import org.gms.net.server.coordinator.matchchecker.MatchCheckerCoordinator;
import org.gms.net.server.coordinator.world.InviteCoordinator;
import org.gms.net.server.coordinator.world.InviteCoordinator.InviteResult;
import org.gms.net.server.coordinator.world.InviteCoordinator.InviteType;
import org.gms.service.NoteService;
import org.gms.util.PacketCreator;
import org.gms.util.SpringContextUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class Guild {
    private static final Logger log = LoggerFactory.getLogger(Guild.class);

    private enum BCOp {
        NONE, DISBAND, EMBLEMCHANGE
    }

    private final List<GuildCharacter> members;
    private final Lock membersLock = new ReentrantLock(true);

    private final String[] rankTitles = new String[5]; // 1 = master, 2 = jr, 5 = lowest member
    private String name, notice;
    private int id, gp, logo, logoColor, leader, capacity, logoBG, logoBGColor, signature, allianceId;
    private final int world;
    private final Map<Integer, List<Integer>> notifications = new LinkedHashMap<>();
    private boolean bDirty = true;

    private static GuildsMapper guildsMapper;
    private static CharactersMapper charactersMapper;

    static {
        guildsMapper = SpringContextUtil.getBean(GuildsMapper.class);
        charactersMapper = SpringContextUtil.getBean(CharactersMapper.class);
    }

    public Guild(int guildid, int world) {
        this.world = world;
        members = new ArrayList<>();

        GuildsDO guildDO = guildsMapper.selectOneById(guildid);
        if (guildDO == null) {
            id = -1;
            return;
        }

        id = guildid;
        name = guildDO.getName();
        gp = guildDO.getGp() != null ? guildDO.getGp().intValue() : 0;
        logo = guildDO.getLogo() != null ? guildDO.getLogo().intValue() : 0;
        logoColor = guildDO.getLogoColor() != null ? guildDO.getLogoColor() : 0;
        logoBG = guildDO.getLogoBG() != null ? guildDO.getLogoBG().intValue() : 0;
        logoBGColor = guildDO.getLogoBGColor() != null ? guildDO.getLogoBGColor() : 0;
        capacity = guildDO.getCapacity() != null ? guildDO.getCapacity().intValue() : 0;
        rankTitles[0] = guildDO.getRank1title();
        rankTitles[1] = guildDO.getRank2title();
        rankTitles[2] = guildDO.getRank3title();
        rankTitles[3] = guildDO.getRank4title();
        rankTitles[4] = guildDO.getRank5title();
        leader = guildDO.getLeader() != null ? guildDO.getLeader().intValue() : 0;
        notice = guildDO.getNotice();
        signature = guildDO.getSignature() != null ? guildDO.getSignature() : 0;
        allianceId = guildDO.getAllianceId() != null ? guildDO.getAllianceId().intValue() : 0;

        List<CharactersDO> memberList = charactersMapper.selectGuildMembers(guildid);
        for (CharactersDO member : memberList) {
            members.add(new GuildCharacter(null, member.getId(), member.getLevel(), member.getName(), (byte) -1, world, member.getJob(), member.getGuildrank(), guildid, false, member.getAllianceRank()));
        }
    }

    private void buildNotifications() {
        if (!bDirty) {
            return;
        }
        Set<Integer> chs = Server.getInstance().getOpenChannels(world);
        synchronized (notifications) {
            if (notifications.keySet().size() != chs.size()) {
                notifications.clear();
                for (Integer ch : chs) {
                    notifications.put(ch, new LinkedList<>());
                }
            } else {
                for (List<Integer> l : notifications.values()) {
                    l.clear();
                }
            }
        }

        membersLock.lock();
        try {
            for (GuildCharacter mgc : members) {
                if (!mgc.isOnline()) {
                    continue;
                }

                List<Integer> chl;
                synchronized (notifications) {
                    chl = notifications.get(mgc.getChannel());
                }
                if (chl != null) {
                    chl.add(mgc.getId());
                }
                //Unable to connect to Channel... error was here
            }
        } finally {
            membersLock.unlock();
        }

        bDirty = false;
    }

    public void writeToDB(boolean bDisband) {
        if (!bDisband) {
            GuildsDO guildDO = new GuildsDO();
            guildDO.setGuildid((long) this.id);
            guildDO.setGp((long) gp);
            guildDO.setLogo((long) logo);
            guildDO.setLogoColor(logoColor);
            guildDO.setLogoBG((long) logoBG);
            guildDO.setLogoBGColor(logoBGColor);
            guildDO.setRank1title(rankTitles[0]);
            guildDO.setRank2title(rankTitles[1]);
            guildDO.setRank3title(rankTitles[2]);
            guildDO.setRank4title(rankTitles[3]);
            guildDO.setRank5title(rankTitles[4]);
            guildDO.setCapacity((long) capacity);
            guildDO.setNotice(notice);
            guildsMapper.update(guildDO);
        } else {
            charactersMapper.resetGuildInfoByGuildId(this.id);
            guildsMapper.deleteById(this.id);

            membersLock.lock();
            try {
                this.broadcast(GuildPackets.guildDisband(this.id));
            } finally {
                membersLock.unlock();
            }
        }
    }

    public int getId() {
        return id;
    }

    public int getLeaderId() {
        return leader;
    }

    public int setLeaderId(int charId) {
        return leader = charId;
    }

    public int getGP() {
        return gp;
    }

    public int getLogo() {
        return logo;
    }

    public void setLogo(int l) {
        logo = l;
    }

    public int getLogoColor() {
        return logoColor;
    }

    public void setLogoColor(int c) {
        logoColor = c;
    }

    public int getLogoBG() {
        return logoBG;
    }

    public void setLogoBG(int bg) {
        logoBG = bg;
    }

    public int getLogoBGColor() {
        return logoBGColor;
    }

    public void setLogoBGColor(int c) {
        logoBGColor = c;
    }

    public String getNotice() {
        if (notice == null) {
            return "";
        }
        return notice;
    }

    public String getName() {
        return name;
    }

    public List<GuildCharacter> getMembers() {
        membersLock.lock();
        try {
            return new ArrayList<>(members);
        } finally {
            membersLock.unlock();
        }
    }

    public int getCapacity() {
        return capacity;
    }

    public int getSignature() {
        return signature;
    }

    public void broadcastNameChanged() {
        PlayerStorage ps = Server.getInstance().getWorld(world).getPlayerStorage();

        for (GuildCharacter mgc : getMembers()) {
            Character chr = ps.getCharacterById(mgc.getId());
            if (chr == null || !chr.isLoggedInWorld()) {
                continue;
            }

            Packet packet = GuildPackets.guildNameChanged(chr.getId(), this.getName());
            chr.getMap().broadcastPacket(chr, packet);
        }
    }

    public void broadcastEmblemChanged() {
        PlayerStorage ps = Server.getInstance().getWorld(world).getPlayerStorage();

        for (GuildCharacter mgc : getMembers()) {
            Character chr = ps.getCharacterById(mgc.getId());
            if (chr == null || !chr.isLoggedInWorld()) {
                continue;
            }

            Packet packet = GuildPackets.guildMarkChanged(chr.getId(), this);
            chr.getMap().broadcastPacket(chr, packet);
        }
    }

    public void broadcastInfoChanged() {
        PlayerStorage ps = Server.getInstance().getWorld(world).getPlayerStorage();

        for (GuildCharacter mgc : getMembers()) {
            Character chr = ps.getCharacterById(mgc.getId());
            if (chr == null || !chr.isLoggedInWorld()) {
                continue;
            }

            chr.sendPacket(GuildPackets.showGuildInfo(chr));
        }
    }

    public void broadcast(Packet packet) {
        broadcast(packet, -1, BCOp.NONE);
    }

    public void broadcast(Packet packet, int exception) {
        broadcast(packet, exception, BCOp.NONE);
    }

    public void broadcast(Packet packet, int exceptionId, BCOp bcop) {
        membersLock.lock(); // membersLock awareness thanks to ProjectNano dev team
        try {
            synchronized (notifications) {
                if (bDirty) {
                    buildNotifications();
                }
                try {
                    for (Integer b : Server.getInstance().getOpenChannels(world)) {
                        if (notifications.get(b).size() > 0) {
                            if (bcop == BCOp.DISBAND) {
                                Server.getInstance().getWorld(world).setGuildAndRank(notifications.get(b), 0, 5, exceptionId);
                            } else if (bcop == BCOp.EMBLEMCHANGE) {
                                Server.getInstance().getWorld(world).changeEmblem(this.id, notifications.get(b), new GuildSummary(this));
                            } else {
                                Server.getInstance().getWorld(world).sendPacket(notifications.get(b), packet, exceptionId);
                            }
                        }
                    }
                } catch (Exception re) {
                    log.error("Failed to contact channel(s) for broadcast.", re);
                }
            }
        } finally {
            membersLock.unlock();
        }
    }

    public void guildMessage(Packet serverNotice) {
        membersLock.lock();
        try {
            for (GuildCharacter mgc : members) {
                for (Channel cs : Server.getInstance().getChannelsFromWorld(world)) {
                    if (cs.getPlayerStorage().getCharacterById(mgc.getId()) != null) {
                        cs.getPlayerStorage().getCharacterById(mgc.getId()).sendPacket(serverNotice);
                        break;
                    }
                }
            }
        } finally {
            membersLock.unlock();
        }
    }

    public void dropMessage(String message) {
        dropMessage(5, message);
    }

    public void dropMessage(int type, String message) {
        membersLock.lock();
        try {
            for (GuildCharacter mgc : members) {
                if (mgc.getCharacter() != null) {
                    mgc.getCharacter().dropMessage(type, message);
                }
            }
        } finally {
            membersLock.unlock();
        }
    }

    public void broadcastMessage(Packet packet) {
        Server.getInstance().guildMessage(id, packet);
    }

    public final void setOnline(int cid, boolean online, int channel) {
        membersLock.lock();
        try {
            boolean bBroadcast = true;
            for (GuildCharacter mgc : members) {
                if (mgc.getId() == cid) {
                    if (mgc.isOnline() && online) {
                        bBroadcast = false;
                    }
                    mgc.setOnline(online);
                    mgc.setChannel(channel);
                    break;
                }
            }
            if (bBroadcast) {
                this.broadcast(GuildPackets.guildMemberOnline(id, cid, online), cid);
            }
            bDirty = true;
        } finally {
            membersLock.unlock();
        }
    }

    public void guildChat(String name, int cid, String message) {
        membersLock.lock();
        try {
            this.broadcast(PacketCreator.multiChat(name, message, 2), cid);
        } finally {
            membersLock.unlock();
        }
    }

    public String getRankTitle(int rank) {
        return rankTitles[rank - 1];
    }

    public static int createGuild(int leaderId, String name) {
        try {
            GuildsDO existingGuild = guildsMapper.selectOneByQuery(QueryWrapper.create().where("name = ?", name));
            if (existingGuild != null) {
                return 0;
            }

            GuildsDO newGuild = new GuildsDO();
            newGuild.setLeader((long) leaderId);
            newGuild.setName(name);
            newGuild.setSignature((int) System.currentTimeMillis());
            guildsMapper.insert(newGuild);

            GuildsDO createdGuild = guildsMapper.selectOneByQuery(QueryWrapper.create().where("leader = ?", leaderId));
            int guildId = createdGuild.getGuildid().intValue();

            charactersMapper.updateGuildInfo(leaderId, guildId, 1);

            return guildId;
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    public int addGuildMember(GuildCharacter mgc, Character chr) {
        membersLock.lock();
        try {
            if (members.size() >= capacity) {
                return 0;
            }
            for (int i = members.size() - 1; i >= 0; i--) {
                if (members.get(i).getGuildRank() < 5 || members.get(i).getName().compareTo(mgc.getName()) < 0) {
                    mgc.setCharacter(chr);
                    members.add(i + 1, mgc);
                    bDirty = true;
                    break;
                }
            }

            this.broadcast(GuildPackets.newGuildMember(mgc));
            return 1;
        } finally {
            membersLock.unlock();
        }
    }

    public void leaveGuild(GuildCharacter mgc) {
        membersLock.lock();
        try {
            this.broadcast(GuildPackets.memberLeft(mgc, false));
            members.remove(mgc);
            bDirty = true;
        } finally {
            membersLock.unlock();
        }
    }

    public void expelMember(GuildCharacter initiator, String name, int cid, NoteService noteService) {
        membersLock.lock();
        try {
            java.util.Iterator<GuildCharacter> itr = members.iterator();
            GuildCharacter mgc;
            while (itr.hasNext()) {
                mgc = itr.next();
                if (mgc.getId() == cid && initiator.getGuildRank() < mgc.getGuildRank()) {
                    this.broadcast(GuildPackets.memberLeft(mgc, true));
                    itr.remove();
                    bDirty = true;
                    try {
                        if (mgc.isOnline()) {
                            Server.getInstance().getWorld(mgc.getWorld()).setGuildAndRank(cid, 0, 5);
                        } else {
                            noteService.sendNormal("You have been expelled from the guild.", initiator.getName(), mgc.getName());
                            Server.getInstance().getWorld(mgc.getWorld()).setOfflineGuildStatus((short) 0, (byte) 5, cid);
                        }
                    } catch (Exception re) {
                        re.printStackTrace();
                        return;
                    }
                    return;
                }
            }
            log.warn("Unable to find member with name {} and id {}", name, cid);
        } finally {
            membersLock.unlock();
        }
    }

    public void changeRank(int cid, int newRank) {
        membersLock.lock();
        try {
            for (GuildCharacter mgc : members) {
                if (cid == mgc.getId()) {
                    changeRank(mgc, newRank);
                    return;
                }
            }
        } finally {
            membersLock.unlock();
        }
    }

    public void changeRank(GuildCharacter mgc, int newRank) {
        try {
            if (mgc.isOnline()) {
                Server.getInstance().getWorld(mgc.getWorld()).setGuildAndRank(mgc.getId(), this.id, newRank);
                mgc.setGuildRank(newRank);
            } else {
                Server.getInstance().getWorld(mgc.getWorld()).setOfflineGuildStatus((short) this.id, (byte) newRank, mgc.getId());
                mgc.setOfflineGuildRank(newRank);
            }
        } catch (Exception re) {
            re.printStackTrace();
            return;
        }

        membersLock.lock();
        try {
            this.broadcast(GuildPackets.changeRank(mgc));
        } finally {
            membersLock.unlock();
        }
    }

    public void setGuildNotice(String notice) {
        this.notice = notice;
        this.writeToDB(false);

        membersLock.lock();
        try {
            this.broadcast(GuildPackets.guildNotice(this.id, notice));
        } finally {
            membersLock.unlock();
        }
    }

    public void memberLevelJobUpdate(GuildCharacter mgc) {
        membersLock.lock();
        try {
            for (GuildCharacter member : members) {
                if (mgc.equals(member)) {
                    member.setJobId(mgc.getJobId());
                    member.setLevel(mgc.getLevel());
                    this.broadcast(GuildPackets.guildMemberLevelJobUpdate(mgc));
                    break;
                }
            }
        } finally {
            membersLock.unlock();
        }
    }

    @Override
    public boolean equals(Object other) {
        if (other instanceof GuildCharacter o) {
            return (o.getId() == id && o.getName().equals(name));
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 89 * hash + (this.name != null ? this.name.hashCode() : 0);
        hash = 89 * hash + this.id;
        return hash;
    }

    public void changeRankTitle(String[] ranks) {
        System.arraycopy(ranks, 0, rankTitles, 0, 5);

        membersLock.lock();
        try {
            this.broadcast(GuildPackets.rankTitleChange(this.id, ranks));
        } finally {
            membersLock.unlock();
        }

        this.writeToDB(false);
    }

    public void disbandGuild() {
        if (allianceId > 0) {
            if (!Alliance.removeGuildFromAlliance(allianceId, id, world)) {
                Alliance.disbandAlliance(allianceId);
            }
        }

        membersLock.lock();
        try {
            this.writeToDB(true);
            this.broadcast(null, -1, BCOp.DISBAND);
        } finally {
            membersLock.unlock();
        }
    }

    public void setGuildEmblem(short bg, byte bgcolor, short logo, byte logocolor) {
        this.logoBG = bg;
        this.logoBGColor = bgcolor;
        this.logo = logo;
        this.logoColor = logocolor;
        this.writeToDB(false);

        membersLock.lock();
        try {
            this.broadcast(null, -1, BCOp.EMBLEMCHANGE);
        } finally {
            membersLock.unlock();
        }
    }

    public GuildCharacter getMGC(int cid) {
        membersLock.lock();
        try {
            for (GuildCharacter mgc : members) {
                if (mgc.getId() == cid) {
                    return mgc;
                }
            }
            return null;
        } finally {
            membersLock.unlock();
        }
    }

    public boolean increaseCapacity() {
        if (capacity > 99) {
            return false;
        }
        capacity += 5;
        this.writeToDB(false);

        membersLock.lock();
        try {
            this.broadcast(GuildPackets.guildCapacityChange(this.id, this.capacity));
        } finally {
            membersLock.unlock();
        }

        return true;
    }

    public void gainGP(int amount) {
        this.gp += amount;
        this.writeToDB(false);
        this.guildMessage(GuildPackets.updateGP(this.id, this.gp));
        this.guildMessage(PacketCreator.getGPMessage(amount));
    }

    public void removeGP(int amount) {
        this.gp -= amount;
        this.writeToDB(false);
        this.guildMessage(GuildPackets.updateGP(this.id, this.gp));
    }

    public static GuildResponse sendInvitation(Client c, String targetName) {
        Character mc = c.getChannelServer().getPlayerStorage().getCharacterByName(targetName);
        if (mc == null) {
            return GuildResponse.NOT_IN_CHANNEL;
        }
        if (mc.getGuildId() > 0) {
            return GuildResponse.ALREADY_IN_GUILD;
        }

        Character sender = c.getPlayer();
        if (InviteCoordinator.createInvite(InviteType.GUILD, sender, sender.getGuildId(), mc.getId())) {
            mc.sendPacket(GuildPackets.guildInvite(sender.getGuildId(), sender.getName()));
            return null;
        } else {
            return GuildResponse.MANAGING_INVITE;
        }
    }

    public static boolean answerInvitation(int targetId, String targetName, int guildId, boolean answer) {
        InviteResult res = InviteCoordinator.answerInvite(InviteType.GUILD, targetId, guildId, answer);

        GuildResponse mgr;
        Character sender = res.from;
        switch (res.result) {
            case ACCEPTED:
                return true;

            case DENIED:
                mgr = GuildResponse.DENIED_INVITE;
                break;

            default:
                mgr = GuildResponse.NOT_FOUND_INVITE;
        }

        if (mgr != null && sender != null) {
            sender.sendPacket(mgr.getPacket(targetName));
        }
        return false;
    }

    public static Set<Character> getEligiblePlayersForGuild(Character guildLeader) {
        Set<Character> guildMembers = new HashSet<>();
        guildMembers.add(guildLeader);

        MatchCheckerCoordinator mmce = guildLeader.getWorldServer().getMatchCheckerCoordinator();
        for (Character chr : guildLeader.getMap().getAllPlayers()) {
            if (chr.getParty() == null && chr.getGuild() == null && mmce.getMatchConfirmationLeaderid(chr.getId()) == -1) {
                guildMembers.add(chr);
            }
        }

        return guildMembers;
    }

    public static void displayGuildRanks(Client c, int npcid) {
        List<GuildsDO> guilds = guildsMapper.selectListByQuery(
                QueryWrapper.create()
                        .select("name", "GP", "logoBG", "logoBGColor", "logo", "logoColor")
                        .orderBy("GP", false)
                        .limit(50)
        );
        c.sendPacket(GuildPackets.showGuildRanks(npcid, guilds));
    }

    public int getAllianceId() {
        return allianceId;
    }

    public void setAllianceId(int aid) {
        this.allianceId = aid;
        GuildsDO guildDO = new GuildsDO();
        guildDO.setGuildid((long) id);
        guildDO.setAllianceId((long) aid);
        guildsMapper.update(guildDO);
    }

    public void resetAllianceGuildPlayersRank() {
        membersLock.lock();
        try {
            for (GuildCharacter mgc : members) {
                if (mgc.isOnline()) {
                    mgc.setAllianceRank(5);
                }
            }
        } finally {
            membersLock.unlock();
        }

        charactersMapper.updateAllianceRankByGuildId(id, 5);
    }

    public static int getIncreaseGuildCost(int size) {
        int cost = GameConfig.getServerInt("expand_guild_base_cost") + Math.max(0, (size - 15) / 5) * GameConfig.getServerInt("expand_guild_tier_cost");

        if (size > 30) {
            return Math.min(GameConfig.getServerInt("expand_guild_max_cost"), Math.max(cost, 5000000));
        } else {
            return cost;
        }
    }
}
