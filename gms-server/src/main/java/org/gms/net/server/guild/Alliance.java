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
import org.gms.dao.entity.AllianceDO;
import org.gms.dao.entity.AllianceguildsDO;
import org.gms.dao.mapper.AllianceMapper;
import org.gms.dao.mapper.AllianceguildsMapper;
import org.gms.net.packet.Packet;
import org.gms.net.server.Server;
import org.gms.net.server.coordinator.world.InviteCoordinator;
import org.gms.net.server.coordinator.world.InviteCoordinator.InviteResult;
import org.gms.net.server.coordinator.world.InviteCoordinator.InviteType;
import org.gms.net.server.world.Party;
import org.gms.net.server.world.PartyCharacter;
import org.gms.util.SpringContextUtil;

import java.util.LinkedList;
import java.util.List;

/**
 * @author XoticStory
 * @author Ronan
 */
public class Alliance {
    final private List<Integer> guilds = new LinkedList<>();

    private int allianceId = -1;
    private int capacity;
    private String name;
    private String notice = "";
    private String[] rankTitles = new String[5];

    private static AllianceMapper allianceMapper;
    private static AllianceguildsMapper allianceguildsMapper;

    static {
        allianceMapper = SpringContextUtil.getBean(AllianceMapper.class);
        allianceguildsMapper = SpringContextUtil.getBean(AllianceguildsMapper.class);
    }

    public Alliance(String name, int id) {
        this.name = name;
        allianceId = id;
        String[] ranks = {"Master", "Jr. Master", "Member", "Member", "Member"};
        for (int i = 0; i < 5; i++) {
            rankTitles[i] = ranks[i];
        }
    }

    public static boolean canBeUsedAllianceName(String name) {
        if (name.contains(" ") || name.length() > 12) {
            return false;
        }

        AllianceDO alliance = allianceMapper.selectOneByQuery(QueryWrapper.create().where("name = ?", name));
        return alliance == null;
    }

    private static List<Character> getPartyGuildMasters(Party party) {
        List<Character> mcl = new LinkedList<>();

        for (PartyCharacter mpc : party.getMembers()) {
            Character chr = mpc.getPlayer();
            if (chr != null) {
                Character lchr = party.getLeader().getPlayer();
                if (chr.getGuildRank() == 1 && lchr != null && chr.getMapId() == lchr.getMapId()) {
                    mcl.add(chr);
                }
            }
        }

        if (!mcl.isEmpty() && !mcl.get(0).isPartyLeader()) {
            for (int i = 1; i < mcl.size(); i++) {
                if (mcl.get(i).isPartyLeader()) {
                    Character temp = mcl.get(0);
                    mcl.set(0, mcl.get(i));
                    mcl.set(i, temp);
                }
            }
        }

        return mcl;
    }

    public static Alliance createAlliance(Party party, String name) {
        List<Character> guildMasters = getPartyGuildMasters(party);
        if (guildMasters.size() != 2) {
            return null;
        }

        List<Integer> guilds = new LinkedList<>();
        for (Character mc : guildMasters) {
            guilds.add(mc.getGuildId());
        }
        Alliance alliance = Alliance.createAllianceOnDb(guilds, name);
        if (alliance != null) {
            alliance.setCapacity(guilds.size());
            for (Integer g : guilds) {
                alliance.addGuild(g);
            }

            int id = alliance.getId();
            try {
                for (int i = 0; i < guildMasters.size(); i++) {
                    Server.getInstance().setGuildAllianceId(guilds.get(i), id);
                    Server.getInstance().resetAllianceGuildPlayersRank(guilds.get(i));

                    Character chr = guildMasters.get(i);
                    chr.getMGC().setAllianceRank((i == 0) ? 1 : 2);
                    Server.getInstance().getGuild(chr.getGuildId()).getMGC(chr.getId()).setAllianceRank((i == 0) ? 1 : 2);
                    chr.saveGuildStatus();
                }

                Server.getInstance().addAlliance(id, alliance);

                int worldid = guildMasters.get(0).getWorld();
                Server.getInstance().allianceMessage(id, GuildPackets.updateAllianceInfo(alliance, worldid), -1, -1);
                Server.getInstance().allianceMessage(id, GuildPackets.getGuildAlliances(alliance, worldid), -1, -1);  // thanks Vcoc for noticing guilds from other alliances being visually stacked here due to this not being updated
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        }

        return alliance;
    }

    public static Alliance createAllianceOnDb(List<Integer> guilds, String name) {
        // will create an alliance, where the first guild listed is the leader and the alliance name MUST BE already checked for unicity.

        AllianceDO allianceDO = new AllianceDO();
        allianceDO.setName(name);
        allianceMapper.insert(allianceDO);
        
        // 获取生成的ID
        // MyBatis Flex insert后会自动回填ID到实体类
        int id = allianceDO.getId().intValue();

        for (int guild : guilds) {
            AllianceguildsDO allianceguildsDO = new AllianceguildsDO();
            allianceguildsDO.setAllianceid(id);
            allianceguildsDO.setGuildid(guild);
            allianceguildsMapper.insert(allianceguildsDO);
        }

        return new Alliance(name, id);
    }

    public static Alliance loadAlliance(int id) {
        if (id <= 0) {
            return null;
        }
        Alliance alliance = new Alliance(null, -1);
        
        AllianceDO allianceDO = allianceMapper.selectOneById(id);
        if (allianceDO == null) {
            return null;
        }

        alliance.allianceId = id;
        alliance.capacity = allianceDO.getCapacity() != null ? allianceDO.getCapacity().intValue() : 0;
        alliance.name = allianceDO.getName();
        alliance.notice = allianceDO.getNotice();

        String[] ranks = new String[5];
        ranks[0] = allianceDO.getRank1();
        ranks[1] = allianceDO.getRank2();
        ranks[2] = allianceDO.getRank3();
        ranks[3] = allianceDO.getRank4();
        ranks[4] = allianceDO.getRank5();
        alliance.rankTitles = ranks;

        List<AllianceguildsDO> guildList = allianceguildsMapper.selectListByQuery(
                QueryWrapper.create().where("allianceid = ?", id)
        );
        
        for (AllianceguildsDO ag : guildList) {
            alliance.addGuild(ag.getGuildid());
        }

        return alliance;
    }

    public void saveToDB() {
        AllianceDO allianceDO = new AllianceDO();
        allianceDO.setId((long) this.allianceId);
        allianceDO.setCapacity((long) this.capacity);
        allianceDO.setNotice(this.notice);
        allianceDO.setRank1(this.rankTitles[0]);
        allianceDO.setRank2(this.rankTitles[1]);
        allianceDO.setRank3(this.rankTitles[2]);
        allianceDO.setRank4(this.rankTitles[3]);
        allianceDO.setRank5(this.rankTitles[4]);
        allianceMapper.update(allianceDO);

        allianceguildsMapper.deleteByQuery(QueryWrapper.create().where("allianceid = ?", this.allianceId));

        for (int guild : guilds) {
            AllianceguildsDO allianceguildsDO = new AllianceguildsDO();
            allianceguildsDO.setAllianceid(this.allianceId);
            allianceguildsDO.setGuildid(guild);
            allianceguildsMapper.insert(allianceguildsDO);
        }
    }

    public static void disbandAlliance(int allianceId) {
        allianceMapper.deleteById(allianceId);
        allianceguildsMapper.deleteByQuery(QueryWrapper.create().where("allianceid = ?", allianceId));

        Server.getInstance().allianceMessage(allianceId, GuildPackets.disbandAlliance(allianceId), -1, -1);
        Server.getInstance().disbandAlliance(allianceId);
    }

    private static void removeGuildFromAllianceOnDb(int guildId) {
        allianceguildsMapper.deleteByQuery(QueryWrapper.create().where("guildid = ?", guildId));
    }

    public static boolean removeGuildFromAlliance(int allianceId, int guildId, int worldId) {
        Server srv = Server.getInstance();
        Alliance alliance = srv.getAlliance(allianceId);

        if (alliance.getLeader().getGuildId() == guildId) {
            return false;
        }

        srv.allianceMessage(alliance.getId(), GuildPackets.removeGuildFromAlliance(alliance, guildId, worldId), -1, -1);
        srv.removeGuildFromAlliance(alliance.getId(), guildId);
        removeGuildFromAllianceOnDb(guildId);

        srv.allianceMessage(alliance.getId(), GuildPackets.getGuildAlliances(alliance, worldId), -1, -1);
        srv.allianceMessage(alliance.getId(), GuildPackets.allianceNotice(alliance.getId(), alliance.getNotice()), -1, -1);
        srv.guildMessage(guildId, GuildPackets.disbandAlliance(alliance.getId()));

        alliance.dropMessage("[" + srv.getGuild(guildId, worldId).getName() + "] 家族离开了联盟。");
        return true;
    }

    public void updateAlliancePackets(Character chr) {
        if (allianceId > 0) {
            this.broadcastMessage(GuildPackets.updateAllianceInfo(this, chr.getWorld()));
            this.broadcastMessage(GuildPackets.allianceNotice(this.getId(), this.getNotice()));
        }
    }

    public boolean removeGuild(int gid) {
        synchronized (guilds) {
            int index = getGuildIndex(gid);
            if (index == -1) {
                return false;
            }

            guilds.remove(index);
            return true;
        }
    }

    public boolean addGuild(int gid) {
        synchronized (guilds) {
            if (guilds.size() == capacity || getGuildIndex(gid) > -1) {
                return false;
            }

            guilds.add(gid);
            return true;
        }
    }

    private int getGuildIndex(int gid) {
        synchronized (guilds) {
            for (int i = 0; i < guilds.size(); i++) {
                if (guilds.get(i) == gid) {
                    return i;
                }
            }
            return -1;
        }
    }

    public void setRankTitle(String[] ranks) {
        rankTitles = ranks;
    }

    public String getRankTitle(int rank) {
        return rankTitles[rank - 1];
    }

    public List<Integer> getGuilds() {
        synchronized (guilds) {
            List<Integer> guilds_ = new LinkedList<>();
            for (int guild : guilds) {
                if (guild != -1) {
                    guilds_.add(guild);
                }
            }
            return guilds_;
        }
    }

    public String getAllianceNotice() {
        return notice;
    }

    public String getNotice() {
        return notice;
    }

    public void setNotice(String notice) {
        this.notice = notice;
    }

    public void increaseCapacity(int inc) {
        this.capacity += inc;
    }

    public void setCapacity(int newCapacity) {
        this.capacity = newCapacity;
    }

    public int getCapacity() {
        return this.capacity;
    }

    public int getId() {
        return allianceId;
    }

    public String getName() {
        return name;
    }

    public GuildCharacter getLeader() {
        synchronized (guilds) {
            for (Integer gId : guilds) {
                Guild guild = Server.getInstance().getGuild(gId);
                GuildCharacter mgc = guild.getMGC(guild.getLeaderId());

                if (mgc.getAllianceRank() == 1) {
                    return mgc;
                }
            }

            return null;
        }
    }

    public void dropMessage(String message) {
        dropMessage(5, message);
    }

    public void dropMessage(int type, String message) {
        synchronized (guilds) {
            for (Integer gId : guilds) {
                Guild guild = Server.getInstance().getGuild(gId);
                guild.dropMessage(type, message);
            }
        }
    }

    public void broadcastMessage(Packet packet) {
        Server.getInstance().allianceMessage(allianceId, packet, -1, -1);
    }

    public static void sendInvitation(Client c, String targetGuildName, int allianceId) {
        Guild mg = Server.getInstance().getGuildByName(targetGuildName);
        if (mg == null) {
            c.getPlayer().dropMessage(5, "输入的家族不存在。");
        } else {
            if (mg.getAllianceId() > 0) {
                c.getPlayer().dropMessage(5, "输入的家族已经加入了家族联盟。");
            } else {
                Character victim = mg.getMGC(mg.getLeaderId()).getCharacter();
                if (victim == null) {
                    c.getPlayer().dropMessage(5, "你邀请的家族族长当前不在线。");
                } else {
                    if (InviteCoordinator.createInvite(InviteType.ALLIANCE, c.getPlayer(), allianceId, victim.getId())) {
                        victim.sendPacket(GuildPackets.allianceInvite(allianceId, c.getPlayer()));
                    } else {
                        c.getPlayer().dropMessage(5, "你邀请的家族族长当前正在处理另一个邀请。");
                    }
                }
            }
        }
    }

    public static boolean answerInvitation(int targetId, String targetGuildName, int allianceId, boolean answer) {
        InviteResult res = InviteCoordinator.answerInvite(InviteType.ALLIANCE, targetId, allianceId, answer);

        String msg;
        Character sender = res.from;
        switch (res.result) {
            case ACCEPTED:
                return true;

            case DENIED:
                msg = "[" + targetGuildName + "] 家族拒绝了你的家族联盟邀请。";
                break;

            default:
                msg = "家族联盟请求未被接受，因为邀请已过期。";
        }

        if (sender != null) {
            sender.dropMessage(5, msg);
        }

        return false;
    }
}
