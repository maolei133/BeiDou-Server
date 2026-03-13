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
package org.gms.client;

import com.mybatisflex.core.update.UpdateChain;
import org.gms.dao.entity.FamilyCharacterDO;
import org.gms.net.packet.Packet;
import org.gms.net.server.Server;
import org.gms.net.server.world.World;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.gms.util.PacketCreator;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author Jay Estrella - Mr.Trash :3
 * @author Ubaware
 */
public class Family {
    private static final Logger log = LoggerFactory.getLogger(Family.class);
    private static final AtomicInteger familyIDCounter = new AtomicInteger();

    private final int id, world;
    private final Map<Integer, FamilyEntry> members = new ConcurrentHashMap<>();
    private FamilyEntry leader;
    private String name;
    private String preceptsMessage = "";
    private int totalGenerations;

    public Family(int id, int world) {
        int newId = id;
        if (id == -1) {
            // get next available family id
            while (idInUse(newId = familyIDCounter.incrementAndGet())) {
            }
        }
        this.id = newId;
        this.world = world;
    }

    private static boolean idInUse(int id) {
        for (World world : Server.getInstance().getWorlds()) {
            if (world.getFamily(id) != null) {
                return true;
            }
        }
        return false;
    }

    public int getID() {
        return id;
    }

    public int getWorld() {
        return world;
    }

    public void setLeader(FamilyEntry leader) {
        this.leader = leader;
        setName(leader.getName());
    }

    public FamilyEntry getLeader() {
        return leader;
    }

    private void setName(String name) {
        this.name = name;
    }

    public int getTotalMembers() {
        return members.size();
    }

    public int getTotalGenerations() {
        return totalGenerations;
    }

    public void setTotalGenerations(int generations) {
        this.totalGenerations = generations;
    }

    public String getName() {
        return this.name;
    }

    public void setMessage(String message, boolean save) {
        this.preceptsMessage = message != null ? message : "";
        if (save) {
            try {
                UpdateChain.of(FamilyCharacterDO.class)
                        .set(FamilyCharacterDO::getPrecepts, message)
                        .where(FamilyCharacterDO::getCid).eq(getLeader().getChrId())
                        .update();
            } catch (Exception e) {
                log.error("Could not save new precepts for family {}", getID(), e);
            }
        }
    }

    public String getMessage() {
        return preceptsMessage != null ? preceptsMessage : "";
    }

    public void addEntry(FamilyEntry entry) {
        members.put(entry.getChrId(), entry);
    }

    public void removeEntryBranch(FamilyEntry root) {
        members.remove(root.getChrId());
        for (FamilyEntry junior : root.getJuniors()) {
            if (junior != null) {
                removeEntryBranch(junior);
            }
        }
    }

    public void addEntryTree(FamilyEntry root) {
        members.put(root.getChrId(), root);
        for (FamilyEntry junior : root.getJuniors()) {
            if (junior != null) {
                addEntryTree(junior);
            }
        }
    }

    public FamilyEntry getEntryByID(int cid) {
        return members.get(cid);
    }

    /**
     * 获取学院所有成员的集合。
     * @return 成员集合
     */
    public Collection<FamilyEntry> getMembers() {
        return members.values();
    }

    public void broadcast(Packet packet) {
        broadcast(packet, -1);
    }

    public void broadcast(Packet packet, int ignoreID) {
        for (FamilyEntry entry : members.values()) {
            Character chr = entry.getChr();
            if (chr != null) {
                if (chr.getId() == ignoreID) {
                    continue;
                }
                chr.sendPacket(packet);
            }
        }
    }

    public void Familybuff(int duration) {
        for (FamilyEntry entry : members.values()) {
            Character chr = entry.getChr();
            if (chr != null) {
                chr.sendPacket(PacketCreator.familyBuff(4, 4, 1, duration  * 60000));
                chr.setFamilyBuff(true,2,2);
                chr.startFamilyBuffTimer(duration  * 60000);
            }
        }
    }

    public void broadcastFamilyInfoUpdate() {
        for (FamilyEntry entry : members.values()) {
            Character chr = entry.getChr();
            if (chr != null) {
                chr.sendPacket(PacketCreator.getFamilyInfo(entry));
            }
        }
    }

    public void resetDailyReps() {
        for (FamilyEntry entry : members.values()) {
            entry.setTodaysRep(0);
            entry.setRepsToSenior(0);
            entry.resetEntitlementUsages();
        }
    }

    public void saveAllMembersRep() { //was used for autosave task, but character autosave should be enough
        boolean success = true;
        for (FamilyEntry entry : members.values()) {
            success = entry.saveReputation();
            if (!success) {
                break;
            }
        }
        if (!success) {
            log.error("Family rep autosave failed for family {}", getID());
        }
        //reset repChanged after successful save
        for (FamilyEntry entry : members.values()) {
            entry.savedSuccessfully();
        }
    }
}
