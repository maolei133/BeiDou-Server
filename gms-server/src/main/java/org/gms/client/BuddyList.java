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

import com.mybatisflex.core.query.QueryWrapper;
import com.mybatisflex.core.row.Row;
import org.gms.dao.mapper.BuddiesMapper;
import org.gms.net.packet.Packet;
import org.gms.net.server.PlayerStorage;
import org.gms.util.PacketCreator;
import org.gms.util.SpringContextUtil;

import java.util.*;

import static org.gms.dao.entity.table.BuddiesDOTableDef.BUDDIES_D_O;
import static org.gms.dao.entity.table.CharactersDOTableDef.CHARACTERS_D_O;

public class BuddyList {
    public enum BuddyOperation {
        ADDED, DELETED
    }

    public enum BuddyAddResult {
        BUDDYLIST_FULL, ALREADY_ON_LIST, OK
    }

    private final Map<Integer, BuddylistEntry> buddies = new LinkedHashMap<>();
    private int capacity;
    private final Deque<CharacterNameAndId> pendingRequests = new LinkedList<>();

    public BuddyList(int capacity) {
        this.capacity = capacity;
    }

    public boolean contains(int characterId) {
        synchronized (buddies) {
            return buddies.containsKey(characterId);
        }
    }

    public boolean containsVisible(int characterId) {
        BuddylistEntry ble;
        synchronized (buddies) {
            ble = buddies.get(characterId);
        }

        if (ble == null) {
            return false;
        }
        return ble.isVisible();

    }

    public int getCapacity() {
        return capacity;
    }

    public void setCapacity(int capacity) {
        this.capacity = capacity;
    }

    public BuddylistEntry get(int characterId) {
        synchronized (buddies) {
            return buddies.get(characterId);
        }
    }

    public BuddylistEntry get(String characterName) {
        String lowerCaseName = characterName.toLowerCase();
        for (BuddylistEntry ble : getBuddies()) {
            if (ble.getName().toLowerCase().equals(lowerCaseName)) {
                return ble;
            }
        }

        return null;
    }

    public void put(BuddylistEntry entry) {
        synchronized (buddies) {
            buddies.put(entry.getCharacterId(), entry);
        }
    }

    public void remove(int characterId) {
        synchronized (buddies) {
            buddies.remove(characterId);
        }
    }

    public Collection<BuddylistEntry> getBuddies() {
        synchronized (buddies) {
            return Collections.unmodifiableCollection(buddies.values());
        }
    }

    public boolean isFull() {
        synchronized (buddies) {
            return buddies.size() >= capacity;
        }
    }

    public int[] getBuddyIds() {
        synchronized (buddies) {
            int[] buddyIds = new int[buddies.size()];
            int i = 0;
            for (BuddylistEntry ble : buddies.values()) {
                buddyIds[i++] = ble.getCharacterId();
            }
            return buddyIds;
        }
    }

    public void broadcast(Packet packet, PlayerStorage pstorage) {
        for (int bid : getBuddyIds()) {
            Character chr = pstorage.getCharacterById(bid);

            if (chr != null && chr.isLoggedInWorld()) {
                chr.sendPacket(packet);
            }
        }
    }

    public void loadFromDb(int characterId) {
        BuddiesMapper buddiesMapper = SpringContextUtil.getBean(BuddiesMapper.class);
        if (buddiesMapper == null) return;

        QueryWrapper query = QueryWrapper.create()
                .select(BUDDIES_D_O.BUDDYID, BUDDIES_D_O.PENDING, BUDDIES_D_O.GROUP, CHARACTERS_D_O.NAME.as("buddyname"))
                .from(BUDDIES_D_O)
                .join(CHARACTERS_D_O).on(CHARACTERS_D_O.ID.eq(BUDDIES_D_O.BUDDYID))
                .where(BUDDIES_D_O.CHARACTERID.eq(characterId));
        
        List<Row> results = buddiesMapper.selectRowsByQuery(query);
        
        if (results != null) {
            for (Row row : results) {
                int buddyId = ((Number) row.get("buddyid")).intValue();
                String buddyName = (String) row.get("buddyname");
                int pending = ((Number) row.get("pending")).intValue();
                String group = (String) row.get("group");
                
                if (pending == 1) {
                    pendingRequests.push(new CharacterNameAndId(buddyId, buddyName));
                } else {
                    put(new BuddylistEntry(buddyName, group, buddyId, (byte) -1, true));
                }
            }
        }

        buddiesMapper.deleteByQuery(
                QueryWrapper.create().where(BUDDIES_D_O.PENDING.eq(1)).and(BUDDIES_D_O.CHARACTERID.eq(characterId))
        );
    }

    public CharacterNameAndId pollPendingRequest() {
        return pendingRequests.pollLast();
    }

    public void addBuddyRequest(Client c, int cidFrom, String nameFrom, int channelFrom) {
        put(new BuddylistEntry(nameFrom, "默认分组", cidFrom, channelFrom, false));
        if (pendingRequests.isEmpty()) {
            c.sendPacket(PacketCreator.requestBuddylistAdd(cidFrom, c.getPlayer().getId(), nameFrom));
        } else {
            pendingRequests.push(new CharacterNameAndId(cidFrom, nameFrom));
        }
    }
}
