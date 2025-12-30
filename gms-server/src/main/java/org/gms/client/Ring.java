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
import org.gms.dao.entity.InventoryequipmentDO;
import org.gms.dao.entity.RingsDO;
import org.gms.dao.mapper.InventoryequipmentMapper;
import org.gms.dao.mapper.RingsMapper;
import org.gms.util.CashIdGenerator;
import org.gms.util.Pair;
import org.gms.util.SpringContextUtil;

import java.util.Arrays;

/**
 * @author Danny
 */
public class Ring implements Comparable<Ring> {
    private final int ringId;
    private final int ringId2;
    private final int partnerId;
    private final int itemId;
    private final String partnerName;
    private boolean equipped = false;

    public Ring(int id, int id2, int partnerId, int itemid, String partnername) {
        this.ringId = id;
        this.ringId2 = id2;
        this.partnerId = partnerId;
        this.itemId = itemid;
        this.partnerName = partnername;
    }

    public static Ring loadFromDb(int ringId) {
        RingsMapper mapper = SpringContextUtil.getBean(RingsMapper.class);
        if (mapper != null) {
            RingsDO ring = mapper.selectOneById(ringId);
            if (ring != null) {
                return new Ring(ringId, ring.getPartnerRingId(), ring.getPartnerChrId(), ring.getItemid(), ring.getPartnerName());
            }
        }
        return null;
    }

    public static void removeRing(final Ring ring) {
        if (ring == null) {
            return;
        }
        
        RingsMapper ringsMapper = SpringContextUtil.getBean(RingsMapper.class);
        InventoryequipmentMapper equipMapper = SpringContextUtil.getBean(InventoryequipmentMapper.class);
        
        if (ringsMapper != null) {
            ringsMapper.deleteByQuery(new QueryWrapper().in("id", Arrays.asList(ring.getRingId(), ring.getPartnerRingId())));
        }

        CashIdGenerator.freeCashId(ring.getRingId());
        CashIdGenerator.freeCashId(ring.getPartnerRingId());

        if (equipMapper != null) {
            InventoryequipmentDO updateEntity = new InventoryequipmentDO();
            updateEntity.setRingid(-1);
            
            equipMapper.updateByQuery(updateEntity, new QueryWrapper().in("ringid", Arrays.asList(ring.getRingId(), ring.getPartnerRingId())));
        }
    }

    public static Pair<Integer, Integer> createRing(int itemid, final Character partner1, final Character partner2) {
        if (partner1 == null) {
            return new Pair<>(-3, -3);
        } else if (partner2 == null) {
            return new Pair<>(-2, -2);
        }

        int[] ringID = new int[2];
        ringID[0] = CashIdGenerator.generateCashId();
        ringID[1] = CashIdGenerator.generateCashId();

        RingsMapper mapper = SpringContextUtil.getBean(RingsMapper.class);
        if (mapper != null) {
            RingsDO r1 = new RingsDO();
            r1.setId(ringID[0]);
            r1.setItemid(itemid);
            r1.setPartnerRingId(ringID[1]);
            r1.setPartnerChrId(partner2.getId());
            r1.setPartnerName(partner2.getName());
            mapper.insert(r1);

            RingsDO r2 = new RingsDO();
            r2.setId(ringID[1]);
            r2.setItemid(itemid);
            r2.setPartnerRingId(ringID[0]);
            r2.setPartnerChrId(partner1.getId());
            r2.setPartnerName(partner1.getName());
            mapper.insert(r2);
            
            return new Pair<>(ringID[0], ringID[1]);
        }
        
        return new Pair<>(-1, -1);
    }

    public int getRingId() {
        return ringId;
    }

    public int getPartnerRingId() {
        return ringId2;
    }

    public int getPartnerChrId() {
        return partnerId;
    }

    public int getItemId() {
        return itemId;
    }

    public String getPartnerName() {
        return partnerName;
    }

    public boolean equipped() {
        return equipped;
    }

    public void equip() {
        this.equipped = true;
    }

    public void unequip() {
        this.equipped = false;
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof Ring ring) {
            return ring.getRingId() == getRingId();
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 53 * hash + this.ringId;
        return hash;
    }

    @Override
    public int compareTo(Ring other) {
        if (ringId < other.getRingId()) {
            return -1;
        } else if (ringId == other.getRingId()) {
            return 0;
        }
        return 1;
    }
}
