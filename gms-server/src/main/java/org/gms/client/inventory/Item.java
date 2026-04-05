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
package org.gms.client.inventory;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.gms.client.inventory.manipulator.KarmaManipulator;
import org.gms.constants.inventory.ItemConstants;
import org.gms.model.dto.ItemInfoRtnDTO;
import org.gms.server.ItemInformationProvider;
import org.gms.util.SnowflakeIdGenerator;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

public class Item implements Comparable<Item> {

    private static final AtomicInteger runningCashId = new AtomicInteger(777000000);  // 宠物和戒指共享现金ID值

    private int id;
    private int cashId;
    private int sn;
    private short position;
    private short quantity;
    @JsonIgnore
    private int petid = -1;
    private Pet pet = null;
    private String owner = "";
    protected List<String> itemLog;
    private short flag;
    private long expiration = -1;
    private String giftFrom = "";
    /**
     * 物品唯一ID (不序列化到JSON)
     */
    @JsonIgnore
    private long uid;
    private Long inventoryItemId;

    @JsonIgnore
    private transient boolean dirty = false;

    public Item(int id, short position, short quantity) {
        this.id = id;
        this.position = position;
        this.quantity = quantity;
        this.itemLog = new LinkedList<>();
        this.flag = 0;
        this.uid = SnowflakeIdGenerator.getInstance().nextId();
        this.dirty = true; // 新创建的物品默认为脏
    }

    public Item(int id, short position, short quantity, int petid) {
        this.id = id;
        this.position = position;
        this.quantity = quantity;
        if (petid > -1) {
            this.pet = Pet.loadFromDb(id, position, petid);
            if (this.pet == null) {
                petid = -1;
            }
        }
        this.petid = petid;
        this.flag = 0;
        this.itemLog = new LinkedList<>();
        this.uid = SnowflakeIdGenerator.getInstance().nextId();
        this.dirty = true; // 新创建的物品默认为脏
    }

    public boolean isDirty() {
        return dirty;
    }

    public void setDirty(boolean dirty) {
        this.dirty = dirty;
    }

    public Item copy() {
        Item ret = new Item(id, position, quantity, petid);
        ret.flag = flag;
        ret.owner = owner;
        ret.expiration = expiration;
        ret.itemLog = new LinkedList<>(itemLog);
        ret.uid = this.uid;
        ret.inventoryItemId = this.inventoryItemId;
        ret.dirty = this.dirty; // 复制时也要复制脏标记
        return ret;
    }

    public void setPosition(short position) {
        if (this.position != position) {
            this.position = position;
            setDirty(true);
        }
        if (this.pet != null) {
            this.pet.setPosition(position);
        }
    }

    public void setQuantity(short quantity) {
        if (this.quantity != quantity) {
            this.quantity = quantity;
            setDirty(true);
        }
    }

    public int getItemId() {
        return id;
    }
    
    public void setItemId(int id) {
        if (this.id != id) {
            this.id = id;
            setDirty(true);
        }
    }

    public void setCashId(int cashId) {
        if (this.cashId != cashId) {
            this.cashId = cashId;
            setDirty(true);
        }
    }

    public int getCashId() {
        if (cashId == 0) {
            cashId = runningCashId.getAndIncrement();
        }
        return cashId;
    }

    public short getPosition() {
        return position;
    }

    public short getQuantity() {
        return quantity;
    }

    public InventoryType getInventoryType() {
        return ItemConstants.getInventoryType(id);
    }

    public byte getItemType() {
        if (getPetId() > -1) return 3;
        return 2;
    }

    public String getOwner() {
        return owner;
    }

    public void setOwner(String owner) {
        if (!Objects.equals(this.owner, owner)) {
            this.owner = owner;
            setDirty(true);
        }
    }

    @JsonIgnore
    public int getPetId() {
        return petid;
    }

    @Override
    public int compareTo(Item other) {
        return Integer.compare(this.id, other.getItemId());
    }

    @Override
    public String toString() {
        return "物品: " + id + " 数量: " + quantity;
    }

    public List<String> getItemLog() {
        return Collections.unmodifiableList(itemLog);
    }

    public short getFlag() {
        return flag;
    }

    public void setFlag(short b) {
        ItemInformationProvider ii = ItemInformationProvider.getInstance();
        if (ii.isAccountRestricted(id)) {
            b |= ItemConstants.ACCOUNT_SHARING;
        }
        if (this.flag != b) {
            this.flag = b;
            setDirty(true);
        }
    }

    public long getExpiration() {
        return expiration;
    }

    public void setExpiration(long expire) {
        long newExpiration = !ItemConstants.isPermanentItem(id) ? expire : ItemConstants.isPet(id) ? Long.MAX_VALUE : -1;
        if (this.expiration != newExpiration) {
            this.expiration = newExpiration;
            setDirty(true);
        }
    }

    public int getSN() {
        return sn;
    }

    public void setSN(int sn) {
        if (this.sn != sn) {
            this.sn = sn;
            setDirty(true);
        }
    }

    public String getGiftFrom() {
        return giftFrom;
    }

    public void setGiftFrom(String giftFrom) {
        if (!Objects.equals(this.giftFrom, giftFrom)) {
            this.giftFrom = giftFrom;
            setDirty(true);
        }
    }

    public Pet getPet() {
        return pet;
    }

    public boolean isUntradeable() {
        return ((this.getFlag() & ItemConstants.UNTRADEABLE) == ItemConstants.UNTRADEABLE) || (ItemInformationProvider.getInstance().isDropRestricted(this.getItemId()) && !KarmaManipulator.hasKarmaFlag(this));
    }

    public long getUid() {
        return uid;
    }

    public void setUid(long uid) {
        if (this.uid != uid) {
            this.uid = uid;
            setDirty(true);
        }
    }

    public Long getInventoryItemId() {
        return inventoryItemId;
    }

    public void setInventoryItemId(Long inventoryItemId) {
        if (!Objects.equals(this.inventoryItemId, inventoryItemId)) {
            this.inventoryItemId = inventoryItemId;
            setDirty(true);
        }
    }

    /**
     * 将物品的核心属性转换为DTO对象, 用于JSON序列化。
     * 默认不包含数量, 以支持仓库、商店等大多数场景。
     * @return ItemInfoRtnDTO
     */
    public ItemInfoRtnDTO toInfoRtnDTO() {
        return toInfoRtnDTO(false);
    }

    /**
     * 将物品的核心属性转换为DTO对象, 用于JSON序列化。
     * @param includeQuantity 是否在DTO中包含quantity字段。
     *                        - true: (用于快递系统) DTO中会包含quantity，如果值不为0，将被序列化到JSON中。
     *                        - false: (用于其他系统) DTO中quantity字段为null，将被序列化器忽略。
     * @return ItemInfoRtnDTO
     */
    public ItemInfoRtnDTO toInfoRtnDTO(boolean includeQuantity) {
        ItemInfoRtnDTO dto = new ItemInfoRtnDTO();
        
        if (includeQuantity) {
            dto.setQuantity((int) this.getQuantity());
        }

        if (this.getOwner() != null && !this.getOwner().isEmpty()) {
            dto.setOwner(this.getOwner());
        }
        if (this.getExpiration() != -1) {
            dto.setExpiration(this.getExpiration());
        }
        if (this.getFlag() != 0) {
            dto.setFlag(this.getFlag());
        }
        if (this.getSN() > 0) {
            dto.setSn((long) this.getSN());
        }
        if (this.getPetId() > -1) {
            dto.setPetId(this.getPetId());
        }
        return dto;
    }
}
