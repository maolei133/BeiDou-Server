package org.gms.util.packets;

import org.gms.client.inventory.Equip.ScrollResult;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.ModifyInventory;
import org.gms.client.Character;
import org.gms.net.opcodes.SendOpcode;
import org.gms.net.packet.OutPacket;
import org.gms.net.packet.Packet;
import org.gms.server.maps.MapItem;

import java.awt.*;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * InventoryPackets
 * 处理背包操作、捡取物品、丢弃物品、仓库等相关的数据包构建
 */
public class InventoryPackets {

    /**
     * 获取修改背包包
     *
     * @param updateTick 是否更新 tick
     * @param mods       修改列表
     * @return 修改背包包
     */
    public static Packet modifyInventory(boolean updateTick, final List<ModifyInventory> mods) {
        OutPacket p = OutPacket.create(SendOpcode.INVENTORY_OPERATION);
        p.writeBool(updateTick);
        p.writeByte(mods.size());
        int addMovement = -1;
        for (ModifyInventory mod : mods) {
            p.writeByte(mod.getMode());
            p.writeByte(mod.getInventoryType());
            p.writeShort(mod.getMode() == 2 ? mod.getOldPosition() : mod.getPosition());
            switch (mod.getMode()) {
                case 0: {//add item
                    PacketHelper.addItemInfo(p, mod.getItem(), true);
                    break;
                }
                case 1: {//update quantity
                    p.writeShort(mod.getQuantity());
                    break;
                }
                case 2: {//move
                    p.writeShort(mod.getPosition());
                    if (mod.getPosition() < 0 || mod.getOldPosition() < 0) {
                        addMovement = mod.getOldPosition() < 0 ? 1 : 2;
                    }
                    break;
                }
                case 3: {//remove
                    if (mod.getPosition() < 0) {
                        addMovement = 2;
                    }
                    break;
                }
            }
            mod.clear();
        }
        if (addMovement > -1) {
            p.writeByte(addMovement);
        }
        return p;
    }

    public static Packet updateInventorySlotLimit(int type, int newLimit) {
        final OutPacket p = OutPacket.create(SendOpcode.INVENTORY_GROW);
        p.writeByte(type);
        p.writeByte(newLimit);
        return p;
    }

    public static Packet getInventoryFull() {
        return modifyInventory(true, Collections.emptyList());
    }

    public static Packet getShowInventoryFull() {
        return getShowInventoryStatus(0xff);
    }

    public static Packet showItemUnavailable() {
        return getShowInventoryStatus(0xfe);
    }

    public static Packet getShowInventoryStatus(int mode) {
        OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        p.writeByte(0);
        p.writeByte(mode);
        p.writeInt(0);
        p.writeInt(0);
        return p;
    }

    public static Packet getScrollEffect(int chr, ScrollResult scrollSuccess, boolean legendarySpirit, boolean whiteScroll) {
        OutPacket p = OutPacket.create(SendOpcode.SHOW_SCROLL_EFFECT);
        p.writeInt(chr);
        p.writeBool(scrollSuccess == ScrollResult.SUCCESS);
        p.writeBool(scrollSuccess == ScrollResult.CURSE);
        p.writeBool(legendarySpirit);
        p.writeBool(whiteScroll);
        return p;
    }

    public static Packet sendHammerData(int hammerUsed) {
        OutPacket p = OutPacket.create(SendOpcode.VICIOUS_HAMMER);
        p.writeByte(0x39);
        p.writeInt(0);
        p.writeInt(hammerUsed);
        return p;
    }

    public static Packet sendHammerMessage() {
        final OutPacket p = OutPacket.create(SendOpcode.VICIOUS_HAMMER);
        p.writeByte(0x3D);
        p.writeInt(0);
        return p;
    }

    public static Packet getStorage(int npcId, byte slots, Collection<Item> items, int meso) {
        final OutPacket p = OutPacket.create(SendOpcode.STORAGE);
        p.writeByte(0x16);
        p.writeInt(npcId);
        p.writeByte(slots);
        p.writeShort(0x7E);
        p.writeShort(0);
        p.writeInt(0);
        p.writeInt(meso);
        p.writeShort(0);
        p.writeByte((byte) items.size());
        for (Item item : items) {
            PacketHelper.addItemInfo(p, item, true);
        }
        p.writeShort(0);
        p.writeByte(0);
        return p;
    }

    /*
     * 0x0A = Inv full
     * 0x0B = You do not have enough mesos
     * 0x0C = One-Of-A-Kind error
     */
    public static Packet getStorageError(byte i) {
        final OutPacket p = OutPacket.create(SendOpcode.STORAGE);
        p.writeByte(i);
        return p;
    }

    public static Packet mesoStorage(byte slots, int meso) {
        final OutPacket p = OutPacket.create(SendOpcode.STORAGE);
        p.writeByte(0x13);
        p.writeByte(slots);
        p.writeShort(2);
        p.writeShort(0);
        p.writeInt(0);
        p.writeInt(meso);
        return p;
    }

    public static Packet storeStorage(byte slots, InventoryType type, Collection<Item> items) {
        final OutPacket p = OutPacket.create(SendOpcode.STORAGE);
        p.writeByte(0xD);
        p.writeByte(slots);
        p.writeShort(type.getBitfieldEncoding());
        p.writeShort(0);
        p.writeInt(0);
        p.writeByte(items.size());
        for (Item item : items) {
            PacketHelper.addItemInfo(p, item, true);
        }
        return p;
    }

    public static Packet takeOutStorage(byte slots, InventoryType type, Collection<Item> items) {
        final OutPacket p = OutPacket.create(SendOpcode.STORAGE);
        p.writeByte(0x9);
        p.writeByte(slots);
        p.writeShort(type.getBitfieldEncoding());
        p.writeShort(0);
        p.writeInt(0);
        p.writeByte(items.size());
        for (Item item : items) {
            PacketHelper.addItemInfo(p, item, true);
        }
        return p;
    }

    public static Packet arrangeStorage(byte slots, Collection<Item> items) {
        OutPacket p = OutPacket.create(SendOpcode.STORAGE);
        p.writeByte(0xF);
        p.writeByte(slots);
        p.writeByte(124);
        p.skip(10);
        p.writeByte(items.size());
        for (Item item : items) {
            PacketHelper.addItemInfo(p, item, true);
        }
        p.writeByte(0);
        return p;
    }

    public static Packet finishedSort(int inv) {
        OutPacket p = OutPacket.create(SendOpcode.GATHER_ITEM_RESULT);
        p.writeByte(0);
        p.writeByte(inv);
        return p;
    }

    public static Packet finishedSort2(int inv) {
        OutPacket p = OutPacket.create(SendOpcode.SORT_ITEM_RESULT);
        p.writeByte(0);
        p.writeByte(inv);
        return p;
    }

    public static Packet itemEffect(int characterid, int itemid) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_ITEM_EFFECT);
        p.writeInt(characterid);
        p.writeInt(itemid);
        return p;
    }

    public static Packet itemExpired(int itemid) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        p.writeByte(2);
        p.writeInt(itemid);
        return p;
    }

    public static Packet getItemMessage(int itemid) {
        OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        p.writeByte(7);
        p.writeInt(itemid);
        return p;
    }

    public static Packet silentRemoveItemFromMap(int objId) {
        return removeItemFromMap(objId, 1, 0);
    }

    /**
     * animation: 0 - expire<br/> 1 - without animation<br/> 2 - pickup<br/> 4 -
     * explode<br/> cid is ignored for 0 and 1
     *
     * @param objId
     * @param animation
     * @param chrId
     * @return
     */
    public static Packet removeItemFromMap(int objId, int animation, int chrId) {
        return removeItemFromMap(objId, animation, chrId, false, 0);
    }

    /**
     * animation: 0 - expire<br/> 1 - without animation<br/> 2 - pickup<br/> 4 -
     * explode<br/> cid is ignored for 0 and 1.<br /><br />Flagging pet as true
     * will make a pet pick up the item.
     *
     * @param objId
     * @param animation
     * @param chrId
     * @param pet
     * @param slot
     * @return
     */
    public static Packet removeItemFromMap(int objId, int animation, int chrId, boolean pet, int slot) {
        OutPacket p = OutPacket.create(SendOpcode.REMOVE_ITEM_FROM_MAP);
        p.writeByte(animation); // expire
        p.writeInt(objId);
        if (animation >= 2) {
            p.writeInt(chrId);
            if (pet) {
                p.writeByte(slot);
            }
        }
        return p;
    }

    public static Packet dropItemFromMapObject(Character player, MapItem drop, Point dropfrom, Point dropto, byte mod) {
        int dropType = drop.getDropType();
        if (drop.hasClientsideOwnership(player) && dropType < 3) {
            dropType = 2;
        }

        OutPacket p = OutPacket.create(SendOpcode.DROP_ITEM_FROM_MAPOBJECT);
        p.writeByte(mod);
        p.writeInt(drop.getObjectId());
        p.writeBool(drop.getMeso() > 0); // 1 mesos, 0 item, 2 and above all item meso bag,
        p.writeInt(drop.getItemId()); // drop object ID
        p.writeInt(drop.getClientsideOwnerId()); // owner charid/partyid :)
        p.writeByte(dropType); // 0 = timeout for non-owner, 1 = timeout for non-owner's party, 2 = FFA, 3 = explosive/FFA
        p.writePos(dropto);
        p.writeInt(drop.getDropper().getObjectId()); // dropper oid, found thanks to Li Jixue

        if (mod != 2) {
            p.writePos(dropfrom);
            p.writeShort(0);//Fh?
        }
        if (drop.getMeso() == 0) {
            PacketHelper.addExpirationTime(p, drop.getItem().getExpiration());
        }
        p.writeByte(drop.isPlayerDrop() ? 0 : 1); //pet EQP pickup
        return p;
    }

    public static Packet updateMapItemObject(MapItem drop, boolean giveOwnership) {
        OutPacket p = OutPacket.create(SendOpcode.DROP_ITEM_FROM_MAPOBJECT);
        p.writeByte(2);
        p.writeInt(drop.getObjectId());
        p.writeBool(drop.getMeso() > 0);
        p.writeInt(drop.getItemId());
        p.writeInt(giveOwnership ? 0 : -1);
        p.writeByte(drop.hasExpiredOwnershipTime() ? 2 : drop.getDropType());
        p.writePos(drop.getPosition());
        p.writeInt(giveOwnership ? 0 : -1);

        if (drop.getMeso() == 0) {
            PacketHelper.addExpirationTime(p, drop.getItem().getExpiration());
        }
        p.writeBool(!drop.isPlayerDrop());
        return p;
    }

    /**
     * 获取显示物品获得包
     *
     * @param itemId   物品 ID
     * @param quantity 数量
     * @return 显示物品获得包
     */
    public static Packet getShowItemGain(int itemId, short quantity) {
        return getShowItemGain(itemId, quantity, false);
    }

    /**
     * 获取显示物品获得包
     *
     * @param itemId   物品 ID
     * @param quantity 数量
     * @param inChat   是否在聊天框显示
     * @return 显示物品获得包
     */
    public static Packet getShowItemGain(int itemId, short quantity, boolean inChat) {
        final OutPacket p;
        if (inChat) {
            p = OutPacket.create(SendOpcode.SHOW_ITEM_GAIN_INCHAT);
            p.writeByte(3);
            p.writeByte(1);
            p.writeInt(itemId);
            p.writeInt(quantity);
        } else {
            p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
            p.writeShort(0);
            p.writeInt(itemId);
            p.writeInt(quantity);
            p.writeInt(0);
            p.writeInt(0);
        }
        return p;
    }

    public static Packet setExtraPendantSlot(boolean toggleExtraSlot) {
        final OutPacket p = OutPacket.create(SendOpcode.SET_EXTRA_PENDANT_SLOT);
        p.writeBool(toggleExtraSlot);
        return p;
    }
}
