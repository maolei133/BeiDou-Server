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
        //p.writeByte(0); v104 :)
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

    /**
     * 更新背包槽位限制
     *
     * @param type     背包类型
     * @param newLimit 新限制
     * @return 更新背包槽位限制包
     */
    public static Packet updateInventorySlotLimit(int type, int newLimit) {
        final OutPacket p = OutPacket.create(SendOpcode.INVENTORY_GROW);
        p.writeByte(type);
        p.writeByte(newLimit);
        return p;
    }

    /**
     * 获取背包已满包
     *
     * @return 背包已满包
     */
    public static Packet getInventoryFull() {
        return modifyInventory(true, Collections.emptyList());
    }

    /**
     * 获取显示背包已满包
     *
     * @return 显示背包已满包
     */
    public static Packet getShowInventoryFull() {
        return getShowInventoryStatus(0xff);
    }

    /**
     * 显示物品不可用
     *
     * @return 物品不可用包
     */
    public static Packet showItemUnavailable() {
        return getShowInventoryStatus(0xfe);
    }

    /**
     * 获取显示背包状态包
     *
     * @param mode 模式
     * @return 显示背包状态包
     */
    public static Packet getShowInventoryStatus(int mode) {
        OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        p.writeByte(0);
        p.writeByte(mode);
        p.writeInt(0);
        p.writeInt(0);
        return p;
    }

    /**
     * 获取卷轴效果包
     *
     * @param chr             角色 ID
     * @param scrollSuccess   卷轴结果
     * @param legendarySpirit 传说灵魂
     * @param whiteScroll     白卷
     * @return 卷轴效果包
     */
    public static Packet getScrollEffect(int chr, ScrollResult scrollSuccess, boolean legendarySpirit, boolean whiteScroll) {
        OutPacket p = OutPacket.create(SendOpcode.SHOW_SCROLL_EFFECT);
        p.writeInt(chr);
        p.writeBool(scrollSuccess == ScrollResult.SUCCESS);
        p.writeBool(scrollSuccess == ScrollResult.CURSE);
        p.writeBool(legendarySpirit);
        p.writeBool(whiteScroll);
        return p;
    }

    /**
     * 发送锤子数据包
     *
     * @param hammerUsed 已使用锤子数
     * @return 锤子数据包
     */
    public static Packet sendHammerData(int hammerUsed) {
        OutPacket p = OutPacket.create(SendOpcode.VICIOUS_HAMMER);
        p.writeByte(0x39);
        p.writeInt(0);
        p.writeInt(hammerUsed);
        return p;
    }

    /**
     * 发送锤子消息包
     *
     * @return 锤子消息包
     */
    public static Packet sendHammerMessage() {
        final OutPacket p = OutPacket.create(SendOpcode.VICIOUS_HAMMER);
        p.writeByte(0x3D);
        p.writeInt(0);
        return p;
    }

    /**
     * 获取仓库包
     *
     * @param npcId NPC ID
     * @param slots 槽位数
     * @param items 物品列表
     * @param meso  金币
     * @return 仓库包
     */
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
     * 0x0A = 背包已满
     * 0x0B = 金币不足
     * 0x0C = 唯一物品错误
     */
    /**
     * 获取仓库错误包
     *
     * @param i 错误代码
     * @return 仓库错误包
     */
    public static Packet getStorageError(byte i) {
        final OutPacket p = OutPacket.create(SendOpcode.STORAGE);
        p.writeByte(i);
        return p;
    }

    /**
     * 仓库金币包
     *
     * @param slots 槽位数
     * @param meso  金币
     * @return 仓库金币包
     */
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

    /**
     * 存入仓库包
     *
     * @param slots 槽位数
     * @param type  背包类型
     * @param items 物品列表
     * @return 存入仓库包
     */
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

    /**
     * 取出仓库包
     *
     * @param slots 槽位数
     * @param type  背包类型
     * @param items 物品列表
     * @return 取出仓库包
     */
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

    /**
     * 整理仓库包
     *
     * @param slots 槽位数
     * @param items 物品列表
     * @return 整理仓库包
     */
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

    /**
     * 完成整理包
     *
     * @param inv 背包类型
     * @return 完成整理包
     */
    public static Packet finishedSort(int inv) {
        OutPacket p = OutPacket.create(SendOpcode.GATHER_ITEM_RESULT);
        p.writeByte(0);
        p.writeByte(inv);
        return p;
    }

    /**
     * 完成整理包2
     *
     * @param inv 背包类型
     * @return 完成整理包2
     */
    public static Packet finishedSort2(int inv) {
        OutPacket p = OutPacket.create(SendOpcode.SORT_ITEM_RESULT);
        p.writeByte(0);
        p.writeByte(inv);
        return p;
    }

    /**
     * 物品特效包
     *
     * @param characterid 角色 ID
     * @param itemid      物品 ID
     * @return 物品特效包
     */
    public static Packet itemEffect(int characterid, int itemid) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_ITEM_EFFECT);
        p.writeInt(characterid);
        p.writeInt(itemid);
        return p;
    }

    /**
     * 物品过期包
     *
     * @param itemid 物品 ID
     * @return 物品过期包
     */
    public static Packet itemExpired(int itemid) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        p.writeByte(2);
        p.writeInt(itemid);
        return p;
    }

    /**
     * 获取物品消息包
     *
     * @param itemid 物品 ID
     * @return 物品消息包
     */
    public static Packet getItemMessage(int itemid) {
        OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        p.writeByte(7);
        p.writeInt(itemid);
        return p;
    }

    /**
     * 静默移除地图物品包
     *
     * @param objId 对象 ID
     * @return 静默移除地图物品包
     */
    public static Packet silentRemoveItemFromMap(int objId) {
        return removeItemFromMap(objId, 1, 0);
    }

    /**
     * animation: 0 - expire<br/> 1 - without animation<br/> 2 - pickup<br/> 4 -
     * explode<br/> cid is ignored for 0 and 1
     * 动画: 0 - 过期<br/> 1 - 无动画<br/> 2 - 拾取<br/> 4 - 爆炸<br/> cid 对于 0 和 1 被忽略
     *
     * @param objId     对象 ID
     * @param animation 动画类型
     * @param chrId     角色 ID
     * @return 移除地图物品包
     */
    public static Packet removeItemFromMap(int objId, int animation, int chrId) {
        return removeItemFromMap(objId, animation, chrId, false, 0);
    }

    /**
     * animation: 0 - expire<br/> 1 - without animation<br/> 2 - pickup<br/> 4 -
     * explode<br/> cid is ignored for 0 and 1.<br /><br />Flagging pet as true
     * will make a pet pick up the item.
     * 动画: 0 - 过期<br/> 1 - 无动画<br/> 2 - 拾取<br/> 4 - 爆炸<br/> cid 对于 0 和 1 被忽略。<br /><br />将 pet 标记为 true 将使宠物拾取物品。
     *
     * @param objId     对象 ID
     * @param animation 动画类型
     * @param chrId     角色 ID
     * @param pet       是否宠物
     * @param slot      槽位
     * @return 移除地图物品包
     */
    public static Packet removeItemFromMap(int objId, int animation, int chrId, boolean pet, int slot) {
        OutPacket p = OutPacket.create(SendOpcode.REMOVE_ITEM_FROM_MAP);
        p.writeByte(animation); // expire // 过期
        p.writeInt(objId);
        if (animation >= 2) {
            p.writeInt(chrId);
            if (pet) {
                p.writeByte(slot);
            }
        }
        return p;
    }

    /**
     * 从地图对象掉落物品包
     *
     * @param player   玩家
     * @param drop     掉落物
     * @param dropfrom 掉落起始点
     * @param dropto   掉落终点
     * @param mod      模式
     * @return 从地图对象掉落物品包
     */
    public static Packet dropItemFromMapObject(Character player, MapItem drop, Point dropfrom, Point dropto, byte mod) {
        int dropType = drop.getDropType();
        if (drop.hasClientsideOwnership(player) && dropType < 3) {
            dropType = 2;
        }

        OutPacket p = OutPacket.create(SendOpcode.DROP_ITEM_FROM_MAPOBJECT);
        p.writeByte(mod);
        p.writeInt(drop.getObjectId());
        p.writeBool(drop.getMeso() > 0); // 1 mesos, 0 item, 2 and above all item meso bag, // 1 金币, 0 物品, 2 及以上所有物品金币袋
        p.writeInt(drop.getItemId()); // drop object ID // 掉落对象 ID
        p.writeInt(drop.getClientsideOwnerId()); // owner charid/partyid :) // 拥有者 charid/partyid :)
        p.writeByte(dropType); // 0 = timeout for non-owner, 1 = timeout for non-owner's party, 2 = FFA, 3 = explosive/FFA // 0 = 非拥有者超时, 1 = 非拥有者队伍超时, 2 = 自由拾取, 3 = 爆炸/自由拾取
        p.writePos(dropto);
        p.writeInt(drop.getDropper().getObjectId()); // dropper oid, found thanks to Li Jixue // 掉落者 oid, 感谢 Li Jixue 发现

        if (mod != 2) {
            p.writePos(dropfrom);
            p.writeShort(0);//Fh?
        }
        if (drop.getMeso() == 0) {
            PacketHelper.addExpirationTime(p, drop.getItem().getExpiration());
        }
        p.writeByte(drop.isPlayerDrop() ? 0 : 1); //pet EQP pickup // 宠物装备拾取
        return p;
    }

    /**
     * 更新地图物品对象包
     *
     * @param drop          掉落物
     * @param giveOwnership 是否给予所有权
     * @return 更新地图物品对象包
     */
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

    /**
     * 设置额外吊坠槽位包
     *
     * @param toggleExtraSlot 是否切换额外槽位
     * @return 设置额外吊坠槽位包
     */
    public static Packet setExtraPendantSlot(boolean toggleExtraSlot) {
        final OutPacket p = OutPacket.create(SendOpcode.SET_EXTRA_PENDANT_SLOT);
        p.writeBool(toggleExtraSlot);
        return p;
    }
}
