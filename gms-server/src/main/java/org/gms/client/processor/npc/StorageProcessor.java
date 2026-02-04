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
package org.gms.client.processor.npc;

import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.autoban.AutobanFactory;
import org.gms.client.inventory.Inventory;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.manipulator.InventoryManipulator;
import org.gms.client.inventory.manipulator.KarmaManipulator;
import org.gms.config.GameConfig;
import org.gms.constants.id.ItemId;
import org.gms.constants.inventory.ItemConstants;
import org.gms.net.packet.InPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.gms.server.ItemInformationProvider;
import org.gms.server.Storage;
import org.gms.util.PacketCreator;

/**
 * @author Matze
 * @author Ronan - inventory concurrency protection on storing items
 */
public class StorageProcessor {
    private static final Logger log = LoggerFactory.getLogger(StorageProcessor.class);

    /**
     * 仓库操作错误码枚举
     * 用于规范化错误处理，避免硬编码。
     */
    public enum StorageError {
        /** 未知错误 (0x00) */
        UNKNOWN(0x00),
        /** 解除UI锁 (0x09) */
        ENABLE_ACTIONS(0x09),
        /** 背包已满 (0x0A) */
        INVENTORY_FULL(0x0A),
        /** 金币不足 (0x0B) */
        NOT_ENOUGH_MESOS(0x0B),
        /** 只能持有一个 (0x0C) */
        ONE_OF_A_KIND(0x0C),
        /** 仓库已满 (0x11) */
        STORAGE_FULL(0x11);

        private final byte code;

        StorageError(int code) {
            this.code = (byte) code;
        }

        public byte getCode() {
            return code;
        }
    }

    /**
     * 发送仓库错误包
     * @param c 客户端
     * @param error 错误类型
     */
    private static void sendStorageError(Client c, StorageError error) {
        c.sendPacket(PacketCreator.getStorageError(error.getCode()));
    }

    public static void storageAction(InPacket p, Client c) {
        ItemInformationProvider ii = ItemInformationProvider.getInstance();
        Character chr = c.getPlayer();
        Storage storage = chr.getStorage();
        String gmBlockedStorageMessage = "当前GM级别禁止使用仓库";

        byte mode = p.readByte();

        if (chr.getLevel() < 15) {
            chr.dropMessage(1, "15级以后才可以使用仓库服务");
            c.enableActions();
            return;
        }

        if (c.tryacquireClient()) {
            try {
                switch (mode) {
                case 4: { // 取出物品
                    byte type = p.readByte();
                    byte slot = p.readByte();
                    if (slot < 0 || slot > storage.getSlots()) { // 索引从0开始
                        AutobanFactory.PACKET_EDIT.alert(c.getPlayer(), c.getPlayer().getName() + " 尝试通过仓库进行封包编辑。");
                        log.warn("角色 {} 尝试操作仓库槽位 {}", c.getPlayer().getName(), slot);
                        c.disconnect(true, false);
                        return;
                    }

                    slot = storage.getSlot(InventoryType.getByType(type), slot);
                    Item item = storage.getItem(slot);

                    if (hasGMRestrictions(chr)) {
                        chr.dropMessage(1, gmBlockedStorageMessage);
                        log.info("{} GM级别不够，无法使用仓库", chr.getName());
                        c.enableActions();
                        return;
                    }

                    if (item != null) {
                        if (ii.isPickupRestricted(item.getItemId()) && chr.haveItemWithId(item.getItemId(), true)) {
                            sendStorageError(c, StorageError.ONE_OF_A_KIND);
                            return;
                        }

                        int takeoutFee = storage.getTakeOutFee();
                        if (chr.getMeso() < takeoutFee) {
                            sendStorageError(c, StorageError.NOT_ENOUGH_MESOS);
                            return;
                        } else {
                            chr.gainMeso(-takeoutFee, false);
                        }

                        if (InventoryManipulator.checkSpace(c, item.getItemId(), item.getQuantity(), item.getOwner())) {
                            if (storage.takeOut(item)) {
                                chr.setUsedStorage();

                                KarmaManipulator.toggleKarmaFlagToUntradeable(item);
                                InventoryManipulator.addFromDrop(c, item, false);

                                String itemName = ii.getName(item.getItemId());
                                log.debug("角色 {} 取出了 {}x {} ({})", c.getPlayer().getName(), item.getQuantity(), itemName, item.getItemId());

                                storage.sendTakenOut(c, item.getInventoryType());
                            } else {
                                c.enableActions();
                                return;
                            }
                        } else {
                            sendStorageError(c, StorageError.INVENTORY_FULL);
                        }
                    }
                    break;
                }
                case 5: { // 存入物品
                    short slot = p.readShort();
                    int itemId = p.readInt();
                    short quantity = p.readShort();
                    InventoryType invType = ItemConstants.getInventoryType(itemId);
                    Inventory inv = chr.getInventory(invType);
                    if (slot < 1 || slot > inv.getSlotLimit()) { // 玩家背包从1开始
                        AutobanFactory.PACKET_EDIT.alert(c.getPlayer(),
                                c.getPlayer().getName() + " 尝试通过仓库进行封包编辑。");
                        log.warn("角色 {} 尝试存入物品到槽位 {}", c.getPlayer().getName(), slot);
                        c.disconnect(true, false);
                        return;
                    }

                    if (hasGMRestrictions(chr)) {
                        chr.dropMessage(1, gmBlockedStorageMessage);
                        log.info("{} GM级别不够，无法使用仓库", chr.getName());
                        c.enableActions();
                        return;
                    }

                    if (quantity < 1) {
                        c.enableActions();
                        return;
                    }
                    if (storage.isFull()) {
                        sendStorageError(c, StorageError.STORAGE_FULL);
                        return;
                    }
                    int storeFee = storage.getStoreFee();
                    if (chr.getMeso() < storeFee) {
                        sendStorageError(c, StorageError.NOT_ENOUGH_MESOS);
                    } else {
                        Item item;

                        inv.lockInventory(); // 感谢 imbee 指出仓库内的复制漏洞
                        try {
                            item = inv.getItem(slot);
                            if (item != null && item.getItemId() == itemId
                                    && (item.getQuantity() >= quantity || ItemConstants.isRechargeable(itemId))) {
                                if (ItemId.isWeddingRing(itemId) || ItemId.isWeddingToken(itemId)) {
                                    c.enableActions();
                                    return;
                                }
                                
                                // 检查：现金道具
                                if (ii.isCash(itemId)) {
                                    c.getPlayer().dropMessage(1, "现金道具无法存入仓库。");
                                    sendStorageError(c, StorageError.ENABLE_ACTIONS); // 使用无感解锁
                                    return;
                                }
                                
                                // 检查：不可交易 (包括固有道具等)
                                if (ItemConstants.isUntradeable(item.getFlag()) || ii.isDropRestricted(itemId)) {
                                    // 这里可以预留配置开关，例如 if (!GameConfig.getServerBoolean("allow_storage_untradeable"))
                                    c.getPlayer().dropMessage(1, "不可交易或固有道具无法存入仓库。");
                                    sendStorageError(c, StorageError.ENABLE_ACTIONS); // 使用无感解锁
                                    return;
                                }
                                
                                // 检查：任务道具
                                if (ii.isQuestItem(itemId)) {
                                    c.getPlayer().dropMessage(1, "任务道具无法存入仓库。");
                                    sendStorageError(c, StorageError.ENABLE_ACTIONS); // 使用无感解锁
                                    return;
                                }

                                if (ItemConstants.isRechargeable(itemId)) {
                                    quantity = item.getQuantity();
                                }

                                InventoryManipulator.removeFromSlot(c, invType, slot, quantity, false);
                            } else {
                                c.enableActions();
                                return;
                            }

                            item = item.copy(); // 感谢 Robin Schulz & BHB88 注意到存入物品时的背包故障
                        } finally {
                            inv.unlockInventory();
                        }

                        chr.gainMeso(-storeFee, false, true, false);

                        KarmaManipulator.toggleKarmaFlagToUntradeable(item);
                        item.setQuantity(quantity);

                        if (storage.store(c, item)) { // 在临界区内，"!(storage.isFull())" 仍然有效...
                            chr.setUsedStorage();

                            String itemName = ii.getName(item.getItemId());
                            log.debug("角色 {} 存入了 {}x {} ({})", c.getPlayer().getName(), item.getQuantity(), itemName, item.getItemId());
                            storage.sendStored(c, ItemConstants.getInventoryType(itemId));
                        } else {
                            // 存入失败（如仓库已满），退还费用并提示
                            chr.gainMeso(storeFee, false, true, false);
                            InventoryManipulator.addFromDrop(c, item, false); // 退还物品
                            sendStorageError(c, StorageError.STORAGE_FULL); // 仓库已满
                        }
                    }
                    break;
                }
                case 6: // 整理物品
                    if (GameConfig.getServerBoolean("use_storage_item_sort")) {
                        storage.arrangeItems(c);
                    }
                    c.enableActions();
                    break;
                case 7: { // 金币操作
                    int meso = p.readInt();
                    int storageMesos = storage.getMeso();
                    int playerMesos = chr.getMeso();

                    if (hasGMRestrictions(chr)) {
                        chr.dropMessage(1, gmBlockedStorageMessage);
                        log.info("{} GM级别不够，无法使用仓库", chr.getName());
                        c.enableActions();
                        return;
                    }

                    if ((meso > 0 && storageMesos >= meso) || (meso < 0 && playerMesos >= -meso)) {
                        if (meso < 0 && (storageMesos - meso) < 0) {
                            meso = Integer.MIN_VALUE + storageMesos;
                            if (meso < playerMesos) {
                                c.enableActions();
                                return;
                            }
                        } else if (meso > 0 && (playerMesos + meso) < 0) {
                            meso = Integer.MAX_VALUE - playerMesos;
                            if (meso > storageMesos) {
                                c.enableActions();
                                return;
                            }
                        }
                        storage.setMeso(storageMesos - meso);
                        chr.gainMeso(meso, false, true, false);
                        chr.setUsedStorage();
                        log.debug("角色 {} {} {} 金币", c.getPlayer().getName(), meso > 0 ? "取出了" : "存入了", Math.abs(meso));
                        storage.sendMeso(c);
                    } else {
                        c.enableActions();
                        return;
                    }
                    break;
                }
                case 8: // 关闭 (除非玩家决定进入商城)
                    storage.close();
                    break;
                }
            } catch (Exception e) {
                log.error("仓库操作失败", e);
                sendStorageError(c, StorageError.ENABLE_ACTIONS); // 发送无感解锁
            } finally {
                c.releaseClient();
            }
        }
    }

    private static boolean hasGMRestrictions(Character character) {
        return character.isGM() && character.gmLevel() < GameConfig.getServerInt("minimum_gm_level_to_use_storage");
    }
}
