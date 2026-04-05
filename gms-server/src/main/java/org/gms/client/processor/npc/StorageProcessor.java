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

import org.apache.logging.log4j.message.MapMessage;
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
import org.gms.manager.ServerManager;
import org.gms.net.packet.InPacket;
import org.gms.server.logging.AuditLogger;
import org.gms.server.logging.LogAction;
import org.gms.server.logging.LogModule;
import org.gms.service.TraceabilityService;
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
    private static final TraceabilityService traceabilityService = ServerManager.getApplicationContext().getBean(TraceabilityService.class);

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
            sendStorageError(c, StorageError.UNKNOWN);
            chr.dropMessage(1, "15级以后才可以使用仓库服务");
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
                        AuditLogger.info(LogModule.STORAGE, LogAction.STORAGE_OUT,
                                new MapMessage().with("msg", "检测到封包编辑").with("slot", slot));
                        c.disconnect(true, false);
                        return;
                    }

                    // 1. 获取目标物品在全局列表中的索引
                    byte globalSlot = storage.getSlot(InventoryType.getByType(type), slot);
                    
                    // 2. 获取物品对象
                    Item item = storage.getItem(globalSlot);

                    if (hasGMRestrictions(chr)) {
                        sendStorageError(c, StorageError.UNKNOWN);
                        chr.dropMessage(1, gmBlockedStorageMessage);
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
                            if (storage.takeOut(c, item)) {
                                chr.setUsedStorage();

                                KarmaManipulator.toggleKarmaFlagToUntradeable(item);
                                InventoryManipulator.addFromDrop(c, item, false);

                                traceabilityService.log(item, chr, TraceabilityService.ActionType.STORAGE, TraceabilityService.ActionSourceType.STORAGE_TAKE_OUT, item.getQuantity());

                                String itemName = ii.getName(item.getItemId());
                                // 发送提示消息
                                String feeMsg = takeoutFee > 0 ? " (手续费: " + takeoutFee + " 金币)" : "";
                                chr.dropMessage(5, "[仓库] 取出 " + itemName + " × " + item.getQuantity() + feeMsg);

                                storage.sendTakenOut(c, item.getInventoryType());
                            } else {
                                AuditLogger.error(LogModule.STORAGE, LogAction.STORAGE_OUT, "storage.takeOut 返回 false", null);
                                sendStorageError(c, StorageError.UNKNOWN);
                                return;
                            }
                        } else {
                            sendStorageError(c, StorageError.INVENTORY_FULL);
                        }
                    } else {
                        AuditLogger.info(LogModule.STORAGE, LogAction.STORAGE_OUT,
                                new MapMessage().with("msg", "未找到物品").with("slot", globalSlot));
                        sendStorageError(c, StorageError.UNKNOWN);
                        chr.dropMessage(1, "仓库中没有该物品");
                    }
                    break;
                }
                case 5: { // 存入物品
                    short slot = p.readShort();
                    int itemId = p.readInt();
                    short quantity = p.readShort();
                    short oldqty;
                    
                    InventoryType invType = ItemConstants.getInventoryType(itemId);
                    Inventory inv = chr.getInventory(invType);
                    if (slot < 1 || slot > inv.getSlotLimit()) { // 玩家背包从1开始
                        AutobanFactory.PACKET_EDIT.alert(c.getPlayer(),c.getPlayer().getName() + " 尝试通过仓库进行封包编辑。");
                        c.disconnect(true, false);
                        return;
                    }

                    if (hasGMRestrictions(chr)) {
                        sendStorageError(c, StorageError.UNKNOWN);
                        chr.dropMessage(1, gmBlockedStorageMessage);
                        return;
                    }

                    if (quantity < 1) {
                        sendStorageError(c, StorageError.UNKNOWN);
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
                                    sendStorageError(c, StorageError.UNKNOWN);
                                    return;
                                }
                                
                                // 检查：现金道具
                                if (ii.isCash(itemId)) {
                                    sendStorageError(c, StorageError.UNKNOWN); // 使用未知错误
                                    c.getPlayer().dropMessage(1, "现金道具无法存入仓库。");
                                    return;
                                }
                                
                                // 检查：不可存入的物品
                                // 规则：
                                // 1. 固有道具 (One-of-a-kind)
                                // 2. 不可交易 (Untradeable)
                                // 3. 合并不可交易 (Merge Untradeable)
                                // 满足任意一种即不可存入，除非：
                                // a. 有宿命剪刀 (Karma Scissors)
                                // b. 有账号共享标记 (Account Sharing)
                                boolean isOneOfAKind = ii.isPickupRestricted(itemId);
                                boolean isUntradeable = ItemConstants.isUntradeable(item.getFlag());
                                boolean isMergeUntradeable = (item.getFlag() & ItemConstants.MERGE_UNTRADEABLE) == ItemConstants.MERGE_UNTRADEABLE; // 假设有这个标记
                                boolean isDropRestricted = ii.isDropRestricted(itemId); // 通常也意味着不可交易

                                if (isOneOfAKind || isUntradeable || isMergeUntradeable || isDropRestricted) {
                                    boolean hasKarma = KarmaManipulator.hasKarmaFlag(item);
                                    boolean isAccountSharing = (item.getFlag() & ItemConstants.ACCOUNT_SHARING) == ItemConstants.ACCOUNT_SHARING;
                                    
                                    // 修正：如果不可丢弃物品标记为0，也可以存入
                                    // 注意：isDropRestricted 已经包含了不可丢弃的判断，但这里我们需要更细致的区分
                                    // 如果 isDropRestricted 为 true，但 flag 为 0，是否允许存入？
                                    // 原始需求：不可丢弃物品，如果标记为0，也是可以存入到仓库里的。
                                    // 这里的“标记为0”指的是 item.getFlag() == 0
                                    
                                    boolean isFlagZero = item.getFlag() == 0;

                                    if (!hasKarma && !isAccountSharing && !isFlagZero) {
                                        // 这里可以预留配置开关，例如 if (!GameConfig.getServerBoolean("allow_storage_untradeable"))
                                        sendStorageError(c, StorageError.UNKNOWN); // 使用未知错误
                                        c.getPlayer().dropMessage(1, "不可交易或固有道具无法存入仓库。");
                                        return;
                                    }
                                }
                                
                                // 检查：任务道具
                                if (ii.isQuestItem(itemId)) {
                                    sendStorageError(c, StorageError.UNKNOWN); // 使用未知错误
                                    c.getPlayer().dropMessage(1, "任务道具无法存入仓库。");
                                    return;
                                }

                                if (ItemConstants.isRechargeable(itemId)) {
                                    quantity = item.getQuantity();
                                }

                                InventoryManipulator.removeFromSlot(c, invType, slot, quantity, false);
                            } else {
                                sendStorageError(c, StorageError.UNKNOWN);
                                return;
                            }
                            oldqty = (short) (item.getQuantity() + quantity);
                            item = item.copy(); // 感谢 Robin Schulz & BHB88 注意到存入物品时的背包故障
                        } finally {
                            inv.unlockInventory();
                        }

                        chr.gainMeso(-storeFee, false, true, false);

                        KarmaManipulator.toggleKarmaFlagToUntradeable(item);
                        item.setQuantity(quantity);

                        if (storage.store(c, item)) { // 在临界区内，"!(storage.isFull())" 仍然有效...
                            chr.setUsedStorage();

                            traceabilityService.log(item, chr, TraceabilityService.ActionType.STORAGE, TraceabilityService.ActionSourceType.STORAGE_PUT_IN, -quantity,null,String.format("数量: %d -> %d",oldqty, oldqty - quantity));

                            String itemName = ii.getName(item.getItemId());
                            // 发送提示消息
                            String feeMsg = storeFee > 0 ? " (手续费: " + storeFee + " 金币)" : "";
                            chr.dropMessage(6, "[仓库] 存入 " + itemName + " × " + item.getQuantity() + feeMsg);
                            
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
                        sendStorageError(c, StorageError.UNKNOWN);
                        chr.dropMessage(1, gmBlockedStorageMessage);
                        return;
                    }

                    if ((meso > 0 && storageMesos >= meso) || (meso < 0 && playerMesos >= -meso)) {
                        if (meso < 0 && (storageMesos - meso) < 0) {
                            meso = Integer.MIN_VALUE + storageMesos;
                            if (meso < playerMesos) {
                                sendStorageError(c, StorageError.UNKNOWN);
                                return;
                            }
                        } else if (meso > 0 && (playerMesos + meso) < 0) {
                            meso = Integer.MAX_VALUE - playerMesos;
                            if (meso > storageMesos) {
                                sendStorageError(c, StorageError.UNKNOWN);
                                return;
                            }
                        }
                        storage.setMeso(storageMesos - meso);
                        chr.gainMeso(meso, false, true, false);
                        chr.setUsedStorage();

                        AuditLogger.info(LogModule.STORAGE, meso > 0 ? LogAction.STORAGE_OUT : LogAction.STORAGE_IN,
                                new MapMessage().with("meso", Math.abs(meso)));

                        // 发送提示消息
                        String action = meso > 0 ? "取出" : "存入";
                        int msgType = meso > 0 ? 5 : 6;
                        chr.dropMessage(msgType, "[仓库] " + action + " 金币 × " + Math.abs(meso));

                        storage.sendMeso(c);
                    } else {
                        sendStorageError(c, StorageError.UNKNOWN);
                        return;
                    }
                    break;
                }
                case 8: // 关闭 (除非玩家决定进入商城)
                    storage.close();
                    break;
                }
            } catch (Exception e) {
                sendStorageError(c, StorageError.UNKNOWN);
                chr.dropMessage(1, "仓库操作失败");
                // 异常日志：记录详细堆栈
                log.error("[Storage] 仓库操作异常: Char={}, Mode={}", chr.getName(), mode, e);
                AuditLogger.error(LogModule.STORAGE, LogAction.ERROR,
                        new MapMessage()
                                .with("msg", "仓库操作异常")
                                .with("mode", mode)
                                , e);
            } finally {
                c.releaseClient();
            }
        }
    }

    private static boolean hasGMRestrictions(Character character) {
        return character.isGM() && character.gmLevel() < GameConfig.getServerInt("minimum_gm_level_to_use_storage");
    }
}
