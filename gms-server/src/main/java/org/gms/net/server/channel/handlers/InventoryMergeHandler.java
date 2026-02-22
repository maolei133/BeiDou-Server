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
package org.gms.net.server.channel.handlers;

import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.inventory.Inventory;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.manipulator.InventoryManipulator;
import org.gms.config.GameConfig;
import org.gms.constants.inventory.ItemConstants;
import org.gms.net.AbstractPacketHandler;
import org.gms.net.packet.InPacket;
import org.gms.net.server.Server;
import org.gms.server.ItemInformationProvider;
import org.gms.util.PacketCreator;

public final class InventoryMergeHandler extends AbstractPacketHandler {

    @Override
    public final void handlePacket(InPacket p, Client c) {
        Character chr = c.getPlayer();
        p.readInt();
        chr.getAutoBanManager().setTimestamp(2, Server.getInstance().getCurrentTimestamp(), 4);

        if (!GameConfig.getServerBoolean("use_item_sort")) {
            c.sendPacket(PacketCreator.enableActions());
            return;
        }

        byte invType = p.readByte();
        if (invType < 1 || invType > 5) {
            c.disconnect(false, false);
            return;
        }

        InventoryType inventoryType = InventoryType.getByType(invType);
        Inventory inventory = c.getPlayer().getInventory(inventoryType);
        inventory.lockInventory();
        try {
            //------------------- RonanLana's SLOT MERGER -----------------

            ItemInformationProvider ii = ItemInformationProvider.getInstance();
            Item srcItem, dstItem;

            for (short dst = 1; dst <= inventory.getSlotLimit(); dst++) {
                dstItem = inventory.getItem(dst);
                if (dstItem == null) {
                    continue;
                }

                for (short src = (short) (dst + 1); src <= inventory.getSlotLimit(); src++) {
                    srcItem = inventory.getItem(src);
                    if (srcItem == null) {
                        continue;
                    }

                    if (dstItem.getItemId() != srcItem.getItemId()) {
                        continue;
                    }

                    // 检查是否为现金物品，如果是，则检查是否可堆叠
                    if (inventoryType == InventoryType.CASH) {
                        if (!ItemConstants.isRechargeable(dstItem.getItemId()) && ii.getSlotMax(c, dstItem.getItemId()) <= 1) {
                            continue;
                        }
                    }

                    // 检查拥有者是否一致，防止交换位置而不是合并
                    if (!dstItem.getOwner().equals(srcItem.getOwner())) {
                        continue;
                    }

                    if (dstItem.getQuantity() == ii.getSlotMax(c, inventory.getItem(dst).getItemId())) {
                        break;
                    }

                    InventoryManipulator.move(c, inventoryType, src, dst);
                }
            }

            //------------------------------------------------------------
            // 优化后的排序（填补空位）逻辑
            short nextFreeSlot = inventory.getNextFreeSlot();
            if (nextFreeSlot != -1) {
                for (short src = (short) (nextFreeSlot + 1); src <= inventory.getSlotLimit(); src++) {
                    if (inventory.getItem(src) != null) {
                        InventoryManipulator.move(c, inventoryType, src, nextFreeSlot);
                        
                        // 重新计算下一个空闲槽位，避免每次都从头扫描
                        while (nextFreeSlot <= inventory.getSlotLimit() && inventory.getItem(nextFreeSlot) != null) {
                            nextFreeSlot++;
                        }
                        
                        if (nextFreeSlot > inventory.getSlotLimit()) {
                            break;
                        }
                    }
                }
            }
        } finally {
            inventory.unlockInventory();
        }

        c.sendPacket(PacketCreator.finishedSort(inventoryType.getType()));
        c.sendPacket(PacketCreator.enableActions());
    }
}