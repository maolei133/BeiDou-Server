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
package org.gms.server;

import com.mybatisflex.core.query.QueryWrapper;
import org.apache.logging.log4j.message.MapMessage;
import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.inventory.Inventory;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.Pet;
import org.gms.client.inventory.manipulator.InventoryManipulator;
import org.gms.constants.id.ItemId;
import org.gms.constants.inventory.ItemConstants;
import org.gms.dao.entity.ShopitemsDO;
import org.gms.dao.entity.ShopsDO;
import org.gms.dao.mapper.ShopitemsMapper;
import org.gms.dao.mapper.ShopsMapper;
import org.gms.manager.ServerManager;
import org.gms.server.logging.AuditLogger;
import org.gms.server.logging.LogAction;
import org.gms.server.logging.LogModule;
import org.gms.service.TraceabilityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.gms.util.PacketCreator;
import org.gms.util.SpringContextUtil;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 游戏商店服务类
 * @author Matze
 */
public class Shop {
    private static final Logger log = LoggerFactory.getLogger(Shop.class);
    private static final TraceabilityService traceabilityService = ServerManager.getApplicationContext().getBean(TraceabilityService.class);
    private static final Set<Integer> rechargeableItems = new LinkedHashSet<>();

    private final int id;
    private final int npcId;
    private final List<ShopItem> items;
    private final int tokenvalue = 1000000000;
    private final int token = ItemId.GOLDEN_MAPLE_LEAF;

    static {
        for (int throwingStarId : ItemId.allThrowingStarIds()) {
            rechargeableItems.add(throwingStarId);
        }
        rechargeableItems.add(ItemId.BLAZE_CAPSULE);
        rechargeableItems.add(ItemId.GLAZE_CAPSULE);
        rechargeableItems.add(ItemId.BALANCED_FURY);
        rechargeableItems.remove(ItemId.DEVIL_RAIN_THROWING_STAR); // 实际不存在
        for (int bulletId : ItemId.allBulletIds()) {
            rechargeableItems.add(bulletId);
        }
    }

    private Shop(int id, int npcId) {
        this.id = id;
        this.npcId = npcId;
        items = new ArrayList<>();
    }

    private void addItem(ShopItem item) {
        items.add(item);
    }

    public void sendShop(Client c) {
        c.getPlayer().setShop(this);
        c.sendPacket(PacketCreator.getNPCShop(c, getNpcId(), items));
    }

    public void buy(Client c, short slot, int itemId, short quantity) {
        ShopItem item = findBySlot(slot);
        if (item != null) {
            if (item.getItemId() != itemId) {
                log.warn("商店 {} 中的物品栏位号错误", id);
                return;
            }
        } else {
            return;
        }
        ItemInformationProvider ii = ItemInformationProvider.getInstance();
        InventoryType type = ItemConstants.getInventoryType(itemId);
        Character chr = c.getPlayer();
        Inventory inv = chr.getInventory(type);
        inv.lockInventory();
        try {
            if (item.getPrice() > 0) {
                int amount = (int) Math.min((float) item.getPrice() * quantity, Integer.MAX_VALUE);
                if (c.getPlayer().getMeso() >= amount) {
                    if (InventoryManipulator.checkSpace(c, itemId, quantity, "")) {
                        if (!ItemConstants.isRechargeable(itemId)) { //宠物无法从商店购买
                            short finalQuantity = quantity;
                            int finalAmount = amount;
                            InventoryManipulator.addById(c, itemId, quantity, "", -1, (addedItem) -> {
                                // 溯源日志：商店购买
                                traceabilityService.log(addedItem, chr, TraceabilityService.ActionType.SHOP_BUY, "NPC商店购买", finalQuantity, "商店ID: " + id, "花费: " + finalAmount + "金币");
                            });
                            c.getPlayer().gainMeso(-amount, false);
                        } else {
                            quantity = ii.getSlotMax(c, item.getItemId());
                            short finalQuantity = quantity;
                            InventoryManipulator.addById(c, itemId, quantity, "", -1, (addedItem) -> {
                                // 溯源日志：商店购买 (充值类)
                                traceabilityService.log(addedItem, chr, TraceabilityService.ActionType.SHOP_BUY, "NPC商店购买", finalQuantity, "商店ID: " + id, "花费: " + item.getPrice() + "金币");
                            });
                            c.getPlayer().gainMeso(-item.getPrice(), false);
                        }
                        c.sendPacket(PacketCreator.shopTransaction((byte) 0));
                        AuditLogger.info(LogModule.SHOP, LogAction.SHOP_BUY, new MapMessage().with("itm", itemId).with("cnt", quantity).with("cost", amount));
                    } else {
                        c.sendPacket(PacketCreator.shopTransaction((byte) 3));
                    }

                } else {
                    c.sendPacket(PacketCreator.shopTransaction((byte) 2));
                }

            } else if (item.getPitch() > 0) {
                int amount = (int) Math.min((float) item.getPitch() * quantity, Integer.MAX_VALUE);

                if (c.getPlayer().getInventory(InventoryType.ETC).countById(ItemId.PERFECT_PITCH) >= amount) {
                    if (InventoryManipulator.checkSpace(c, itemId, quantity, "")) {
                        if (!ItemConstants.isRechargeable(itemId)) {
                            short finalQuantity = quantity;
                            int finalAmount = amount;
                            InventoryManipulator.addById(c, itemId, quantity, "", -1, (addedItem) -> {
                                traceabilityService.log(addedItem, chr, TraceabilityService.ActionType.SHOP_BUY, "NPC商店兑换(Pitch)", finalQuantity, "商店ID: " + id, "花费: " + finalAmount + " Pitch");
                            });
                            InventoryManipulator.removeById(c, InventoryType.ETC, ItemId.PERFECT_PITCH, amount, false, false);
                        } else {
                            short slotMax = ii.getSlotMax(c, item.getItemId());
                            quantity = slotMax;
                            short finalQuantity = quantity;
                            int finalAmount = amount;
                            InventoryManipulator.addById(c, itemId, quantity, "", -1, (addedItem) -> {
                                traceabilityService.log(addedItem, chr, TraceabilityService.ActionType.SHOP_BUY, "NPC商店兑换(Pitch)", finalQuantity, "商店ID: " + id, "花费: " + finalAmount + " Pitch");
                            });
                            InventoryManipulator.removeById(c, InventoryType.ETC, ItemId.PERFECT_PITCH, amount, false, false);
                        }
                        c.sendPacket(PacketCreator.shopTransaction((byte) 0));
                        AuditLogger.info(LogModule.SHOP, LogAction.SHOP_BUY, new MapMessage().with("itm", itemId).with("cnt", quantity).with("cost", amount).with("currency", "PITCH"));
                    } else {
                        c.sendPacket(PacketCreator.shopTransaction((byte) 3));
                    }
                }

            } else if (c.getPlayer().getInventory(InventoryType.CASH).countById(token) != 0) {
                int amount = c.getPlayer().getInventory(InventoryType.CASH).countById(token);
                int value = amount * tokenvalue;
                int cost = item.getPrice() * quantity;
                if (c.getPlayer().getMeso() + value >= cost) {
                    int cardreduce = value - cost;
                    int diff = cardreduce + c.getPlayer().getMeso();
                    if (InventoryManipulator.checkSpace(c, itemId, quantity, "")) {
                        short finalQuantity = quantity;
                        int finalCost = cost;
                        if (ItemConstants.isPet(itemId)) {
                            int petid = Pet.createPet(itemId);
                            InventoryManipulator.addById(c, itemId, quantity, "", petid, -1, (addedItem) -> {
                                traceabilityService.log(addedItem, chr, TraceabilityService.ActionType.SHOP_BUY, "NPC商店购买(Token)", finalQuantity, "商店ID: " + id, "花费: " + finalCost + " Token");
                            });
                        } else {
                            InventoryManipulator.addById(c, itemId, quantity, "", -1, -1, (addedItem) -> {
                                traceabilityService.log(addedItem, chr, TraceabilityService.ActionType.SHOP_BUY, "NPC商店购买(Token)", finalQuantity, "商店ID: " + id, "花费: " + finalCost + " Token");
                            });
                        }
                        c.getPlayer().gainMeso(diff, false);
                    } else {
                        c.sendPacket(PacketCreator.shopTransaction((byte) 3));
                    }
                    c.sendPacket(PacketCreator.shopTransaction((byte) 0));
                    AuditLogger.info(LogModule.SHOP, LogAction.SHOP_BUY, new MapMessage().with("itm", itemId).with("cnt", quantity).with("cost", cost).with("currency", "TOKEN"));
                } else {
                    c.sendPacket(PacketCreator.shopTransaction((byte) 2));
                }
            }
        } finally {
            inv.unlockInventory();
        }

    }

    private static boolean canSell(Item item, short quantity) {
        if (item == null) { //基础检查
            return false;
        }

        short iQuant = item.getQuantity();
        if (iQuant == 0xFFFF) {
            iQuant = 1;
        } else if (iQuant < 0) {
            return false;
        }

        if (!ItemConstants.isRechargeable(item.getItemId())) {
            return iQuant != 0 && quantity <= iQuant;
        }

        return true;
    }

    private static short getSellingQuantity(Item item, short quantity) {
        if (ItemConstants.isRechargeable(item.getItemId())) {
            quantity = item.getQuantity();
            if (quantity == 0xFFFF) {
                quantity = 1;
            }
        }

        return quantity;
    }

    public void sell(Client c, InventoryType type, short slot, short quantity) {
        if (quantity == 0xFFFF || quantity == 0) {
            quantity = 1;
        } else if (quantity < 0) {
            return;
        }

        Inventory inventory = c.getPlayer().getInventory(type);
        Item item = inventory.getItem(slot);
        inventory.lockInventory();
        try {
            if (canSell(item, quantity)) {
                // 物品找回系统拦截点
                if (InventoryManipulator.isValuableForRecovery(item)) {
                    TraceabilityService traceabilityService = SpringContextUtil.getBean(TraceabilityService.class);
                    traceabilityService.logRecovery(item, c.getPlayer(), "SELL");
                }

                quantity = getSellingQuantity(item, quantity);
                
                // 溯源日志：商店出售
                traceabilityService.log(item, c.getPlayer(), TraceabilityService.ActionType.SHOP_SELL, "NPC商店出售", -quantity, "商店ID: " + id, null);

                InventoryManipulator.removeFromSlot(c, type, (byte) slot, quantity, false);

                ItemInformationProvider ii = ItemInformationProvider.getInstance();
                int recvMesos = ii.getPrice(item.getItemId(), quantity);
                if (recvMesos > 0) {
                    c.getPlayer().gainMeso(recvMesos, false);
                }
                c.sendPacket(PacketCreator.shopTransaction((byte) 0x8));
                AuditLogger.info(LogModule.SHOP, LogAction.SHOP_SELL, new MapMessage().with("itm", item.getItemId()).with("cnt", quantity).with("gain", recvMesos));
            } else {
                c.sendPacket(PacketCreator.shopTransaction((byte) 0x5));
            }
        } finally {
            inventory.unlockInventory();
        }
    }

    public void recharge(Client c, short slot) {
        ItemInformationProvider ii = ItemInformationProvider.getInstance();
        Inventory inventory = c.getPlayer().getInventory(InventoryType.USE);
        Item item = inventory.getItem(slot);
        if (item == null || !ItemConstants.isRechargeable(item.getItemId())) {
            return;
        }
        short slotMax = ii.getSlotMax(c, item.getItemId());
        if (item.getQuantity() < 0) {
            return;
        }
        inventory.lockInventory();
        try {
            if (item.getQuantity() < slotMax) {
                int price = (int) Math.ceil(ii.getUnitPrice(item.getItemId()) * (slotMax - item.getQuantity()));
                if (c.getPlayer().getMeso() >= price) {
                    item.setQuantity(slotMax);
                    c.getPlayer().forceUpdateItem(item);
                    c.getPlayer().gainMeso(-price, false, true, false);
                    c.sendPacket(PacketCreator.shopTransaction((byte) 0x8));
                    AuditLogger.info(LogModule.SHOP, LogAction.SHOP_RECHARGE, new MapMessage().with("itm", item.getItemId()).with("cost", price));
                } else {
                    c.sendPacket(PacketCreator.shopTransaction((byte) 0x2));
                }
            }
        } finally {
            inventory.unlockInventory();
        }

    }

    private ShopItem findBySlot(short slot) {
        return items.get(slot);
    }

    public static Shop createFromDB(int id, boolean isShopId) {
        ShopsMapper shopsMapper = SpringContextUtil.getBean(ShopsMapper.class);
        ShopitemsMapper shopitemsMapper = SpringContextUtil.getBean(ShopitemsMapper.class);

        ShopsDO shopData;
        if (isShopId) {
            shopData = shopsMapper.selectOneById(id);
        } else {
            QueryWrapper query = QueryWrapper.create().where(ShopsDO::getNpcid).eq(id);
            shopData = shopsMapper.selectOneByQuery(query);
        }

        if (shopData == null) {
            return null;
        }

        int shopId = shopData.getShopid().intValue();
        Shop ret = new Shop(shopId, shopData.getNpcid());

        QueryWrapper itemsQuery = QueryWrapper.create()
                .where(ShopitemsDO::getShopid).eq(shopId)
                .orderBy(ShopitemsDO::getPosition, false);
        List<ShopitemsDO> itemsData = shopitemsMapper.selectListByQuery(itemsQuery);

        List<Integer> recharges = new ArrayList<>(rechargeableItems);
        for (ShopitemsDO itemData : itemsData) {
            if (ItemConstants.isRechargeable(itemData.getItemid())) {
                ShopItem starItem = new ShopItem((short) 1, itemData.getItemid(), itemData.getPrice(), itemData.getPitch());
                ret.addItem(starItem);
                recharges.remove(Integer.valueOf(starItem.getItemId()));
            } else {
                ret.addItem(new ShopItem((short) 1000, itemData.getItemid(), itemData.getPrice(), itemData.getPitch()));
            }
        }

        for (Integer recharge : recharges) {
            ret.addItem(new ShopItem((short) 1000, recharge, 0, 0));
        }

        return ret;
    }

    public int getNpcId() {
        return npcId;
    }

    public int getId() {
        return id;
    }
}
