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
package org.gms.server.maps;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.inventory.Inventory;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.ItemFactory;
import org.gms.client.inventory.manipulator.InventoryManipulator;
import org.gms.client.inventory.manipulator.KarmaManipulator;
import org.gms.client.processor.npc.FredrickProcessor;
import org.gms.config.GameConfig;
import org.gms.dao.entity.CharactersDO;
import org.gms.dao.entity.HiredMerchantItemsDO;
import org.gms.dao.entity.HiredMerchantTransactionsDO;
import org.gms.dao.entity.HiredMerchantsDO;
import org.gms.manager.ServerManager;
import org.gms.net.packet.Packet;
import org.gms.net.server.Server;
import org.gms.server.ItemInformationProvider;
import org.gms.server.Trade;
import org.gms.service.CharacterService;
import org.gms.service.HiredMerchantService;
import org.gms.util.PacketCreator;
import org.gms.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @author XoticStory
 * @author Ronan - concurrency protection
 */
public class HiredMerchant extends AbstractMapObject {
    private static final Logger log = LoggerFactory.getLogger(HiredMerchant.class);
    private static final int VISITOR_HISTORY_LIMIT = 10;
    private static final int BLACKLIST_LIMIT = 20;

    private final int ownerId;
    private final int itemId;
    private int mesos = 0;
    private final int channel;
    private final int world;
    private final long start;
    private String ownerName = "";
    private String description = "";
    private final List<PlayerShopItem> items = new LinkedList<>();
    private final List<Pair<String, Byte>> messages = new LinkedList<>();
    private final List<SoldItem> sold = new LinkedList<>();
    private final AtomicBoolean open = new AtomicBoolean();
    private boolean published = false;
    private MapleMap map;
    private final Visitor[] visitors = new Visitor[3];
    private final LinkedList<PastVisitor> visitorHistory = new LinkedList<>();
    private final LinkedHashSet<String> blacklist = new LinkedHashSet<>(); // 区分大小写的角色名
    private final Lock visitorLock = new ReentrantLock(true);
    private static final CharacterService characterService = ServerManager.getApplicationContext().getBean(CharacterService.class);
    private static final HiredMerchantService hiredMerchantService = ServerManager.getApplicationContext().getBean(HiredMerchantService.class);
    
    private int merchantId;

    private record Visitor(Character chr, Instant enteredAt) {}

    public record PastVisitor(String chrName, Duration visitDuration) {}

    public HiredMerchant(final Character owner, String desc, int itemId) {
        this.setPosition(owner.getPosition());
        this.start = System.currentTimeMillis();
        this.ownerId = owner.getId();
        this.channel = owner.getClient().getChannel();
        this.world = owner.getWorld();
        this.itemId = itemId;
        this.ownerName = owner.getName();
        this.description = desc;
        this.map = owner.getMap();
    }

    public HiredMerchant(HiredMerchantsDO dbInfo, String ownerName) {
        this.merchantId = dbInfo.getId();
        this.ownerId = dbInfo.getOwnerId();
        this.itemId = dbInfo.getItemId();
        this.channel = dbInfo.getChannel();
        this.world = dbInfo.getWorldId();
        this.start = (dbInfo.getStartTime() != null && dbInfo.getStartTime() > 0) ? dbInfo.getStartTime() : System.currentTimeMillis();
        this.ownerName = ownerName;
        this.description = dbInfo.getDescription();
        this.mesos = dbInfo.getMesos() != null ? dbInfo.getMesos().intValue() : 0;
        this.setPosition(new java.awt.Point(dbInfo.getX(), dbInfo.getY()));
        // 地图未在此处设置，必须手动设置
    }

    public void loadItemsFromDb(List<HiredMerchantItemsDO> dbItems) {
        synchronized (items) {
            items.clear();
            for (HiredMerchantItemsDO itemDO : dbItems) {
                if ("RETURNED".equals(itemDO.getStatus())) {
                    continue;
                }
                Item item = hiredMerchantService.deserializeItem(itemDO.getItemData());
                if (item != null) {
                    short bundles = itemDO.getBundles() != null ? itemDO.getBundles().shortValue() : 0;
                    int price = itemDO.getPrice() != null ? itemDO.getPrice() : 0;
                    
                    PlayerShopItem psi = new PlayerShopItem(item, bundles, price);
                    psi.setDbId(itemDO.getId());
                    
                    int sold = itemDO.getSoldQuantity() != null ? itemDO.getSoldQuantity() : 0;
                    
                    short currentBundles = (short) (bundles - sold);
                    if (currentBundles < 0) {
                        currentBundles = 0;
                    }
                    
                    psi.setBundles(currentBundles);
                    if (currentBundles == 0) {
                        psi.setDoesExist(false);
                    }
                    items.add(psi);
                }
            }
        }
    }
    
    public void loadSoldItems(List<HiredMerchantTransactionsDO> transactions) {
        synchronized (sold) {
            sold.clear();
            for (HiredMerchantTransactionsDO tx : transactions) {
                String buyerName = Character.getNameById(tx.getBuyerId());
                if (buyerName == null) buyerName = "未知买家";
                
                sold.add(new SoldItem(buyerName, tx.getItemId(), tx.getQuantity().shortValue(), tx.getTotalPrice().intValue()));
            }
        }
    }

    public int getMerchantId() {
        return merchantId;
    }

    public void setMerchantId(int merchantId) {
        this.merchantId = merchantId;
    }

    public long getStartTime() {
        return start;
    }

    public void broadcastToVisitorsThreadsafe(Packet packet) {
        visitorLock.lock();
        try {
            broadcastToVisitors(packet);
        } finally {
            visitorLock.unlock();
        }
    }

    private void broadcastToVisitors(Packet packet) {
        for (Visitor visitor : visitors) {
            if (visitor != null) {
                visitor.chr.sendPacket(packet);
            }
        }
    }

    public byte[] getShopRoomInfo() {
        visitorLock.lock();
        try {
            byte count = 0;
            if (this.isOpen()) {
                for (Visitor visitor : visitors) {
                    if (visitor != null) {
                        count++;
                    }
                }
            } else {
                count = (byte) (visitors.length + 1);
            }

            return new byte[]{count, (byte) (visitors.length + 1)};
        } finally {
            visitorLock.unlock();
        }
    }

    public boolean addVisitor(Character visitor) {
        visitorLock.lock();
        try {
            int i = this.getFreeSlot();
            if (i > -1) {
                visitors[i] = new Visitor(visitor, Instant.now());
                broadcastToVisitors(PacketCreator.hiredMerchantVisitorAdd(visitor, i + 1));
                this.getMap().broadcastMessage(PacketCreator.updateHiredMerchantBox(this));

                return true;
            }

            return false;
        } finally {
            visitorLock.unlock();
        }
    }

    public void removeVisitor(Character chr) {
        visitorLock.lock();
        try {
            int slot = getVisitorSlot(chr);
            if (slot < 0) { // 未找到
                return;
            }

            Visitor visitor = visitors[slot];
            if (visitor != null && visitor.chr.getId() == chr.getId()) {
                visitors[slot] = null;
                addVisitorToHistory(visitor);
                broadcastToVisitors(PacketCreator.hiredMerchantVisitorLeave(slot + 1));
                this.getMap().broadcastMessage(PacketCreator.updateHiredMerchantBox(this));
            }
        } finally {
            visitorLock.unlock();
        }
    }

    private void addVisitorToHistory(Visitor visitor) {
        Duration visitDuration = Duration.between(visitor.enteredAt, Instant.now());
        visitorHistory.addFirst(new PastVisitor(visitor.chr.getName(), visitDuration));
        while (visitorHistory.size() > VISITOR_HISTORY_LIMIT) {
            visitorHistory.removeLast();
        }
    }

    public int getVisitorSlotThreadsafe(Character visitor) {
        visitorLock.lock();
        try {
            return getVisitorSlot(visitor);
        } finally {
            visitorLock.unlock();
        }
    }

    private int getVisitorSlot(Character visitor) {
        for (int i = 0; i < 3; i++) {
            if (visitors[i] != null && visitors[i].chr.getId() == visitor.getId()) {
                return i;
            }
        }
        return -1; // 实际上是0，因为有+1。
    }

    private void removeAllVisitors() {
        visitorLock.lock();
        try {
            for (int i = 0; i < 3; i++) {
                Visitor visitor = visitors[i];

                if (visitor != null) {
                    final Character visitorChr = visitor.chr;
                    visitorChr.setHiredMerchant(null);
                    visitorChr.sendPacket(PacketCreator.leaveHiredMerchant(i + 1, 0x11));
                    visitorChr.sendPacket(PacketCreator.hiredMerchantMaintenanceMessage());
                    visitors[i] = null;
                    addVisitorToHistory(visitor);
                }
            }

            this.getMap().broadcastMessage(PacketCreator.updateHiredMerchantBox(this));
        } finally {
            visitorLock.unlock();
        }
    }

    private void removeOwner(Character owner) {
        if (owner.getHiredMerchant() == this) {
            owner.sendPacket(PacketCreator.hiredMerchantOwnerLeave());
            owner.sendPacket(PacketCreator.leaveHiredMerchant(0x00, 0x03));
            owner.setHiredMerchant(null);
        }
    }

    public void withdrawMesos(Character chr) {
        if (isOwner(chr)) {
            synchronized (items) {
                if (merchantId > 0) {
                    long withdrawn = hiredMerchantService.withdrawAllMesos(merchantId);
                    if (withdrawn > 0) {
                        chr.gainMeso((int) withdrawn, true);
                        chr.dropMessage(1, "已从雇佣商人取出" + withdrawn + "金币。");
                        this.mesos = 0;

                        // 重新加载物品列表，移除已结算的售罄物品
                        List<HiredMerchantItemsDO> dbItems = hiredMerchantService.getMerchantItems(merchantId);
                        loadItemsFromDb(dbItems);
                    }
                }
                // 如果有旧系统的金币，也一并取出
                chr.withdrawMerchantMesos();
            }
        }
    }

    public void takeItemBack(int slot, Character chr) {
        synchronized (items) {
            PlayerShopItem shopItem = items.get(slot);
            if (shopItem.isExist()) {
                if (shopItem.getBundles() > 0) {
                    Item iitem = shopItem.getItem().copy();
                    iitem.setQuantity((short) (shopItem.getItem().getQuantity() * shopItem.getBundles()));

                    if (!Inventory.checkSpot(chr, iitem)) {
                        chr.sendPacket(PacketCreator.serverNotice(1, "请确保背包有足够的空间来取回物品。"));
                        chr.sendPacket(PacketCreator.enableActions());
                        return;
                    }

                    InventoryManipulator.addFromDrop(chr.getClient(), iitem, true);
                }

                removeFromSlot(slot);
                
                // 更新数据库
                if (shopItem.getDbId() != null) {
                    HiredMerchantTransactionsDO transaction = HiredMerchantTransactionsDO.builder()
                            .merchantId(merchantId)
                            .itemId(shopItem.getItem().getItemId())
                            .buyerId(ownerId)
                            .type("REMOVE")
                            .quantity((int) (shopItem.getItem().getQuantity() * shopItem.getBundles()))
                            .timestamp(System.currentTimeMillis())
                            .build();
                    hiredMerchantService.removeItem(shopItem.getDbId(), transaction);
                }
                
                chr.sendPacket(PacketCreator.updateHiredMerchant(this, chr));
            }

            if (GameConfig.getServerBoolean("use_enforce_merchant_save")) {
                chr.saveCharToDB(false);
            }
        }
    }

    private static boolean canBuy(Client c, Item newItem) {    // 感谢 xiaokelvin (Conrad) 注意到这里泄露的测试代码
        return InventoryManipulator.checkSpace(c, newItem.getItemId(), newItem.getQuantity(), newItem.getOwner()) && InventoryManipulator.addFromDrop(c, newItem, false);
    }

    private int getQuantityLeft(int itemid) {
        synchronized (items) {
            int count = 0;

            for (PlayerShopItem mpsi : items) {
                if (mpsi.getItem().getItemId() == itemid) {
                    count += (mpsi.getBundles() * mpsi.getItem().getQuantity());
                }
            }

            return count;
        }
    }

    public void buy(Client c, int item, short quantity) {
        synchronized (items) {
            PlayerShopItem pItem = items.get(item);
            Item newItem = pItem.getItem().copy();

            newItem.setQuantity((short) ((pItem.getItem().getQuantity() * quantity)));
            if (quantity < 1 || !pItem.isExist() || pItem.getBundles() < quantity) {
                c.sendPacket(PacketCreator.enableActions());
                return;
            } else if (newItem.getInventoryType().equals(InventoryType.EQUIP) && newItem.getQuantity() > 1) {
                c.sendPacket(PacketCreator.enableActions());
                return;
            }

            KarmaManipulator.toggleKarmaFlagToUntradeable(newItem);

            long priceLong = (long) pItem.getPrice() * quantity;
            if (priceLong > Integer.MAX_VALUE || priceLong < 0) {
                c.getPlayer().dropMessage(1, "交易金额异常。");
                c.sendPacket(PacketCreator.enableActions());
                return;
            }
            int price = (int) priceLong;

            if (c.getPlayer().getMeso() >= price) {
                if (canBuy(c, newItem)) {
                    c.getPlayer().gainMeso(-price, false);
                    
                    // 使用配置的税率
                    int taxRate = GameConfig.getServerInt("hired_merchant_tax_rate", 0);
                    int fee = (int) ((long) price * taxRate / 100);
                    if (fee <= 0) fee = Trade.getFee(price);    //如果参数没有设置税率，则使用默认税率
                    price -= fee;

                    // 检查金币上限
                    long mesoLimit = GameConfig.getServerLong("hired_merchant_meso_limit", 2147483647L);
                    if (this.mesos + price > mesoLimit) {
                        c.getPlayer().dropMessage(1, "店主金币已达上限，无法购买。");
                        c.getPlayer().gainMeso(price + fee, false); // 退还金币
                        c.sendPacket(PacketCreator.enableActions());
                        return;
                    }

                    synchronized (sold) {
                        sold.add(new SoldItem(c.getPlayer().getName(), pItem.getItem().getItemId(), newItem.getQuantity(), price));
                    }

                    pItem.setBundles((short) (pItem.getBundles() - quantity));
                    if (pItem.getBundles() < 1) {
                        pItem.setDoesExist(false);
                    }

                    if (GameConfig.getServerBoolean("use_announce_shop_item_sold")) {   // 创意来自 Vcoc
                        announceItemSold(newItem, price, getQuantityLeft(pItem.getItem().getItemId()));
                    }

                    if (merchantId > 0) {
                        // 使用 processPurchase 方法统一处理事务
                        hiredMerchantService.processPurchase(
                                merchantId,
                                pItem.getDbId(),
                                pItem.getItem().getItemId(),
                                quantity,
                                pItem.getPrice(),
                                price,
                                c.getPlayer().getId()
                        );
                        
                        this.mesos += price;
                    } else {
                        Character owner = Server.getInstance().getWorld(world).getPlayerStorage().getCharacterByName(ownerName);
                        if (owner != null) {
                            owner.addMerchantMesos(price);
                        } else {
                            CharactersDO character = characterService.findById(ownerId);
                            if (character != null) {
                                long merchantMesos = character.getMerchantmesos() != null ? character.getMerchantmesos() : 0;
                                merchantMesos += price;
                                characterService.update(CharactersDO.builder()
                                        .id(ownerId)
                                        .merchantmesos((int) Math.min(merchantMesos, Integer.MAX_VALUE))
                                        .build());
                            }
                        }
                    }

                } else {
                    c.getPlayer().dropMessage(1, "你的背包已满。请在购买此物品前清理一个空位。");
                    c.sendPacket(PacketCreator.enableActions());
                    return;
                }
            } else {
                c.getPlayer().dropMessage(1, "你没有足够的金币购买此物品。");
                c.sendPacket(PacketCreator.enableActions());
                return;
            }
            try {
                this.saveItems(false);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void announceItemSold(Item item, int mesos, int inStore) {
        String qtyStr = (item.getQuantity() > 1) ? " x " + item.getQuantity() : "";

        Character player = Server.getInstance().getWorld(world).getPlayerStorage().getCharacterById(ownerId);
        if (player != null && player.isLoggedInWorld()) {
            player.dropMessage(6, "[雇佣商人] 物品 '" + ItemInformationProvider.getInstance().getName(item.getItemId()) + "'" + qtyStr + " 已以 " + mesos + " 金币售出。 (剩余 " + inStore + ")");
        }
    }

    public void forceClose() {
        forceClose(true);//不论何时由于什么原因关闭服务端，均不会取消雇佣商店
    }

    public void forceClose(boolean serverShutdown) {
        //Server.getInstance().getChannel(world, channel).removeHiredMerchant(ownerId);
        if (map != null) {
            map.broadcastMessage(PacketCreator.removeHiredMerchantBox(getOwnerId()));
            map.removeMapObject(this);
        }

        Character owner = Server.getInstance().getWorld(world).getPlayerStorage().getCharacterById(ownerId);

        log.info("强制关闭雇佣商店: ownerId={}, merchantId={}, serverShutdown={}", 
                ownerId, merchantId, serverShutdown);

        visitorLock.lock();
        try {
            setOpen(false);
            removeAllVisitors();

            if (owner != null && owner.isLoggedInWorld() && this == owner.getHiredMerchant()) {
                if (serverShutdown) {
                    removeOwner(owner);
                } else {
                    closeOwnerMerchant(owner);
                }
            }
        } finally {
            visitorLock.unlock();
        }

        Server.getInstance().getWorld(world).unregisterHiredMerchant(this);

        if (serverShutdown && merchantId > 0) {
            log.info("雇佣商店 {} 因服务器关闭而从内存移除，数据库状态保持 ACTIVE。", merchantId);
            map = null;
            return;
        }

        try {
            saveItems(true);
            synchronized (items) {
                items.clear();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            saveItemsToLocalFile();
        }

        if (!serverShutdown) {
            Character player = Server.getInstance().getWorld(world).getPlayerStorage().getCharacterById(ownerId);
            if (player != null) {
                player.setHasMerchant(false);
            } else {
                characterService.update(CharactersDO.builder()
                        .id(ownerId)
                        .hasmerchant(false)
                        .build());
            }
        }
        
        if (merchantId > 0 && !serverShutdown) {
            // 更新数据库中的商店状态
            HiredMerchantsDO merchantDO = HiredMerchantsDO.builder()
                    .id(merchantId)
                    .status("CLOSED")
                    .closeTime(System.currentTimeMillis())
                    .build();
            hiredMerchantService.updateMerchant(merchantDO);
            log.info("雇佣商店 {} 已在数据库中关闭。", merchantId);
        }

        map = null;
    }

    public void closeOwnerMerchant(Character chr) {
        if (this.isOwner(chr)) {
            this.closeShop(chr.getClient(), false);
            chr.setHasMerchant(false);
        }
    }

    private void closeShop(Client c, boolean timeout) {
        map.removeMapObject(this);
        map.broadcastMessage(PacketCreator.removeHiredMerchantBox(ownerId));
        c.getChannelServer().removeHiredMerchant(ownerId);

        this.removeAllVisitors();
        this.removeOwner(c.getPlayer());

        try {
            List<PlayerShopItem> copyItems = getItems();
            boolean fullInventory = false;
            if (check(c.getPlayer(), copyItems) && !timeout) {
                for (PlayerShopItem mpsi : copyItems) {
                    if (mpsi.isExist()) {
                        if (mpsi.getItem().getInventoryType().equals(InventoryType.EQUIP)) {
                            InventoryManipulator.addFromDrop(c, mpsi.getItem(), false);
                        } else {
                            InventoryManipulator.addById(c, mpsi.getItem().getItemId(), (short) (mpsi.getBundles() * mpsi.getItem().getQuantity()), mpsi.getItem().getOwner(), -1, mpsi.getItem().getFlag(), mpsi.getItem().getExpiration());
                        }

                        if (merchantId > 0 && mpsi.getDbId() != null) {
                            HiredMerchantTransactionsDO transaction = HiredMerchantTransactionsDO.builder()
                                    .merchantId(merchantId)
                                    .itemId(mpsi.getItem().getItemId())
                                    .buyerId(ownerId)
                                    .type("RETURN")
                                    .quantity((int) (mpsi.getItem().getQuantity() * mpsi.getBundles()))
                                    .timestamp(System.currentTimeMillis())
                                    .build();
                            hiredMerchantService.removeItem(mpsi.getDbId(), transaction);
                        }
                    }
                }

                synchronized (items) {
                    items.clear();
                }
            } else if (!timeout) {
                fullInventory = true;
            }

            try {
                this.saveItems(timeout);
            } catch (Exception e) {
                e.printStackTrace();
                saveItemsToLocalFile();
            }

            // 感谢 Rohenn 注意到关闭商店时可能出现的复制漏洞
            Character player = c.getWorldServer().getPlayerStorage().getCharacterById(ownerId);
            if (player != null) {
                player.setHasMerchant(false);
                if (fullInventory) {
                    player.dropMessage(1, "背包空间不足，道具和金币已存入弗雷德里克处，请前往取回。");
                }
            } else {
                characterService.update(CharactersDO.builder()
                        .id(ownerId)
                        .hasmerchant(false)
                        .build());
            }

            if (GameConfig.getServerBoolean("use_enforce_merchant_save")) {
                c.getPlayer().saveCharToDB(false);
            }

            synchronized (items) {
                items.clear();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        if (merchantId > 0) {
            // 关键修改：如果是服务器关闭期间，不要将状态设为 CLOSED
            if (Server.getInstance().isShutdown()) {
                log.info("服务器正在关闭，保留雇佣商店 {} 的 ACTIVE 状态。", merchantId);
            } else {
                log.info("服务器正在关闭，雇佣商店 {} 已设为 CLOSED 状态。", merchantId);
                // 更新数据库中的商店状态
                HiredMerchantsDO merchantDO = HiredMerchantsDO.builder()
                        .id(merchantId)
                        .status("CLOSED")
                        .closeTime(System.currentTimeMillis())
                        .build();
                hiredMerchantService.updateMerchant(merchantDO);
            }
        }

        Server.getInstance().getWorld(world).unregisterHiredMerchant(this);
    }

    public synchronized void visitShop(Character chr) {
        visitorLock.lock();
        try {
            if (this.isOwner(chr)) {
                this.setOpen(false);
                this.removeAllVisitors();

                chr.sendPacket(PacketCreator.getHiredMerchant(chr, this, false));
            } else if (!this.isOpen()) {
                chr.sendPacket(PacketCreator.getMiniRoomError(18));
                return;
            } else if (isBlacklisted(chr.getName())) {
                chr.sendPacket(PacketCreator.getMiniRoomError(17));
                return;
            } else if (!this.addVisitor(chr)) {
                chr.sendPacket(PacketCreator.getMiniRoomError(2));
                return;
            } else {
                chr.sendPacket(PacketCreator.getHiredMerchant(chr, this, false));
            }
            chr.setHiredMerchant(this);
        } finally {
            visitorLock.unlock();
        }
    }

    public String getOwner() {
        return ownerName;
    }

    public void clearItems() {
        synchronized (items) {
            items.clear();
        }
    }

    public int getOwnerId() {
        return ownerId;
    }

    public String getDescription() {
        return description;
    }

    public Character[] getVisitorCharacters() {
        visitorLock.lock();
        try {
            Character[] copy = new Character[3];
            for (int i = 0; i < visitors.length; i++) {
                Visitor visitor = visitors[i];
                if (visitor != null) {
                    copy[i] = visitor.chr;
                }
            }

            return copy;
        } finally {
            visitorLock.unlock();
        }
    }

    public List<PlayerShopItem> getItems() {
        synchronized (items) {
            return Collections.unmodifiableList(items);
        }
    }

    public boolean hasItem(int itemid) {
        for (PlayerShopItem mpsi : getItems()) {
            if (mpsi.getItem().getItemId() == itemid && mpsi.isExist() && mpsi.getBundles() > 0) {
                return true;
            }
        }

        return false;
    }

    public boolean addItem(PlayerShopItem item) {
        synchronized (items) {
            if (items.size() >= getOnSaleSlotMax()) {
                return false;
            }

            items.add(item);
            
            if (merchantId > 0) {
                // 添加物品到数据库
                HiredMerchantItemsDO itemDO = HiredMerchantItemsDO.builder()
                        .merchantId(merchantId)
                        .itemId(item.getItem().getItemId())
                        .quantity((int) item.getItem().getQuantity())
                        .soldQuantity(0)
                        .price(item.getPrice())
                        .bundles((int) item.getBundles())
                        .status("ON_SALE")
                        .itemData(hiredMerchantService.serializeItem(item.getItem()))
                        .build();
                
                HiredMerchantTransactionsDO transactionDO = HiredMerchantTransactionsDO.builder()
                        .merchantId(merchantId)
                        .buyerId(ownerId)
                        .type("ADD")
                        .quantity((int) item.getItem().getQuantity())
                        .timestamp(System.currentTimeMillis())
                        .build();
                
                hiredMerchantService.addItem(itemDO, transactionDO);
                item.setDbId(itemDO.getId());
            }
            
            return true;
        }
    }

    public void clearInexistentItems() {
        synchronized (items) {
            for (int i = items.size() - 1; i >= 0; i--) {
                if (!items.get(i).isExist()) {
                    items.remove(i);
                }
            }

            try {
                this.saveItems(false);
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    private void removeFromSlot(int slot) {
        items.remove(slot);

        try {
            this.saveItems(false);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private int getFreeSlot() {
        for (int i = 0; i < 3; i++) {
            if (visitors[i] == null) {
                return i;
            }
        }
        return -1;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isPublished() {
        return published;
    }

    public boolean isOpen() {
        return open.get();
    }

    public void setOpen(boolean set) {
        open.getAndSet(set);
        published = true;
    }

    public int getItemId() {
        return itemId;
    }

    public boolean isOwner(Character chr) {
        return chr.getId() == ownerId;
    }

    public void sendMessage(Character chr, String msg) {
        String message = chr.getName() + " : " + msg;
        byte slot = (byte) (getVisitorSlot(chr) + 1);

        synchronized (messages) {
            messages.add(new Pair<>(message, slot));
        }
        broadcastToVisitorsThreadsafe(PacketCreator.hiredMerchantChat(message, slot));
    }

    public List<PlayerShopItem> sendAvailableBundles(int itemid) {
        List<PlayerShopItem> list = new LinkedList<>();
        List<PlayerShopItem> all = new ArrayList<>();

        if (!open.get()) {
            return list;
        }

        synchronized (items) {
            all.addAll(items);
        }

        for (PlayerShopItem mpsi : all) {
            if (mpsi.getItem().getItemId() == itemid && mpsi.getBundles() > 0 && mpsi.isExist()) {
                list.add(mpsi);
            }
        }
        return list;
    }

    public void saveItems(boolean shutdown) {
        if (merchantId > 0) {
            return; // 新系统通过事务处理持久化
        }

        List<Pair<Item, InventoryType>> itemsWithType = new ArrayList<>();
        List<Short> bundles = new ArrayList<>();

        synchronized (items) {
            for (PlayerShopItem pItems : items) {
                Item newItem = pItems.getItem().copy();
                short newBundle = pItems.getBundles();

                if (newBundle > 0) {
                    itemsWithType.add(new Pair<>(newItem, newItem.getInventoryType()));
                    bundles.add(newBundle);
                }
            }
        }

        try {
            ItemFactory.MERCHANT.saveItems(itemsWithType, bundles, this.ownerId);
            FredrickProcessor.insertFredrickLog(this.ownerId);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static boolean check(Character chr, List<PlayerShopItem> items) {
        List<Pair<Item, InventoryType>> li = new ArrayList<>();
        for (PlayerShopItem item : items) {
            Item it = item.getItem().copy();
            it.setQuantity((short) (it.getQuantity() * item.getBundles()));

            li.add(new Pair<>(it, it.getInventoryType()));
        }

        return Inventory.checkSpotsAndOwnership(chr, li);
    }

    public int getChannel() {
        return channel;
    }

    public int getTimeOpen() {
        long now = System.currentTimeMillis();
        long durationMillis = GameConfig.getServerInt("hired_merchant_duration", 1440) * 60 * 1000L;

        double progress = (double)(now - start) / durationMillis;

        return (int) Math.ceil(progress * 1318);
    }

    public void clearMessages() {
        synchronized (messages) {
            messages.clear();
        }
    }

    public List<Pair<String, Byte>> getMessages() {
        synchronized (messages) {
            List<Pair<String, Byte>> msgList = new LinkedList<>();
            msgList.addAll(messages);

            return msgList;
        }
    }

    public List<PastVisitor> getVisitorHistory() {
        return Collections.unmodifiableList(visitorHistory);
    }

    public void addToBlacklist(String chrName) {
        visitorLock.lock();
        try {
            if (blacklist.size() >= BLACKLIST_LIMIT) {
                return;
            }
            blacklist.add(chrName);
        } finally {
            visitorLock.unlock();
        }
    }

    public void removeFromBlacklist(String chrName) {
        visitorLock.lock();
        try {
            blacklist.remove(chrName);
        } finally {
            visitorLock.unlock();
        }
    }

    public Set<String> getBlacklist() {
        return Collections.unmodifiableSet(blacklist);
    }

    private boolean isBlacklisted(String chrName) {
        visitorLock.lock();
        try {
            return blacklist.contains(chrName);
        } finally {
            visitorLock.unlock();
        }
    }

    public int getMapId() {
        return map.getId();
    }

    public MapleMap getMap() {
        return map;
    }

    public void setMap(MapleMap map) {
        this.map = map;
    }

    public List<SoldItem> getSold() {
        synchronized (sold) {
            return Collections.unmodifiableList(sold);
        }
    }

    public int getMesos() {
        return mesos;
    }

    @Override
    public MapObjectType getType() {
        return MapObjectType.HIRED_MERCHANT;
    }

    @Override
    public void sendDestroyData(Client client) {}

    @Override
    public void sendSpawnData(Client client) {
        client.sendPacket(PacketCreator.spawnHiredMerchantBox(this));
    }

    private void saveItemsToLocalFile() {
        try {
            java.io.File dir = new java.io.File("logs/merchant_backup");
            if (!dir.exists()) {
                dir.mkdirs();
            }
            java.io.File file = new java.io.File(dir, "merchant_" + ownerId + "_" + System.currentTimeMillis() + ".json");
            
            Map<String, Object> backupData = new HashMap<>();
            backupData.put("merchantId", merchantId);
            backupData.put("ownerId", ownerId);
            backupData.put("ownerName", ownerName);
            backupData.put("description", description);
            backupData.put("itemId", itemId);
            backupData.put("mesos", mesos);
            backupData.put("channel", channel);
            backupData.put("mapId", map != null ? map.getId() : 0);
            backupData.put("timestamp", System.currentTimeMillis());
            
            List<Map<String, Object>> itemList = new ArrayList<>();
            synchronized (items) {
                for (PlayerShopItem item : items) {
                    Map<String, Object> itemMap = new HashMap<>();
                    itemMap.put("itemId", item.getItem().getItemId());
                    itemMap.put("quantity", item.getItem().getQuantity());
                    itemMap.put("bundles", item.getBundles());
                    itemMap.put("price", item.getPrice());
                    itemMap.put("itemData", hiredMerchantService.serializeItem(item.getItem()));
                    itemList.add(itemMap);
                }
            }
            backupData.put("items", itemList);
            
            ObjectMapper mapper = new ObjectMapper();
            mapper.writeValue(file, backupData);
            
            System.err.println("雇佣商店物品已备份至 " + file.getAbsolutePath());
        } catch (Exception e) {
            System.err.println("雇佣商店物品备份失败。");
            e.printStackTrace();
        }
    }

    public class SoldItem {

        int itemid, mesos;
        short quantity;
        String buyer;

        public SoldItem(String buyer, int itemid, short quantity, int mesos) {
            this.buyer = buyer;
            this.itemid = itemid;
            this.quantity = quantity;
            this.mesos = mesos;
        }

        public String getBuyer() {
            return buyer;
        }

        public int getItemId() {
            return itemid;
        }

        public short getQuantity() {
            return quantity;
        }

        public int getMesos() {
            return mesos;
        }
    }

    public byte getOnSaleSlotMax() {
        return (byte) Math.max(GameConfig.getServerInt("hired_merchant_max_items", 16),255);
    }
}
