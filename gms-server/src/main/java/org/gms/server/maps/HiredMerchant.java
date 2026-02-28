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
import org.gms.server.TimerManager;
import org.gms.server.Trade;
import org.gms.service.CharacterService;
import org.gms.service.HiredMerchantService;
import org.gms.service.TraceabilityService;
import org.gms.util.PacketCreator;
import org.gms.util.Pair;
import org.gms.util.SnowflakeIdGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 雇佣商店（Hired Merchant）
 * <p>
 * 代表游戏地图中的一个雇佣商店实例。
 * 负责处理商店的开张、关闭、物品买卖、访客管理以及与数据库的交互。
 * </p>
 *
 * @author XoticStory
 * @author Ronan - 并发保护
 */
public class HiredMerchant extends AbstractMapObject {
    private static final Logger log = LoggerFactory.getLogger(HiredMerchant.class);
    /** 访客历史记录最大数量 */
    private static final int VISITOR_HISTORY_LIMIT = 10;
    /** 黑名单最大数量 */
    private static final int BLACKLIST_LIMIT = 20;

    /** 店主角色ID */
    private final int ownerId;
    /** 商店外观道具ID */
    private final int itemId;
    /** 当前商店内的金币（未取回） */
    private int mesos = 0;
    /** 所在频道 */
    private final int channel;
    /** 所在世界 */
    private final int world;
    /** 开店时间戳 */
    private final long start;
    /** 店主名称 */
    private String ownerName = "";
    /** 商店描述/名称 */
    private String description = "";
    /** 商店内的物品列表 */
    private final List<PlayerShopItem> items = new LinkedList<>();
    /** 聊天消息记录 */
    private final List<Pair<String, Byte>> messages = new LinkedList<>();
    /** 已售出物品记录 */
    private final List<SoldItem> sold = new LinkedList<>();
    /** 商店是否开启状态 */
    private final AtomicBoolean open = new AtomicBoolean();
    /** 商店是否已发布（正式营业） */
    private boolean published = false;
    /** 所在地图对象 */
    private MapleMap map;
    /** 当前访客列表（最多3人） */
    private final Visitor[] visitors = new Visitor[3];
    /** 访客历史记录 */
    private final LinkedList<PastVisitor> visitorHistory = new LinkedList<>();
    /** 黑名单列表（角色名） */
    private final LinkedHashSet<String> blacklist = new LinkedHashSet<>();
    /** 访客操作锁 */
    private final Lock visitorLock = new ReentrantLock(true);
    /** 角色服务 */
    private static final CharacterService characterService = ServerManager.getApplicationContext().getBean(CharacterService.class);
    /** 雇佣商店服务 */
    private static final HiredMerchantService hiredMerchantService = ServerManager.getApplicationContext().getBean(HiredMerchantService.class);
    /** 溯源服务 */
    private static final TraceabilityService traceabilityService = ServerManager.getApplicationContext().getBean(TraceabilityService.class);
    
    /** 数据库中的商店ID */
    private int merchantId;
    /** 定时关闭任务 */
    private ScheduledFuture<?> closeSchedule = null;
    
    /** 总销售额（税前） */
    private long totalSales = 0;
    /** 总收入（税后） */
    private long totalRevenue = 0;

    /** 访客记录内部类 */
    private record Visitor(Character chr, Instant enteredAt) {}

    /** 历史访客记录内部类 */
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
        this.scheduleClose();
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
        // 注意：这里不调用 scheduleClose，因为在 World.loadActiveHiredMerchants 中会统一调用
    }

    public void loadItemsFromDb(List<HiredMerchantItemsDO> dbItems) {
        synchronized (items) {
            items.clear();
            for (HiredMerchantItemsDO itemDO : dbItems) {
                if (HiredMerchantItemsDO.STATUS_RETURNED.equals(itemDO.getStatus())) {
                    continue;
                }
                Item item = hiredMerchantService.deserializeItem(itemDO.getItemData());
                if (item != null) {
                    // 恢复 UID
                    if (itemDO.getUid() != null && itemDO.getUid() > 0) {
                        item.setUid(itemDO.getUid());
                    } else {
                        // 兼容旧数据，生成新 UID
                        item.setUid(SnowflakeIdGenerator.getInstance().nextId());
                    }
                    
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
            totalSales = 0;
            totalRevenue = 0;
            for (HiredMerchantTransactionsDO tx : transactions) {
                String buyerName = Character.getNameById(tx.getBuyerId());
                if (buyerName == null) buyerName = "未知买家";
                
                sold.add(new SoldItem(buyerName, tx.getItemId(), tx.getQuantity().shortValue(), tx.getTotalPrice().intValue()));
                
                long txPrice = tx.getPrice() != null ? tx.getPrice() : 0;
                long txQty = tx.getQuantity() != null ? tx.getQuantity() : 0;
                long txTotal = tx.getTotalPrice() != null ? tx.getTotalPrice() : 0;
                
                totalSales += txPrice * txQty;
                totalRevenue += txTotal;
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
                    
                    // 记录溯源日志
                    traceabilityService.log(iitem, chr, TraceabilityService.ActionType.HIRED_MERCHANT_RETURN, "雇佣商店取回");
                }

                removeFromSlot(slot);
                
                // 更新数据库
                if (shopItem.getDbId() != null) {
                    HiredMerchantTransactionsDO transaction = HiredMerchantTransactionsDO.builder()
                            .merchantId(merchantId)
                            .itemId(shopItem.getItem().getItemId())
                            .buyerId(ownerId)
                            .type(HiredMerchantTransactionsDO.TYPE_REMOVE)
                            .quantity((int) (shopItem.getItem().getQuantity() * shopItem.getBundles()))
                            .timestamp(System.currentTimeMillis())
                            .uid(shopItem.getItem().getUid()) // 记录 UID
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
            Character chr = c.getPlayer();

            if (chr.getMeso() >= price) {
                if (canBuy(c, newItem)) {
                    chr.gainMeso(-price, false);
                    
                    // 使用配置的税率
                    int taxRate = GameConfig.getServerInt("hired_merchant_tax_rate", 0);
                    int fee = (int) ((long) price * taxRate / 100);
                    if (fee <= 0) fee = Trade.getFee(price);    //如果参数没有设置税率，则使用默认税率
                    price -= fee;

                    // 检查金币上限
                    long mesoLimit = GameConfig.getServerLong("hired_merchant_meso_limit", 2147483647L);
                    if (this.mesos + price > mesoLimit) {
                        chr.dropMessage(1, "店主金币已达上限，无法购买。");
                        chr.gainMeso(price + fee, false); // 退还金币
                        c.sendPacket(PacketCreator.enableActions());
                        return;
                    }

                    synchronized (sold) {
                        sold.add(new SoldItem(chr.getName(), pItem.getItem().getItemId(), newItem.getQuantity(), (int) priceLong));
                    }
                    
                    this.totalSales += priceLong;
                    this.totalRevenue += price;

                    pItem.setBundles((short) (pItem.getBundles() - quantity));
                    if (pItem.getBundles() < 1) {
                        pItem.setDoesExist(false);
                    }

                    if (GameConfig.getServerBoolean("use_announce_shop_item_sold")) {   // 创意来自 Vcoc
                        announceItemSold(newItem, price, priceLong, chr.getName(), getQuantityLeft(pItem.getItem().getItemId()));
                    }
                    
                    // 记录溯源日志
                    traceabilityService.log(newItem, chr, TraceabilityService.ActionType.HIRED_MERCHANT_BUY, "雇佣商店购买", newItem.getQuantity(), "店主: " + ownerName, "价格: " + price);

                    if (merchantId > 0) {
                        // 使用 processPurchase 方法统一处理事务
                        hiredMerchantService.processPurchase(
                                merchantId,
                                pItem.getDbId(),
                                pItem.getItem().getItemId(),
                                quantity,
                                pItem.getPrice(),
                                price,
                                chr.getId()
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
                    chr.dropMessage(1, "你的背包已满。请在购买此物品前清理一个空位。");
                    c.sendPacket(PacketCreator.enableActions());
                    return;
                }
            } else {
                chr.dropMessage(1, "你没有足够的金币购买此物品。");
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

    private void announceItemSold(Item item, int mesos, long totalSales, String buyerName, int inStore) {
        String qtyStr = (item.getQuantity() > 1) ? " x " + item.getQuantity() : "";
        String itemName = ItemInformationProvider.getInstance().getName(item.getItemId());
        String remainStr = (inStore > 0) ? "剩余 " + inStore + " 件" : "已售罄";
        String merchantItemName = ItemInformationProvider.getInstance().getName(itemId);

        Character player = Server.getInstance().getWorld(world).getPlayerStorage().getCharacterById(ownerId);
        if (player != null && player.isLoggedInWorld()) {
            player.dropMessage(6, "[雇佣商店] " + merchantItemName + "：您的物品 " + itemName + " 已被 " + buyerName + " 买走了 " + item.getQuantity() + "件 ，售价 " + totalSales + "金币，税后收入 " + mesos + "金币 ，【" + remainStr + "】");
        }
    }

    public void forceClose() {
        forceClose(Server.getInstance().isShutdown());
    }

    public void forceClose(boolean serverShutdown) {
        if (Server.getInstance().isShutdown()) {
            serverShutdown = true;
        }
        //Server.getInstance().getChannel(world, channel).removeHiredMerchant(ownerId);
        if (map != null) {
            map.broadcastMessage(PacketCreator.removeHiredMerchantBox(getOwnerId()));
            map.removeMapObject(this);
        }

        Character owner = Server.getInstance().getWorld(world).getPlayerStorage().getCharacterById(ownerId);

//        log.info("强制关闭雇佣商店: ownerId={}, merchantId={}, ownerName={}, description={}, serverShutdown={}",
//                ownerId, merchantId, ownerName, description, serverShutdown);

        boolean closedByOwner = false;
        visitorLock.lock();
        try {
            setOpen(false);
            removeAllVisitors();

            if (owner != null && owner.isLoggedInWorld() && this == owner.getHiredMerchant()) {
                if (serverShutdown) {
                    removeOwner(owner);
                } else {
                    closeOwnerMerchant(owner);
                    closedByOwner = true;
                }
            }
        } finally {
            visitorLock.unlock();
        }

        if (closeSchedule != null) {
            closeSchedule.cancel(false);
            closeSchedule = null;
        }

        if (closedByOwner) {
            map = null;
            return;
        }

        try {
            Server.getInstance().getWorld(world).unregisterHiredMerchant(this);
            Server.getInstance().getChannel(world, channel).removeHiredMerchant(ownerId);
        } catch (Exception e) {
            log.warn("从频道服务器移除雇佣商店失败", e);
        }

        if (serverShutdown && merchantId > 0) {
            log.info("雇佣商店 {} 因服务器关闭而从内存移除，数据库状态保持 ACTIVE。店主: {}, 店名: {}", merchantId, ownerName, description);
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
                player.dropMessage(6, "[雇佣商店] 您的商店已到期自动闭店，请前往弗雷德里克处领取物品和金币。");
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
                    .status(HiredMerchantsDO.STATUS_CLOSED)
                    .closeTime(System.currentTimeMillis())
                    .build();
            hiredMerchantService.updateMerchant(merchantDO);
//            log.info("雇佣商店 {} 已在数据库中关闭。店主: {}, 店名: {}", merchantId, ownerName, description);
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
        if (map != null) {
            map.removeMapObject(this);
            map.broadcastMessage(PacketCreator.removeHiredMerchantBox(ownerId));
        }
        c.getChannelServer().removeHiredMerchant(ownerId);

        this.removeAllVisitors();
        this.removeOwner(c.getPlayer());

        if (closeSchedule != null) {
            closeSchedule.cancel(false);
            closeSchedule = null;
        }

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
                        
                        // 记录溯源日志
                        traceabilityService.log(mpsi.getItem(), c.getPlayer(), TraceabilityService.ActionType.HIRED_MERCHANT_RETURN, "雇佣商店关闭取回");

                        if (merchantId > 0 && mpsi.getDbId() != null) {
                            HiredMerchantTransactionsDO transaction = HiredMerchantTransactionsDO.builder()
                                    .merchantId(merchantId)
                                    .itemId(mpsi.getItem().getItemId())
                                    .buyerId(ownerId)
                                    .type(HiredMerchantTransactionsDO.TYPE_RETURN)
                                    .quantity((int) (mpsi.getItem().getQuantity() * mpsi.getBundles()))
                                    .timestamp(System.currentTimeMillis())
                                    .uid(mpsi.getItem().getUid()) // 记录 UID
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
            long durationMillis = getDuration();
            long remainingMillis = (start + durationMillis) - System.currentTimeMillis();
            String remainingTimeStr = (remainingMillis > 0) ? (remainingMillis / 1000 / 60) + "分钟" : "已过期";

            // 关键修改：如果是服务器关闭期间，不要将状态设为 CLOSED
            if (Server.getInstance().isShutdown()) {
                log.info("服务器正在关闭，保留雇佣商店 {} 的 ACTIVE 状态。店主: {}, 店名: {}, 剩余时间: {}", 
                        merchantId, ownerName, description, remainingTimeStr);
            } else {
                log.info("雇佣商店 {} 已设为 CLOSED 状态。店主: {}, 店名: {}",
                        merchantId, ownerName, description);
                // 更新数据库中的商店状态
                HiredMerchantsDO merchantDO = HiredMerchantsDO.builder()
                        .id(merchantId)
                        .status(HiredMerchantsDO.STATUS_CLOSED)
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
            
            // 确保 UID 存在
            if (item.getItem().getUid() == 0) {
                item.getItem().setUid(SnowflakeIdGenerator.getInstance().nextId());
            }

            // items.add(item); // 移动到数据库操作之后
            
            if (merchantId > 0) {
                try {
                    // 添加物品到数据库
                    HiredMerchantItemsDO itemDO = HiredMerchantItemsDO.builder()
                            .merchantId(merchantId)
                            .itemId(item.getItem().getItemId())
                            .quantity((int) item.getItem().getQuantity())
                            .soldQuantity(0)
                            .price(item.getPrice())
                            .bundles((int) item.getBundles())
                            .status(HiredMerchantItemsDO.STATUS_ON_SALE)
                            .itemData(hiredMerchantService.serializeItem(item.getItem()))
                            .uid(item.getItem().getUid()) // 记录 UID
                            .build();
                    
                    HiredMerchantTransactionsDO transactionDO = HiredMerchantTransactionsDO.builder()
                            .merchantId(merchantId)
                            .buyerId(ownerId)
                            .type(HiredMerchantTransactionsDO.TYPE_ADD)
                            .quantity((int) item.getItem().getQuantity())
                            .timestamp(System.currentTimeMillis())
                            .uid(item.getItem().getUid()) // 记录 UID
                            .build();
                    
                    hiredMerchantService.addItem(itemDO, transactionDO);
                    item.setDbId(itemDO.getId());
                } catch (Exception e) {
                    log.error("添加物品到雇佣商店失败: merchantId={}, itemId={}, uid={}", merchantId, item.getItem().getItemId(), item.getItem().getUid(), e);
                    return false; // 数据库操作失败，返回 false，不更新内存，不移除背包物品
                }
            }

            items.add(item); // 数据库操作成功后，再添加到内存
            
            // 记录溯源日志
            Character owner = Server.getInstance().getWorld(world).getPlayerStorage().getCharacterById(ownerId);
            if (owner != null) {
                traceabilityService.log(item.getItem(), owner, TraceabilityService.ActionType.HIRED_MERCHANT_ADD, "雇佣商店上架", (int) (item.getItem().getQuantity() * item.getBundles()), null, "价格: " + item.getPrice());
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

    public int getRemainingDays() {
        long now = System.currentTimeMillis();
        long durationMillis = getDuration();
        long remainingMillis = (start + durationMillis) - now;

        if (remainingMillis <= 0) {
            return 0;
        }

        return (int) (remainingMillis / (24 * 60 * 60 * 1000L));
    }

    public int getTimeOpen() {
        long now = System.currentTimeMillis();
        long durationMillis = getDuration();

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

    public int getOnSaleSlotMax() {
        return Math.min(GameConfig.getServerInt("hired_merchant_max_items", 16),255);
    }

    private long getDuration() {
        return GameConfig.getServerInt("hired_merchant_duration", 1440) * 60 * 1000L;
    }

    public void scheduleClose() {
        if (closeSchedule != null) {
            closeSchedule.cancel(false);
        }
        
        long durationMillis = getDuration();
        long timeLeft = (start + durationMillis) - System.currentTimeMillis();
        
        if (timeLeft <= 0) {
            log.info("雇佣商店 {} 已过期，立即关闭。店主: {}, 店名: {}", merchantId, ownerName, description);
            forceClose();
            return;
        }
        
        closeSchedule = TimerManager.getInstance().schedule(() -> {
            log.info("雇佣商店 {} 定时关闭任务触发。店主: {}, 店名: {}", merchantId, ownerName, description);
            forceClose();
        }, timeLeft);
    }
    
    public void rescheduleClose() {
        scheduleClose();
    }
    
    public long getTotalSales() {
        return totalSales;
    }
    
    public long getTotalRevenue() {
        return totalRevenue;
    }
}
