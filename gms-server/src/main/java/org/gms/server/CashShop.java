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
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import net.jcip.annotations.GuardedBy;
import org.gms.client.inventory.Equip;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.ItemFactory;
import org.gms.config.GameConfig;
import org.gms.constants.id.ItemId;
import org.gms.constants.inventory.ItemConstants;
import org.gms.dao.entity.AccountsDO;
import org.gms.dao.entity.GiftsDO;
import org.gms.dao.entity.ModifiedCashItemDO;
import org.gms.dao.entity.WishlistsDO;
import org.gms.dao.mapper.GiftsMapper;
import org.gms.manager.ServerManager;
import org.gms.model.pojo.CashCategory;
import org.gms.net.server.Server;
import org.gms.provider.*;
import org.gms.provider.wz.WZFiles;
import org.gms.service.AccountService;
import org.gms.service.CashShopService;
import org.gms.service.CharacterService;
import org.gms.service.ItemFactoryService;
import org.gms.util.Pair;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.gms.dao.entity.table.GiftsDOTableDef.GIFTS_DO;

@Slf4j @Getter @Setter
public class CashShop {
    public static final int NX_CREDIT = 1;
    public static final int MAPLE_POINT = 2;
    public static final int NX_PREPAID = 4;

    private final int accountId;
    private final int characterId;
    private int nxCredit;
    private int maplePoint;
    private int nxPrepaid;
    private boolean opened;
    private ItemFactory factory;
    private final List<Item> inventory = new ArrayList<>();
    private final List<Integer> wishList = new ArrayList<>();
    private int notes = 0;
    private final Lock lock = new ReentrantLock();
    private static final AccountService accountService = ServerManager.getApplicationContext().getBean(AccountService.class);
    private static final CharacterService characterService = ServerManager.getApplicationContext().getBean(CharacterService.class);
    private static final ItemFactoryService itemFactoryService = ServerManager.getApplicationContext().getBean(ItemFactoryService.class);
    private static final GiftsMapper giftsMapper = ServerManager.getApplicationContext().getBean(GiftsMapper.class);

    public CashShop(int accountId, int characterId, int jobType) {
        this.accountId = accountId;
        this.characterId = characterId;

        if (!GameConfig.getServerBoolean("use_joint_cash_shop_inventory")) {
            switch (jobType) {
                case 0:
                    factory = ItemFactory.CASH_EXPLORER;
                    break;
                case 1:
                    factory = ItemFactory.CASH_CYGNUS;
                    break;
                case 2:
                    factory = ItemFactory.CASH_ARAN;
                    break;
            }
        } else {
            factory = ItemFactory.CASH_OVERALL;
        }

        AccountsDO accountsDO = accountService.findById(accountId);
        this.nxCredit = Optional.ofNullable(accountsDO.getNxCredit()).orElse(0);
        this.maplePoint = Optional.ofNullable(accountsDO.getMaplePoint()).orElse(0);
        this.nxPrepaid = Optional.ofNullable(accountsDO.getNxPrepaid()).orElse(0);

        for (Pair<Item, InventoryType> item : factory.loadItems(accountId, false)) {
            inventory.add(item.getLeft());
        }

        List<WishlistsDO> wishlistsDOList = characterService.getWishlistsByCharacter(characterId);
        wishlistsDOList.forEach(wishlistsDO -> wishList.add(wishlistsDO.getSn()));
    }

    @Slf4j
    public static class CashItemFactory {
        private static final CachingDataProvider etcData = DataProviderFactory.getDataProvider(WZFiles.ETC);
        // 主缓存，存储所有从WZ加载并转换完成的商品POJO
        @Getter
        private static final Map<Integer, ModifiedCashItemDO> items = new ConcurrentHashMap<>();
        private static final Map<Integer, List<Integer>> packages = new ConcurrentHashMap<>();
        @Getter
        private static final List<CashCategory> cashCategories = new ArrayList<>();
        @Getter
        private static final Map<Integer, ModifiedCashItemDO> modifiedCashItems = new ConcurrentHashMap<>();
        @Getter
        private static final Map<Integer, ModifiedCashItemDO> discontinuedCashItems = new ConcurrentHashMap<>();
        @Getter
        private static final Map<Integer, ModifiedCashItemDO> permanentCashItems = new ConcurrentHashMap<>();
        private static Collection<ModifiedCashItemDO> clientItemsCache = Collections.emptyList();
        private static final List<Integer> rateCouponSnList = new ArrayList<>();
        private static final List<Integer> upgradablePetEquipSnList = new ArrayList<>();

        public static void updateItemInCache(ModifiedCashItemDO updatedItem) {
            if (updatedItem == null) return;
            if (ItemConstants.isUpgradablePetEquip(updatedItem.getItemId())) {
                updatedItem.setPeriod(0L);
                permanentCashItems.put(updatedItem.getSn(), updatedItem);
            } else if (ItemConstants.isRateCoupon(updatedItem.getItemId())) {
                discontinuedCashItems.put(updatedItem.getSn(), updatedItem);
            }
        }

        public static void rebuildClientCache() {
            Map<Integer, ModifiedCashItemDO> itemMap = Stream.of(
                            getDiscontinuedCashItems().values(),
                            getModifiedCashItems().values(),
                            getPermanentCashItems().values()
                    )
                    .flatMap(Collection::stream)
                    .collect(Collectors.toMap(
                            ModifiedCashItemDO::getSn,
                            item -> item,
                            (existing, replacement) -> existing,
                            LinkedHashMap::new
                    ));
            clientItemsCache = itemMap.values();
        }

        public static Collection<ModifiedCashItemDO> getClientCache() {
            if (clientItemsCache.isEmpty()) {
                loadAllModifiedCashItems();
                processRateCouponItems((GameConfig.getServerBoolean("use_supply_rate_coupons")));
                processPetEquipItems(GameConfig.getServerBoolean("use_pet_equip_permanent"));
            }
            rebuildClientCache();
            return clientItemsCache;
        }

        public static void loadAllCashItems() {
            loadAllCashItems(false);
        }
        
        /**
         * 启动时全量加载所有商城数据。
         * @param releaseData 加载后是否立即释放DOM数据
         */
        public static void loadAllCashItems(boolean releaseData) {
            long startTime = System.currentTimeMillis();
            
            // 1. 加载并转换所有商品
            Data commodityData = releaseData ? etcData.getDataAndRelease("Commodity.img") : etcData.getData("Commodity.img");
            if (commodityData != null) {
                Map<Integer, ModifiedCashItemDO> loadedItems = new HashMap<>();
                for (Data itemNode : commodityData.getChildren()) {
                    int sn = DataTool.getIntConvert("SN", itemNode);
                    int itemId = DataTool.getIntConvert("ItemId", itemNode);
                    int price = DataTool.getIntConvert("Price", itemNode, 0);
                    long period = DataTool.getIntConvert("Period", itemNode, 1);
                    short count = (short) DataTool.getIntConvert("Count", itemNode, 1);
                    int onSale = DataTool.getIntConvert("OnSale", itemNode, 0);
                    Integer priority = DataTool.getInteger("Priority", itemNode);
                    Integer bonus = DataTool.getInteger("Bonus", itemNode);
                    Integer maplePoint = DataTool.getInteger("MaplePoint", itemNode);
                    Integer meso = DataTool.getInteger("Meso", itemNode);
                    Integer forPremiumUser = DataTool.getInteger("ForPremiumUser", itemNode);
                    Integer gender = DataTool.getInteger("Gender", itemNode);
                    Integer clz = DataTool.getInteger("Class", itemNode);
                    Integer pbCash = DataTool.getInteger("PbCash", itemNode);
                    Integer pbPoint = DataTool.getInteger("PbPoint", itemNode);
                    Integer pbGift = DataTool.getInteger("PbGift", itemNode);
                    Integer packageSN = DataTool.getInteger("PackageSN", itemNode);

                    loadedItems.put(sn, ModifiedCashItemDO.builder()
                            .sn(sn).itemId(itemId).count(count).price(price).bonus(bonus)
                            .priority(priority).period(period == 0 ? 90 : period).maplePoint(maplePoint)
                            .meso(meso).forPremiumUser(forPremiumUser).commodityGender(gender)
                            .onSale(onSale).clz(clz).pbCash(pbCash).pbPoint(pbPoint)
                            .pbGift(pbGift).packageSn(packageSN).build());
                    
                    // 同时构建专用索引
                    if (ItemConstants.isRateCoupon(itemId)) rateCouponSnList.add(sn);
                    if (ItemConstants.isUpgradablePetEquip(itemId)) upgradablePetEquipSnList.add(sn);
                }
                items.clear();
                items.putAll(loadedItems);
                log.info("商城加载了 {} 个商品，耗时：{} 毫秒", items.size(), System.currentTimeMillis() - startTime);
            }

            // 2. 加载并转换所有礼包
            long time = System.currentTimeMillis();
            Data cashPackageData = releaseData ? etcData.getDataAndRelease("CashPackage.img") : etcData.getData("CashPackage.img");
            if (cashPackageData != null) {
                Map<Integer, List<Integer>> loadedPackages = new HashMap<>();
                for (Data cashPackage : cashPackageData.getChildren()) {
                    List<Integer> cPackage = new ArrayList<>();
                    for (Data item : cashPackage.getChildByPath("SN").getChildren()) {
                        cPackage.add(Integer.parseInt(item.getData().toString()));
                    }
                    loadedPackages.put(Integer.parseInt(cashPackage.getName()), cPackage);
                }
                packages.clear();
                packages.putAll(loadedPackages);
                log.info("商城加载了 {} 个礼包，耗时：{} 毫秒", packages.size(), System.currentTimeMillis() - time);
            }

            // 3. 加载数据库相关数据
            loadCashCategories();
            loadAllModifiedCashItems();
            log.info("商城加载完毕，总耗时：{} 毫秒", System.currentTimeMillis() - startTime);
        }

        public static void loadAllModifiedCashItems() {
            modifiedCashItems.clear();
            CashShopService cashShopService = ServerManager.getApplicationContext().getBean(CashShopService.class);
            cashShopService.loadAllModifiedCashItems().forEach(modifiedCashItemDO -> modifiedCashItems.put(modifiedCashItemDO.getSn(), modifiedCashItemDO));
        }

        private static void loadCashCategories() {
            cashCategories.clear();
            CashShopService cashShopService = ServerManager.getApplicationContext().getBean(CashShopService.class);
            cashCategories.addAll(cashShopService.getAllCategoryList());
        }

        public static Optional<ModifiedCashItemDO> getRandomCashItem() {
            if (items.isEmpty()) return Optional.empty();
            List<Integer> snList = new ArrayList<>(items.keySet());
            int randomSN = snList.get(new Random().nextInt(snList.size()));
            return Optional.ofNullable(getItem(randomSN));
        }

        public static void processRateCouponItems(boolean sale) {
            discontinuedCashItems.values().removeIf(item -> ItemConstants.isRateCoupon(item.getItemId()));
            if (!sale) {
                for (int sn : rateCouponSnList) {
                    ModifiedCashItemDO item = getItem(sn);
                    if (item != null) {
                        ModifiedCashItemDO clone = item.clone();
                        clone.setOnSale(0);
                        discontinuedCashItems.put(clone.getSn(), clone);
                    }
                }
            }
        }

        public static void processPetEquipItems(boolean makePermanent) {
            permanentCashItems.values().removeIf(item -> ItemConstants.isPetEquip(item.getItemId()));
            if (makePermanent) {
                for (int sn : upgradablePetEquipSnList) {
                    ModifiedCashItemDO item = getItem(sn);
                    if (item != null) {
                        ModifiedCashItemDO clone = item.clone();
                        clone.setPeriod(0L);
                        permanentCashItems.put(clone.getSn(), clone);
                    }
                }
            }
        }

        /**
         * 注解：重构后的 getItem 方法。
         * 它现在直接从已全量加载的 'items' Map 中获取数据，不再有懒加载逻辑。
         * @param sn 商品序列号
         * @return 最终的商品信息对象，可能为 null
         */
        public static ModifiedCashItemDO getItem(int sn) {
            ModifiedCashItemDO wzItem = items.get(sn);
            if (wzItem == null) {
                return null; // 在全量加载模式下，如果这里找不到，就是真的不存在
            }

            ModifiedCashItemDO dbItem = modifiedCashItems.get(sn);
            ModifiedCashItemDO finalItem = wzItem.clone();

            if (dbItem != null) {
                finalItem.setItemId(Optional.ofNullable(dbItem.getItemId()).orElse(wzItem.getItemId()));
                finalItem.setPrice(Optional.ofNullable(dbItem.getPrice()).orElse(wzItem.getPrice()));
                finalItem.setPeriod(Optional.ofNullable(dbItem.getPeriod()).orElse(wzItem.getPeriod()));
                finalItem.setPriority(Optional.ofNullable(dbItem.getPriority()).orElse(wzItem.getPriority()));
                finalItem.setCount(Optional.ofNullable(dbItem.getCount()).orElse(wzItem.getCount()));
                finalItem.setOnSale(Optional.ofNullable(dbItem.getOnSale()).orElse(wzItem.getOnSale()));
                finalItem.setBonus(Optional.ofNullable(dbItem.getBonus()).orElse(wzItem.getBonus()));
                finalItem.setMaplePoint(Optional.ofNullable(dbItem.getMaplePoint()).orElse(wzItem.getMaplePoint()));
                finalItem.setMeso(Optional.ofNullable(dbItem.getMeso()).orElse(wzItem.getMeso()));
                finalItem.setForPremiumUser(Optional.ofNullable(dbItem.getForPremiumUser()).orElse(wzItem.getForPremiumUser()));
                finalItem.setCommodityGender(Optional.ofNullable(dbItem.getCommodityGender()).orElse(wzItem.getCommodityGender()));
                finalItem.setClz(Optional.ofNullable(dbItem.getClz()).orElse(wzItem.getClz()));
                finalItem.setLimit(Optional.ofNullable(dbItem.getLimit()).orElse(wzItem.getLimit()));
                finalItem.setPbCash(Optional.ofNullable(dbItem.getPbCash()).orElse(wzItem.getPbCash()));
                finalItem.setPbPoint(Optional.ofNullable(dbItem.getPbPoint()).orElse(wzItem.getPbPoint()));
                finalItem.setPbGift(Optional.ofNullable(dbItem.getPbGift()).orElse(wzItem.getPbGift()));
                finalItem.setPackageSn(Optional.ofNullable(dbItem.getPackageSn()).orElse(wzItem.getPackageSn()));
            }

            if (ItemConstants.isRateCoupon(finalItem.getItemId())) {
                if (!GameConfig.getServerBoolean("use_supply_rate_coupons")) {
                    finalItem.setOnSale(0);
                    discontinuedCashItems.put(finalItem.getSn(), finalItem);
                }
            }
            if (ItemConstants.isUpgradablePetEquip(finalItem.getItemId())) {
                if (GameConfig.getServerBoolean("use_pet_equip_permanent")) {
                    finalItem.setPeriod(0L);
                    permanentCashItems.put(finalItem.getSn(), finalItem);
                }
            }

            return finalItem;
        }

        public static ModifiedCashItemDO getWzItem(int sn) {
            return items.get(sn);
        }

        public static List<Item> getPackage(int itemId) {
            // 注解：由于已全量加载，不再需要懒加载
            List<Integer> packageSNs = packages.get(itemId);
            if (packageSNs == null) return Collections.emptyList();

            List<Item> cashPackage = new ArrayList<>();
            for (int sn : packageSNs) {
                ModifiedCashItemDO itemDO = getItem(sn);
                if (itemDO != null) {
                    cashPackage.add(itemDO.toItem());
                }
            }
            return cashPackage;
        }

        public static boolean isPackage(int itemId) {
            return packages.containsKey(itemId);
        }
    }

    public record CashShopSurpriseResult(Item usedCashShopSurprise, Item reward) {}

    public String getCashName(int type) {
        return switch (type) {
            case NX_CREDIT -> "点券";
            case MAPLE_POINT -> "抵用券";
            case NX_PREPAID -> "信用点";
            default -> "未知:" + type;
        };
    }
    public int getCash(int type) {
        return switch (type) {
            case NX_CREDIT -> nxCredit;
            case MAPLE_POINT -> maplePoint;
            case NX_PREPAID -> nxPrepaid;
            default -> 0;
        };
    }

    public void gainCash(int type, int cash) {
        switch (type) {
            case NX_CREDIT -> nxCredit += cash;
            case MAPLE_POINT -> maplePoint += cash;
            case NX_PREPAID -> nxPrepaid += cash;
        }
    }

    public void gainCash(int type, ModifiedCashItemDO buyItem, int world) {
        gainCash(type, -buyItem.getPrice());
        if (!GameConfig.getServerBoolean("use_enforce_item_suggestion")) {
            Server.getInstance().getWorld(world).addCashItemBought(buyItem.getSn());
        }
    }

    public void open(boolean b) {
        opened = b;
    }

    public List<Item> getInventory() {
        lock.lock();
        try {
            return Collections.unmodifiableList(inventory);
        } finally {
            lock.unlock();
        }
    }

    public Item findByCashId(int cashId) {
        boolean isRing;
        Equip equip = null;
        for (Item item : getInventory()) {
            if (item.getInventoryType().equals(InventoryType.EQUIP)) {
                equip = (Equip) item;
                isRing = equip.getRingId() > -1;
            } else {
                isRing = false;
            }

            if ((item.getPetId() > -1 ? item.getPetId() : isRing ? equip.getRingId() : item.getCashId()) == cashId) {
                return item;
            }
        }

        return null;
    }

    public void addToInventory(Item item) {
        lock.lock();
        try {
            inventory.add(item);
        } finally {
            lock.unlock();
        }
    }

    public void removeFromInventory(Item item) {
        lock.lock();
        try {
            inventory.remove(item);
        } finally {
            lock.unlock();
        }
    }

    public void clearWishList() {
        wishList.clear();
    }

    public void addToWishList(int sn) {
        wishList.add(sn);
    }

    public void gift(int recipient, String from, String message, int sn) {
        gift(recipient, from, message, sn, -1);
    }

    public void gift(int recipient, String from, String message, int sn, int ringid) {
        giftsMapper.insert(GiftsDO.builder()
                .to(recipient)
                .from(from)
                .message(message)
                .sn(sn)
                .ringid(ringid)
                .build());
    }

    public List<Pair<Item, String>> loadGifts() {
        List<Pair<Item, String>> gifts = new ArrayList<>();
        List<GiftsDO> giftList = giftsMapper.selectListByQuery(QueryWrapper.create().where(GIFTS_DO.TO.eq(characterId)));

        for (GiftsDO gift : giftList) {
            notes++;
            ModifiedCashItemDO cItem = CashItemFactory.getItem(gift.getSn());
            Item item = cItem.toItem();
            Equip equip = null;
            item.setGiftFrom(gift.getFrom());
            if (item.getInventoryType().equals(InventoryType.EQUIP)) {
                equip = (Equip) item;
                equip.setRingId(gift.getRingid());
                gifts.add(new Pair<>(equip, gift.getMessage()));
            } else {
                gifts.add(new Pair<>(item, gift.getMessage()));
            }

            if (CashItemFactory.isPackage(cItem.getItemId())) { //礼包里永远不会有戒指
                for (Item packageItem : CashItemFactory.getPackage(cItem.getItemId())) {
                    packageItem.setGiftFrom(gift.getFrom());
                    addToInventory(packageItem);
                }
            } else {
                addToInventory(equip == null ? item : equip);
            }
        }

        if (!giftList.isEmpty()) {
            giftsMapper.deleteByQuery(QueryWrapper.create().where(GIFTS_DO.TO.eq(characterId)));
        }

        return gifts;
    }

    public int getAvailableNotes() {
        return notes;
    }

    public void decreaseNotes() {
        notes--;
    }

    public void save() {
        accountService.update(AccountsDO.builder()
                .id(accountId)
                .nxCredit(nxCredit)
                .maplePoint(maplePoint)
                .nxPrepaid(nxPrepaid)
                .build());

        List<Pair<Item, InventoryType>> itemsWithType = new ArrayList<>();

        List<Item> inv = getInventory();
        for (Item item : inv) {
            itemsWithType.add(new Pair<>(item, item.getInventoryType()));
        }

        itemFactoryService.saveItems(factory.getValue(), factory.isAccount(), itemsWithType, accountId);
    }

    public Optional<CashShopSurpriseResult> openCashShopSurprise(long cashId) {
        lock.lock();
        try {
            Optional<Item> maybeCashShopSurprise = getItemByCashId(cashId);
            if (maybeCashShopSurprise.isEmpty() ||
                    maybeCashShopSurprise.get().getItemId() != ItemId.CASH_SHOP_SURPRISE) {
                return Optional.empty();
            }

            Item cashShopSurprise = maybeCashShopSurprise.get();
            if (cashShopSurprise.getQuantity() <= 0) {
                return Optional.empty();
            }

            if (getItemsSize() >= 100) {
                return Optional.empty();
            }

            Optional<ModifiedCashItemDO> cashItemReward = CashItemFactory.getRandomCashItem();
            if (cashItemReward.isEmpty()) {
                return Optional.empty();
            }

            short newQuantity = (short) (cashShopSurprise.getQuantity() - 1);
            cashShopSurprise.setQuantity(newQuantity);
            if (newQuantity <= 0) {
                removeFromInventory(cashShopSurprise);
            }

            Item itemReward = cashItemReward.get().toItem();
            addToInventory(itemReward);

            return Optional.of(new CashShopSurpriseResult(cashShopSurprise, itemReward));
        } finally {
            lock.unlock();
        }
    }

    @GuardedBy("lock")
    private Optional<Item> getItemByCashId(long cashId) {
        return inventory.stream()
                .filter(item -> item.getCashId() == cashId)
                .findAny();
    }

    public int getItemsSize() {
        lock.lock();
        try {
            return inventory.size();
        } finally {
            lock.unlock();
        }
    }

    public static Item generateCouponItem(int itemId, short quantity) {
        return ModifiedCashItemDO.builder()
                .sn(77777777)
                .itemId(itemId)
                .price(777)
                .period(ItemConstants.isPet(itemId) ? 30L : 0L)
                .count(quantity)
                .onSale(1)
                .priority(0)
                .build()
                .toItem();
    }
}
