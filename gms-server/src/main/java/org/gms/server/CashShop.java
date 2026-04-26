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
import org.gms.provider.Data;
import org.gms.provider.DataProvider;
import org.gms.provider.DataProviderFactory;
import org.gms.provider.DataTool;
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

/**
 * 商城核心逻辑处理类
 * @author Flav
 * @author Ponk
 */
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
        private static final DataProvider etcData = DataProviderFactory.getDataProvider(WZFiles.ETC);
        // 主缓存，用于懒加载所有商场道具的原始WZ数据
        @Getter
        private static final Map<Integer, ModifiedCashItemDO> items = new ConcurrentHashMap<>();
        // 礼包缓存
        private static final Map<Integer, List<Integer>> packages = new ConcurrentHashMap<>();
        @Getter
        private static final List<CashCategory> cashCategories = new ArrayList<>();
        // 数据库修改项缓存
        @Getter
        private static final Map<Integer, ModifiedCashItemDO> modifiedCashItems = new ConcurrentHashMap<>();
        // 动态生成的特殊状态列表
        @Getter
        private static final Map<Integer, ModifiedCashItemDO> discontinuedCashItems = new ConcurrentHashMap<>();
        @Getter
        private static final Map<Integer, ModifiedCashItemDO> permanentCashItems = new ConcurrentHashMap<>();

        // 优化：预构建SN到节点的映射，以加速单品加载，但只在第一次需要时构建
        private static final Map<Integer, Data> snToNodeMap = new HashMap<>();
        private static volatile boolean commodityIndexBuilt = false;

        // 客户端最终商品缓存
        private static Collection<ModifiedCashItemDO> clientItemsCache = Collections.emptyList();

        // 专用索引，用于快速定位需要全局处理的商品
        private static final List<Integer> rateCouponSnList = new ArrayList<>();
        private static final List<Integer> upgradablePetEquipSnList = new ArrayList<>();

        /**
         * 在购买时更新动态修改的商品缓存。
         * @param updatedItem 状态已更新的商品对象
         */
        public static void updateItemInCache(ModifiedCashItemDO updatedItem) {
            if (updatedItem == null) {
                return;
            }
            // 检查商品是否属于某个动态分类，并更新它
            if (ItemConstants.isUpgradablePetEquip(updatedItem.getItemId())) {
                updatedItem.setPeriod(0L);
                permanentCashItems.put(updatedItem.getSn(), updatedItem);
//                log.info("【商城缓存】购买时更新了永久宠物装备 SN: {}", updatedItem.getSn());
            } else if (ItemConstants.isRateCoupon(updatedItem.getItemId())) {
                discontinuedCashItems.put(updatedItem.getSn(), updatedItem);
//                log.info("【商城缓存】购买时更新了倍率卡 SN: {}", updatedItem.getSn());
            }
        }

        /**
         * 重建用于客户端的商品缓存。
         * 该方法合并所有修改和动态配置，生成最终的商品列表。
         */
        public static void rebuildClientCache() {
            // 使用 Stream 按优先级顺序合并和滤重
            Map<Integer, ModifiedCashItemDO> itemMap = Stream.of(//生效的优先级从高到低，确保控制台商城管理的优先级最高，并且减少重复的现金道具。
                            getDiscontinuedCashItems().values(), // 合并已下架现金道具列表
                            getModifiedCashItems().values(),  // 获取修改过的现金道具信息
                            getPermanentCashItems().values() // 合并永久现金道具列表
                    )
                    .flatMap(Collection::stream)
                    .collect(Collectors.toMap(
                            ModifiedCashItemDO::getSn,
                            item -> item,
                            (existing, replacement) -> existing, // 保留先出现的（高优先级）
                            LinkedHashMap::new // 保持插入顺序
                    ));
            clientItemsCache = itemMap.values();
//            log.info("商城商品缓存重建完毕，共缓存 {} 个商品。", clientItemsCache.size());
        }

        /**
         * 获取供客户端使用的、已缓存的最终商品列表。
         * @return 最终商品列表的集合
         */
        public static Collection<ModifiedCashItemDO> getClientCache() {
            if (clientItemsCache.isEmpty()) {
                loadAllModifiedCashItems(); // 加载所有修改过的现金道具
                processRateCouponItems((GameConfig.getServerBoolean("use_supply_rate_coupons"))); //重载商城是否允许出售倍率卡
                processPetEquipItems(GameConfig.getServerBoolean("use_pet_equip_permanent"));  //重载宠物装备有效期
            }
            rebuildClientCache();   // 重新生成客户端缓存
            return clientItemsCache;
        }

        /**
         * 恢复全量加载逻辑，用于调试或特定的预加载场景。
         * 调用此方法将一次性加载所有商城道具到内存中。
         */
        public static void loadAllCashItems() {
            long startTime = System.currentTimeMillis();
            long time;

            // 1. 加载所有商品
            Map<Integer, ModifiedCashItemDO> loadedItems = new HashMap<>();
            Data commodityData = etcData.getData("Commodity.img");
            if (commodityData != null) {
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
                            .sn(sn)
                            .itemId(itemId)
                            .count(count)
                            .price(price)
                            .bonus(bonus)
                            .priority(priority)
                            .period(period == 0 ? 90 : period)
                            .maplePoint(maplePoint)
                            .meso(meso)
                            .forPremiumUser(forPremiumUser)
                            .commodityGender(gender)
                            .onSale(onSale)
                            .clz(clz)
                            .pbCash(pbCash)
                            .pbPoint(pbPoint)
                            .pbGift(pbGift)
                            .packageSn(packageSN)
                            .build());
                }
            }
            items.clear();
            items.putAll(loadedItems);
            log.info("商城加载了 {} 个商品，耗时：{} 毫秒", items.size(), System.currentTimeMillis() - startTime);
            time = System.currentTimeMillis();
            // 2. 加载所有礼包
            Map<Integer, List<Integer>> loadedPackages = new HashMap<>();
            Data cashPackageData = etcData.getData("CashPackage.img");
            if (cashPackageData != null) {
                for (Data cashPackage : cashPackageData.getChildren()) {
                    List<Integer> cPackage = new ArrayList<>();
                    for (Data item : cashPackage.getChildByPath("SN").getChildren()) {
                        cPackage.add(Integer.parseInt(item.getData().toString()));
                    }
                    loadedPackages.put(Integer.parseInt(cashPackage.getName()), cPackage);
                }
            }
            packages.clear();
            packages.putAll(loadedPackages);
            log.info("商城加载了 {} 个礼包，耗时：{} 毫秒", packages.size(), System.currentTimeMillis() - time);

            // 3. 加载数据库相关数据
            loadCashCategories();
            loadAllModifiedCashItems();

            // 4. 确保索引也已构建，以便后续单品加载逻辑（如getItem）能正常工作
            ensureCommodityIndex();
            log.info("商城加载完毕，总耗时：{} 毫秒", System.currentTimeMillis() - startTime);
        }

        /**
         * 确保商品索引已构建。这是一个线程安全的、一次性的操作。
         * 它会在第一次访问商城数据时被触发，构建SN到数据节点的映射以优化后续加载。
         */
        private static void ensureCommodityIndex() {
            if (!commodityIndexBuilt) {
                synchronized (snToNodeMap) {
                    if (!commodityIndexBuilt) {
                        long startTime = System.currentTimeMillis();
                        Data commodityData = etcData.getData("Commodity.img");
                        if (commodityData != null) {
                            for (Data itemNode : commodityData.getChildren()) {
                                int sn = DataTool.getIntConvert("SN", itemNode);
                                snToNodeMap.put(sn, itemNode);

                                // 建立专用索引
                                int itemId = DataTool.getIntConvert("ItemId", itemNode);
                                if (ItemConstants.isRateCoupon(itemId)) {
                                    rateCouponSnList.add(sn);
                                }
                                if (ItemConstants.isUpgradablePetEquip(itemId)) {
                                    upgradablePetEquipSnList.add(sn);
                                }
                            }
                        } else {
                            log.error("无法加载 Commodity.img，商城功能可能异常！");
                        }
                        commodityIndexBuilt = true;
                        log.info("商城商品索引构建完成，耗时：{} 毫秒。", System.currentTimeMillis() - startTime);
                        log.info("专用索引：找到 {} 个倍率卡, {} 个可升级宠物装备。", rateCouponSnList.size(), upgradablePetEquipSnList.size());
                    }
                }
            }
        }

        /**
         * 懒加载商城礼包数据。
         */
        private static void lazyLoadPackages() {
            if (packages.isEmpty()) {
                synchronized (packages) {
                    if (packages.isEmpty()) {
                        long startTime = System.currentTimeMillis();
                        Data cashPackageData = etcData.getData("CashPackage.img");
                        if (cashPackageData != null) {
                            for (Data cashPackage : cashPackageData.getChildren()) {
                                List<Integer> cPackage = new ArrayList<>();
                                for (Data item : cashPackage.getChildByPath("SN").getChildren()) {
                                    cPackage.add(Integer.parseInt(item.getData().toString()));
                                }
                                packages.put(Integer.parseInt(cashPackage.getName()), cPackage);
                            }
                        }
                        log.info("商城礼包数据加载完成，耗时：{} 毫秒", System.currentTimeMillis() - startTime);
                    }
                }
            }
        }

        /**
         * 从WZ文件中加载单个商城道具的数据。
         * @param sn 商品序列号 (SN)
         * @return 商城道具信息，如果找不到则返回 null
         */
        private static ModifiedCashItemDO loadSingleItemFromWZ(int sn) {
            ensureCommodityIndex(); // 确保索引已构建
            Data itemData = snToNodeMap.get(sn);

            if (itemData == null) {
                log.warn("在 Commodity.img 索引中找不到 SN 为 {} 的道具", sn);
                return null;
            }

            int itemId = DataTool.getIntConvert("ItemId", itemData);
            int price = DataTool.getIntConvert("Price", itemData, 0);
            long period = DataTool.getIntConvert("Period", itemData, 1);
            short count = (short) DataTool.getIntConvert("Count", itemData, 1);
            int onSale = DataTool.getIntConvert("OnSale", itemData, 0);
            Integer priority = DataTool.getInteger("Priority", itemData);
            Integer bonus = DataTool.getInteger("Bonus", itemData);
            Integer maplePoint = DataTool.getInteger("MaplePoint", itemData);
            Integer meso = DataTool.getInteger("Meso", itemData);
            Integer forPremiumUser = DataTool.getInteger("ForPremiumUser", itemData);
            Integer gender = DataTool.getInteger("Gender", itemData);
            Integer clz = DataTool.getInteger("Class", itemData);
            Integer pbCash = DataTool.getInteger("PbCash", itemData);
            Integer pbPoint = DataTool.getInteger("PbPoint", itemData);
            Integer pbGift = DataTool.getInteger("PbGift", itemData);
            Integer packageSN = DataTool.getInteger("PackageSN", itemData);

            return ModifiedCashItemDO.builder()
                    .sn(sn)
                    .itemId(itemId)
                    .count(count)
                    .price(price)
                    .bonus(bonus)
                    .priority(priority)
                    .period(period == 0 ? 90 : period)
                    .maplePoint(maplePoint)
                    .meso(meso)
                    .forPremiumUser(forPremiumUser)
                    .commodityGender(gender)
                    .onSale(onSale)
                    .clz(clz)
                    .pbCash(pbCash)
                    .pbPoint(pbPoint)
                    .pbGift(pbGift)
                    .packageSn(packageSN)
                    .build();
        }

        public static void loadAllModifiedCashItems() {
            modifiedCashItems.clear();
            CashShopService cashShopService = ServerManager.getApplicationContext().getBean(CashShopService.class);
            cashShopService.loadAllModifiedCashItems().forEach(modifiedCashItemDO -> modifiedCashItems.put(modifiedCashItemDO.getSn(), modifiedCashItemDO));
             // 数据变更，重建缓存
        }

        private static void loadCashCategories() {
            cashCategories.clear();
            CashShopService cashShopService = ServerManager.getApplicationContext().getBean(CashShopService.class);
            cashCategories.addAll(cashShopService.getAllCategoryList());
        }

        public static Optional<ModifiedCashItemDO> getRandomCashItem() {
            ensureCommodityIndex(); // 确保索引已构建
            // 随机选择一个SN，然后加载它
            List<Integer> snList = new ArrayList<>(snToNodeMap.keySet());
            if (snList.isEmpty()) {
                return Optional.empty();
            }
            int randomSN = snList.get(new Random().nextInt(snList.size()));
            return Optional.ofNullable(getItem(randomSN));
        }

        /**
         * 处理倍率卡商品的上架/下架状态。
         * 此方法在配置变更时调用，用于回顾性地更新已缓存道具的状态。
         * @param sale true表示上架倍率卡商品，false表示下架倍率卡商品
         */
        public static void processRateCouponItems(boolean sale) {
            discontinuedCashItems.values().removeIf(item -> ItemConstants.isRateCoupon(item.getItemId()));
            if (!sale) {
                // 使用专用索引，只处理相关商品
                for (int sn : rateCouponSnList) {
                    ModifiedCashItemDO item = getItem(sn); // getItem内部会处理懒加载
                    if (item != null) {
                        ModifiedCashItemDO clone = item.clone();
                        clone.setOnSale(0);
                        discontinuedCashItems.put(clone.getSn(), clone);
                    }
                }
            }
             // 数据变更，重建缓存
        }

        /**
         * 处理宠物装备商品的永久化设置。
         * 此方法在配置变更时调用，用于回顾性地更新已缓存道具的状态。
         * @param makePermanent true表示将符合条件的宠物装备设置为永久，false表示取消永久设置
         */
        public static void processPetEquipItems(boolean makePermanent) {
            permanentCashItems.values().removeIf(item -> ItemConstants.isPetEquip(item.getItemId()));
            if (makePermanent) {
                // 使用专用索引，只处理相关商品
                for (int sn : upgradablePetEquipSnList) {
                    ModifiedCashItemDO item = getItem(sn); // getItem内部会处理懒加载
                    if (item != null) {
                        ModifiedCashItemDO clone = item.clone();
                        clone.setPeriod(0L);
                        permanentCashItems.put(clone.getSn(), clone);
                    }
                }
            }
             // 数据变更，重建缓存
        }

        public static ModifiedCashItemDO getItem(int sn) {
            // 1. 从主缓存获取或懒加载WZ原始数据
            ModifiedCashItemDO wzItem = items.computeIfAbsent(sn, CashItemFactory::loadSingleItemFromWZ);
            if (wzItem == null) {
                return null; // WZ中不存在此SN
            }

            // 2. 应用数据库中的修改
            ModifiedCashItemDO dbItem = modifiedCashItems.get(sn);
            ModifiedCashItemDO finalItem = wzItem.clone(); // 创建副本以避免修改缓存

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

            // 3. 根据当前动态配置，即时处理特殊状态
            // 处理倍率卡
            if (ItemConstants.isRateCoupon(finalItem.getItemId())) {
                if (!GameConfig.getServerBoolean("use_supply_rate_coupons")) {
                    finalItem.setOnSale(0);
                    discontinuedCashItems.put(finalItem.getSn(), finalItem);
                }
            }
            // 处理宠物装备
            if (ItemConstants.isUpgradablePetEquip(finalItem.getItemId())) {
                if (GameConfig.getServerBoolean("use_pet_equip_permanent")) {
                    finalItem.setPeriod(0L);
                    permanentCashItems.put(finalItem.getSn(), finalItem);
                }
            }

            return finalItem;
        }

        public static ModifiedCashItemDO getWzItem(int sn) {
            return items.computeIfAbsent(sn, CashItemFactory::loadSingleItemFromWZ);
        }

        public static List<Item> getPackage(int itemId) {
            lazyLoadPackages(); // 确保礼包数据已加载
            List<Integer> packageSNs = packages.get(itemId);
            if (packageSNs == null) {
                return Collections.emptyList();
            }

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
            lazyLoadPackages(); // 确保礼包数据已加载
            return packages.containsKey(itemId);
        }
    }

    public record CashShopSurpriseResult(Item usedCashShopSurprise, Item reward) {
    }

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
