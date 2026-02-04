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
import org.gms.client.Client;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.ItemFactory;
import org.gms.constants.inventory.ItemConstants;
import org.gms.dao.entity.StoragesDO;
import org.gms.dao.mapper.StoragesMapper;
import org.gms.provider.Data;
import org.gms.provider.DataProvider;
import org.gms.provider.DataProviderFactory;
import org.gms.provider.DataTool;
import org.gms.provider.wz.WZFiles;
import org.gms.service.StorageService;
import org.gms.util.PacketCreator;
import org.gms.util.Pair;
import org.gms.util.SpringContextUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

/**
 * 仓库领域模型
 * 负责管理仓库的内存状态，并协调 StorageService 进行持久化。
 * <p>
 * 重构说明：
 * 1. 移除了 typeItems 冗余缓存，直接使用 Stream API 过滤 items。
 * 2. 强化了 store 方法的堆叠逻辑。
 * 3. 统一了线程锁的使用。
 * </p>
 */
public class Storage {
    private static final Logger log = LoggerFactory.getLogger(Storage.class);
    // 静态缓存，用于存储NPC的仓库费用信息，避免重复读取WZ文件
    private static final Map<Integer, Integer> trunkGetCache = new HashMap<>();
    private static final Map<Integer, Integer> trunkPutCache = new HashMap<>();

    private final int id;
    private int currentNpcid;
    private int meso;
    private byte slots;
    private List<Item> items; // 核心数据结构
    private final Lock lock = new ReentrantLock(true);

    // 依赖注入
    private static final StorageService storageService = SpringContextUtil.getBean(StorageService.class);

    private Storage(int id, byte slots, int meso) {
        this.id = id;
        this.slots = slots;
        this.meso = meso;
        this.items = new LinkedList<>();
    }

    /**
     * 工厂方法：加载或创建仓库
     */
    public static Storage loadOrCreateFromDB(int accountId, int world) {
        StoragesMapper mapper = SpringContextUtil.getBean(StoragesMapper.class);
        QueryWrapper query = QueryWrapper.create()
                .where(StoragesDO::getAccountid).eq(accountId)
                .and(StoragesDO::getWorld).eq(world);

        StoragesDO data = mapper.selectOneByQuery(query);

        if (data == null) {
            return create(accountId, world);
        }

        Storage ret = new Storage(data.getStorageid().intValue(), data.getSlots().byteValue(), data.getMeso());
        
        // 加载物品
        List<Item> loadedItems = storageService.loadStorageItems(ret.id);
        
        // 兼容性迁移：如果新表为空，尝试从旧表迁移
        if (loadedItems.isEmpty()) {
            List<Pair<Item, InventoryType>> oldItems = ItemFactory.STORAGE.loadItems(ret.id, false);
            if (!oldItems.isEmpty()) {
                List<Item> itemsToMigrate = new ArrayList<>();
                for (Pair<Item, InventoryType> pair : oldItems) {
                    itemsToMigrate.add(pair.getLeft());
                }
                storageService.migrateOldData(ret.id, itemsToMigrate);
                // 迁移后重新加载以获取正确的 UID
                ret.items.addAll(storageService.loadStorageItems(ret.id));
            }
        } else {
            ret.items.addAll(loadedItems);
        }

        return ret;
    }

    private static Storage create(int accountId, int world) {
        StoragesMapper mapper = SpringContextUtil.getBean(StoragesMapper.class);
        StoragesDO newStorage = new StoragesDO();
        newStorage.setAccountid(accountId);
        newStorage.setWorld(world);
        newStorage.setSlots(4);
        newStorage.setMeso(0);
        mapper.insert(newStorage);
        return loadOrCreateFromDB(accountId, world);
    }

    /**
     * 存入物品（核心逻辑）
     * 包含自动堆叠处理
     */
    public boolean store(Client c, Item item) {
        lock.lock();
        try {
            // 1. 尝试堆叠 (Stacking)
            // 只有非装备类、非可充值道具且最大堆叠数 > 1 的物品才尝试堆叠
            if (!ItemConstants.isEquipment(item.getItemId()) 
                && !ItemConstants.isRechargeable(item.getItemId()) 
                && ItemInformationProvider.getInstance().getSlotMax(c, item.getItemId()) > 1) {
                short maxSlot = ItemInformationProvider.getInstance().getSlotMax(c, item.getItemId());
                
                // 遍历现有物品寻找可堆叠的目标
                for (Item existing : items) {
                    if (existing.getItemId() == item.getItemId() && existing.getQuantity() < maxSlot) {
                        // 检查属性是否一致（如拥有者、有效期等），通常同ID消耗品属性一致，但为了严谨可以加检查
                        // 这里简化为同ID即可堆叠，符合大多数游戏逻辑
                        
                        int amountToStack = Math.min(maxSlot - existing.getQuantity(), item.getQuantity());
                        
                        // 更新内存
                        existing.setQuantity((short) (existing.getQuantity() + amountToStack));
                        item.setQuantity((short) (item.getQuantity() - amountToStack));
                        
                        // 更新数据库
                        storageService.updateItem(this.id, existing);
                        
                        if (item.getQuantity() <= 0) {
                            return true; // 全部堆叠完成，无需占用新槽位
                        }
                    }
                }
            }

            // 2. 存入新槽位 (New Slot)
            if (items.size() >= slots) {
                return false; // 仓库已满
            }

            // 设置位置为当前末尾
            item.setPosition((short) items.size());
            items.add(item);
            
            // 插入数据库
            storageService.addItem(this.id, item);

            return true;
        } finally {
            lock.unlock();
        }
    }

    /**
     * 取出物品
     */
    public boolean takeOut(Item item) {
        lock.lock();
        try {
            boolean removed = items.remove(item);
            if (removed) {
                storageService.removeItem(this.id, item);
            }
            return removed;
        } finally {
            lock.unlock();
        }
    }

    /**
     * 整理仓库
     */
    public void arrangeItems(Client c) {
        lock.lock();
        try {
            // 使用 StorageInventory 进行排序逻辑 (保持原有排序算法)
            StorageInventory msi = new StorageInventory(c, items);
            msi.mergeItems(); // 内存合并
            this.items = msi.sortItems(); // 内存排序

            // 全量同步到数据库 (处理合并后的删除、更新和排序)
            storageService.syncStorageItems(this.id, this.items);

            // 发送更新包
            c.sendPacket(PacketCreator.arrangeStorage(slots, items));
        } finally {
            lock.unlock();
        }
    }

    /**
     * 获取指定类型的物品列表 (动态过滤)
     */
    public List<Item> getItemsByType(InventoryType type) {
        lock.lock();
        try {
            return items.stream()
                    .filter(i -> i.getInventoryType() == type)
                    .collect(Collectors.toList());
        } finally {
            lock.unlock();
        }
    }

    public void sendStorage(Client c, int npcId) {
        if (c.getPlayer().getLevel() < 15) {
            c.getPlayer().dropMessage(1, "15级以后才可以使用仓库服务");
            c.sendPacket(PacketCreator.enableActions());
            return;
        }

        lock.lock();
        try {
            this.currentNpcid = npcId;
            // 排序：装备在前，其他按类型排序 (保持原有展示逻辑)
            items.sort((o1, o2) -> Integer.compare(o1.getInventoryType().getType(), o2.getInventoryType().getType()));
            
            c.sendPacket(PacketCreator.getStorage(npcId, slots, items, meso));
        } finally {
            lock.unlock();
        }
    }

    public void sendStored(Client c, InventoryType type) {
        lock.lock();
        try {
            c.sendPacket(PacketCreator.storeStorage(slots, type, getItemsByType(type)));
        } finally {
            lock.unlock();
        }
    }

    public void sendTakenOut(Client c, InventoryType type) {
        lock.lock();
        try {
            c.sendPacket(PacketCreator.takeOutStorage(slots, type, getItemsByType(type)));
        } finally {
            lock.unlock();
        }
    }

    public void sendMeso(Client c) {
        c.sendPacket(PacketCreator.mesoStorage(slots, meso));
    }

    // --- 属性访问与辅助方法 ---

    public Item getItem(byte slot) {
        lock.lock();
        try {
            if (slot >= 0 && slot < items.size()) {
                return items.get(slot);
            }
            return null;
        } finally {
            lock.unlock();
        }
    }

    public List<Item> getItems() {
        lock.lock();
        try {
            return Collections.unmodifiableList(items);
        } finally {
            lock.unlock();
        }
    }

    public boolean isFull() {
        lock.lock();
        try {
            return items.size() >= slots;
        } finally {
            lock.unlock();
        }
    }

    public byte getSlots() {
        return slots;
    }

    public boolean gainSlots(int amount) {
        lock.lock();
        try {
            if (slots + amount <= 48) {
                slots += (byte) amount;
                storageService.updateSlots(this.id, this.slots);
                return true;
            }
            return false;
        } finally {
            lock.unlock();
        }
    }
    
    public boolean canGainSlots(int amount) {
        return slots + amount <= 48;
    }

    public int getMeso() {
        return meso;
    }

    public void setMeso(int meso) {
        if (meso < 0) {
            throw new RuntimeException("仓库金币不能为负数");
        }
        this.meso = meso;
        storageService.updateMeso(this.id, this.meso);
    }

    public int getStoreFee() {
        return getFee(currentNpcid, "info/trunkPut", 100, trunkPutCache);
    }

    public int getTakeOutFee() {
        return getFee(currentNpcid, "info/trunkGet", 0, trunkGetCache);
    }

    private int getFee(int npcId, String path, int def, Map<Integer, Integer> cache) {
        return cache.computeIfAbsent(npcId, id -> {
            DataProvider npc = DataProviderFactory.getDataProvider(WZFiles.NPC);
            Data npcData = npc.getData(id + ".img");
            if (npcData != null) {
                return DataTool.getIntConvert(path, npcData, def);
            }
            return def;
        });
    }

    public void close() {
        // 移除 typeItems 后，close 方法其实没什么可做的了，但为了兼容性保留
        // 如果有其他资源需要释放，可以在这里处理
    }
    
    /**
     * 根据类型和槽位获取物品在总列表中的索引
     * 兼容旧的 StorageProcessor 逻辑
     */
    public byte getSlot(InventoryType type, byte slot) {
        lock.lock();
        try {
            List<Item> typeItems = getItemsByType(type);
            if (slot >= 0 && slot < typeItems.size()) {
                Item targetItem = typeItems.get(slot);
                return (byte) items.indexOf(targetItem);
            }
            return -1;
        } finally {
            lock.unlock();
        }
    }
}
