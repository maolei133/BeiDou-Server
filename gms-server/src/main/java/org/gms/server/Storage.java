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
import org.gms.server.logging.AuditLogger;
import org.gms.server.logging.LogAction;
import org.gms.server.logging.LogModule;
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
    private final Map<InventoryType, List<Item>> typeItems = new HashMap<>(); // 分类缓存，用于快速响应客户端请求
    private List<Item> items; // 核心数据结构，存储所有物品
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
                List<Item> reloadedItems = storageService.loadStorageItems(ret.id);
                ret.items.addAll(reloadedItems);
                
                // 记录迁移日志
                AuditLogger.info(LogModule.STORAGE, LogAction.STORAGE_MIGRATE, 
                        new MapMessage()
                                .with("sid", ret.id)
                                .with("cnt", itemsToMigrate.size())
                                .with("msg", "迁移旧仓库物品"));
            }
        } else {
            ret.items.addAll(loadedItems);
            
            // 修复：如果新旧表都有数据（例如回档导致），尝试合并旧表数据
            List<Pair<Item, InventoryType>> oldItems = ItemFactory.STORAGE.loadItems(ret.id, false);
            if (!oldItems.isEmpty()) {
                int oldItemCount = oldItems.size();
                int newItemCount = ret.items.size();
                int oldMeso = 0; // 旧仓库金币通常存储在 storages 表中，这里只处理物品
                int newMeso = ret.meso;
                
                List<Item> itemsToMerge = new ArrayList<>();
                for (Pair<Item, InventoryType> pair : oldItems) {
                    itemsToMerge.add(pair.getLeft());
                }
                
                // 计算合并后的起始位置
                int startPosition = ret.items.size();
                
                try {
                    // 执行合并
                    storageService.mergeOldData(ret.id, itemsToMerge, startPosition);
                    
                    // 重新加载以获取完整数据
                    List<Item> reloadedItems = storageService.loadStorageItems(ret.id);
                    ret.items.clear();
                    ret.items.addAll(reloadedItems);
                    
                    int mergedItemCount = ret.items.size();
                    int mergedMeso = ret.meso; // 金币保持不变，因为旧金币逻辑未涉及合并
                    
                    String msg = String.format("合并旧仓库残留数据成功: 旧(物品:%d, 金币:%d) + 新(物品:%d, 金币:%d) -> 合并后(物品:%d, 金币:%d)",
                            oldItemCount, oldMeso, newItemCount, newMeso, mergedItemCount, mergedMeso);

                    AuditLogger.info(LogModule.STORAGE, LogAction.STORAGE_MERGE, 
                            new MapMessage()
                                    .with("sid", ret.id)
                                    .with("oCnt", oldItemCount)
                                    .with("oMeso", oldMeso)
                                    .with("nCnt", newItemCount)
                                    .with("nMeso", newMeso)
                                    .with("mCnt", mergedItemCount)
                                    .with("mMeso", mergedMeso)
                                    .with("msg", msg));
                                    
                } catch (Exception e) {
                    String errorMsg = String.format("合并旧仓库数据失败: %s. 旧(物品:%d) + 新(物品:%d)", 
                            e.getMessage(), oldItemCount, newItemCount);
                    log.error(errorMsg, e);
                    
                    AuditLogger.error(LogModule.STORAGE, LogAction.STORAGE_MERGE_FAIL, 
                            new MapMessage()
                                    .with("sid", ret.id)
                                    .with("oCnt", oldItemCount)
                                    .with("nCnt", newItemCount)
                                    .with("msg", errorMsg), e);
                }
            }
        }
        
        // 初始排序和整理
        // 这里的排序是为了让客户端第一次打开仓库时看到整齐的列表
        // 排序后会重置 Position，确保与列表索引一致
        ret.sortItems();
        ret.refreshTypeItems();

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
            if (!ItemConstants.isEquipment(item.getItemId()) 
                && !ItemConstants.isRechargeable(item.getItemId()) 
                && ItemInformationProvider.getInstance().getSlotMax(c, item.getItemId()) > 1) {
                short maxSlot = ItemInformationProvider.getInstance().getSlotMax(c, item.getItemId());
                
                for (Item existing : items) {
                    if (existing.getItemId() == item.getItemId() && existing.getQuantity() < maxSlot) {
                        int amountToStack = Math.min(maxSlot - existing.getQuantity(), item.getQuantity());
                        
                        existing.setQuantity((short) (existing.getQuantity() + amountToStack));
                        item.setQuantity((short) (item.getQuantity() - amountToStack));
                        
                        storageService.updateItem(this.id, existing);
                        
                        if (item.getQuantity() <= 0) {
                            return true; 
                        }
                    }
                }
            }

            // 2. 存入新槽位 (New Slot)
            if (items.size() >= slots) {
                return false; // 仓库已满
            }

            // 计算新物品的 Position
            // 为了保持顺序一致性，新物品总是追加到末尾
            // Position 设为当前最大 Position + 1，或者列表大小（如果列表是紧凑的）
            // 这里简单地使用列表大小作为新索引，因为我们不排序
            short newPos = (short) items.size();
            item.setPosition(newPos);

            // 插入到列表末尾
            items.add(item); 
            
            // 注意：这里不再调用 sortItems()，以保持与客户端增量更新逻辑一致
            
            // 更新 typeItems 缓存
            refreshTypeItems();
            
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
            // 使用迭代器进行引用比较删除，防止 equals() 误删同ID的其他物品
            boolean removed = false;
            Iterator<Item> it = items.iterator();
            while (it.hasNext()) {
                if (it.next() == item) { // 引用比较
                    it.remove();
                    removed = true;
                    break;
                }
            }

            if (removed) {
                storageService.removeItem(this.id, item);
                
                // 注意：这里不再调用 sortItems()，也不重置 Position
                // 移除物品后，列表索引会发生变化，但 Position 字段保持不变（直到下次整理或重载）
                // 这符合客户端“移除指定位置物品”的逻辑
                
                // 更新 typeItems 缓存
                refreshTypeItems();
            } else {
                String itemName = ItemInformationProvider.getInstance().getName(item.getItemId());
                String msg = String.format("从列表中移除物品失败: ID=%d, Name=%s, Pos=%d, ListSize=%d", 
                        item.getItemId(), itemName, item.getPosition(), items.size());
                AuditLogger.error(LogModule.STORAGE, LogAction.STORAGE_OUT, 
                        new MapMessage()
                                .with("msg", msg)
                                .with("itemId", item.getItemId())
                                .with("itemName", itemName)
                                .with("pos", item.getPosition())
                                .with("listSize", items.size()), null);
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
            StorageInventory msi = new StorageInventory(c, items);
            msi.mergeItems(); // 内存合并
            this.items = msi.sortItems(); // 内存排序

            // 重新分配 position，确保连续
            // 整理操作会改变列表顺序，所以必须重置 Position 并同步给客户端
            short pos = 0;
            for (Item item : items) {
                item.setPosition(pos++);
            }

            // 更新所有类型的缓存
            refreshTypeItems();

            // 全量同步到数据库
            storageService.syncStorageItems(this.id, this.items);

            c.sendPacket(PacketCreator.arrangeStorage(slots, items));
        } finally {
            lock.unlock();
        }
    }
    
    /**
     * 对物品列表进行排序，并重新分配 Position
     * 排序规则：InventoryType -> ItemId -> Position
     * 仅在加载和整理时调用
     */
    private void sortItems() {
        items.sort(Comparator.comparingInt((Item i) -> i.getInventoryType().getType())
                .thenComparingInt(Item::getItemId)
                .thenComparingInt(Item::getPosition));
        
        // 重新分配 Position，确保连续且与列表索引一致
        short pos = 0;
        for (Item item : items) {
            item.setPosition(pos++);
        }
    }

    /**
     * 刷新 typeItems 缓存
     * 保持 items 的原始顺序（插入顺序）
     */
    private void refreshTypeItems() {
        for (InventoryType type : InventoryType.values()) {
            List<Item> typeList = new ArrayList<>();
            for (Item item : items) {
                // 使用 item.getInventoryType() 确保与物品自身属性一致
                if (item.getInventoryType() == type) {
                    typeList.add(item);
                }
            }
            typeItems.put(type, typeList);
        }
    }

    private List<Item> filterItems(InventoryType type) {
        List<Item> ret = new LinkedList<>();
        for (Item item : items) {
            if (item.getInventoryType() == type) {
                ret.add(item);
            }
        }
        return ret;
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
            
            // 确保发送前列表是有序的
            // 每次打开仓库都重新排序，确保客户端看到的是整齐的列表
            sortItems();
            
            // 刷新缓存
            refreshTypeItems();
            
            c.sendPacket(PacketCreator.getStorage(npcId, slots, items, meso));
        } finally {
            lock.unlock();
        }
    }

    public void sendStored(Client c, InventoryType type) {
        lock.lock();
        try {
            // 恢复为增量更新包
            c.sendPacket(PacketCreator.storeStorage(slots, type, typeItems.get(type)));
        } finally {
            lock.unlock();
        }
    }

    public void sendTakenOut(Client c, InventoryType type) {
        lock.lock();
        try {
            // 恢复为增量更新包
            c.sendPacket(PacketCreator.takeOutStorage(slots, type, typeItems.get(type)));
        } finally {
            lock.unlock();
        }
    }

    public void sendMeso(Client c) {
        c.sendPacket(PacketCreator.mesoStorage(slots, meso));
    }

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
        lock.lock();
        try {
            typeItems.clear();
        } finally {
            lock.unlock();
        }
    }
    
    /**
     * 根据类型和槽位获取物品在总列表中的索引
     * 
     * 智能查找逻辑：
     * 1. 优先尝试将 slot 作为全局绝对索引查找。
     * 2. 如果类型不匹配，降级为尝试将 slot 作为相对索引查找。
     * 3. 这样可以兼容客户端发送全局索引或相对索引的情况，并解决排序不一致导致的问题。
     */
    public byte getSlot(InventoryType type, byte slot) {
        lock.lock();
        try {
            // 1. 尝试全局索引匹配
            if (slot >= 0 && slot < items.size()) {
                Item item = items.get(slot);
                if (item.getInventoryType() == type) {
                    return slot;
                } else {
                    String itemName = ItemInformationProvider.getInstance().getName(item.getItemId());
                    String msg = String.format("全局索引类型不匹配: ReqType=%s, ActualType=%s, Slot=%d, ItemID=%d, Name=%s", 
                            type, item.getInventoryType(), slot, item.getItemId(), itemName);
                    AuditLogger.info(LogModule.STORAGE, LogAction.STORAGE_OUT, 
                            new MapMessage()
                                    .with("msg", msg)
                                    .with("reqType", type)
                                    .with("actualType", item.getInventoryType())
                                    .with("slot", slot)
                                    .with("itemId", item.getItemId())
                                    .with("itemName", itemName));
                }
            } else {
                String msg = String.format("全局索引越界: Slot=%d, Size=%d", slot, items.size());
                AuditLogger.info(LogModule.STORAGE, LogAction.STORAGE_OUT, 
                        new MapMessage()
                                .with("msg", msg)
                                .with("slot", slot)
                                .with("size", items.size()));
            }
            
            // 2. 尝试相对索引匹配 (Fallback)
            int count = 0;
            for (int i = 0; i < items.size(); i++) {
                if (items.get(i).getInventoryType() == type) {
                    if (count == slot) {
                        return (byte) i;
                    }
                    count++;
                }
            }
            
            String msg = String.format("未找到物品: Type=%s, Slot=%d, ListSize=%d", type, slot, items.size());
            AuditLogger.error(LogModule.STORAGE, LogAction.STORAGE_OUT, 
                    new MapMessage()
                            .with("msg", msg)
                            .with("type", type)
                            .with("slot", slot)
                            .with("listSize", items.size()), null);
            return -1;
        } finally {
            lock.unlock();
        }
    }
}
