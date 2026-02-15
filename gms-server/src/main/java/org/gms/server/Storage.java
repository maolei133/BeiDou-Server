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
                                .with("storageId", ret.id)
                                .with("count", itemsToMigrate.size())
                                .with("msg", "迁移旧仓库物品"));
            }
        } else {
            ret.items.addAll(loadedItems);
        }
        
        // 初始排序和整理
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

            // 插入到列表
            items.add(item); 
            
            // 重新排序并更新 Position
            sortItems();
            
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
                
                // 重新排序并更新 Position (保持内存整洁)
                sortItems();
                
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
