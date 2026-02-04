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
import org.gms.dao.entity.StoragesDO;
import org.gms.dao.mapper.StoragesMapper;
import org.gms.service.StorageService;
import org.gms.service.TraceabilityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.gms.provider.Data;
import org.gms.provider.DataProvider;
import org.gms.provider.DataProviderFactory;
import org.gms.provider.DataTool;
import org.gms.provider.wz.WZFiles;
import org.gms.util.PacketCreator;
import org.gms.util.Pair;
import org.gms.util.SpringContextUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 仓库服务类
 * @author Matze
 */
public class Storage {
    private static final Logger log = LoggerFactory.getLogger(Storage.class);
    private static final Map<Integer, Integer> trunkGetCache = new HashMap<>();
    private static final Map<Integer, Integer> trunkPutCache = new HashMap<>();

    private final int id;
    private int currentNpcid;
    private int meso;
    private byte slots;
    private final Map<InventoryType, List<Item>> typeItems = new HashMap<>();
    private List<Item> items = new LinkedList<>();
    private final Lock lock = new ReentrantLock(true);

    private Storage(int id, byte slots, int meso) {
        this.id = id;
        this.slots = slots;
        this.meso = meso;
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
        
        // 使用 StorageService 加载物品，支持从新表 storage_items 加载
        StorageService storageService = SpringContextUtil.getBean(StorageService.class);
        List<Item> loadedItems = storageService.loadStorageItems(ret.id);
        
        // 如果新表为空，尝试从旧表加载并迁移
        if (loadedItems.isEmpty()) {
            List<Pair<Item, InventoryType>> oldItems = ItemFactory.STORAGE.loadItems(ret.id, false);
            if (!oldItems.isEmpty()) {
                List<Item> itemsToMigrate = new ArrayList<>();
                for (Pair<Item, InventoryType> pair : oldItems) {
                    itemsToMigrate.add(pair.getLeft());
                }
                // 执行迁移
                storageService.migrateOldData(ret.id, itemsToMigrate);
                // 重新加载以获取正确的 UID 和状态
                ret.items.addAll(storageService.loadStorageItems(ret.id));
            }
        } else {
            ret.items.addAll(loadedItems);
        }

        return ret;
    }

    public byte getSlots() {
        return slots;
    }

    public boolean canGainSlots(int slots) {
        slots += this.slots;
        return slots <= 48;
    }

    public boolean gainSlots(int slots) {
        lock.lock();
        try {
            if (canGainSlots(slots)) {
                slots += this.slots;
                this.slots = (byte) slots;
                
                // 实时更新数据库
                StorageService storageService = SpringContextUtil.getBean(StorageService.class);
                storageService.updateSlots(this.id, this.slots);
                
                return true;
            }

            return false;
        } finally {
            lock.unlock();
        }
    }

    // saveToDB 已废弃，不再需要
    // public void saveToDB() { ... }

    public Item getItem(byte slot) {
        lock.lock();
        try {
            return items.get(slot);
        } finally {
            lock.unlock();
        }
    }

    public boolean takeOut(Item item) {
        lock.lock();
        try {
            boolean ret = items.remove(item);

            InventoryType type = item.getInventoryType();
            typeItems.put(type, new ArrayList<>(filterItems(type)));
            
            if (ret) {
                // 实时从数据库移除
                StorageService storageService = SpringContextUtil.getBean(StorageService.class);
                storageService.removeItem(this.id, item);
            }

            return ret;
        } finally {
            lock.unlock();
        }
    }

    public boolean store(Item item) {
        lock.lock();
        try {
            if (isFull()) {
                return false;
            }

            items.add(item);
            // 设置位置，通常是列表末尾，或者由 StorageInventory 处理
            // 这里简单设置为当前大小 - 1
            item.setPosition((short) (items.size() - 1));

            InventoryType type = item.getInventoryType();
            typeItems.put(type, new ArrayList<>(filterItems(type)));
            
            // 实时存入数据库
            StorageService storageService = SpringContextUtil.getBean(StorageService.class);
            storageService.addItem(this.id, item);

            return true;
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

    private List<Item> filterItems(InventoryType type) {
        List<Item> storageItems = getItems();
        List<Item> ret = new LinkedList<>();

        for (Item item : storageItems) {
            if (item.getInventoryType() == type) {
                ret.add(item);
            }
        }
        return ret;
    }

    public byte getSlot(InventoryType type, byte slot) {
        lock.lock();
        try {
            byte ret = 0;
            List<Item> storageItems = getItems();
            for (Item item : storageItems) {
                if (item == typeItems.get(type).get(slot)) {
                    return ret;
                }
                ret++;
            }
            return -1;
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
            items.sort((o1, o2) -> {
                if (o1.getInventoryType().getType() < o2.getInventoryType().getType()) {
                    return -1;
                } else if (o1.getInventoryType() == o2.getInventoryType()) {
                    return 0;
                }
                return 1;
            });

            List<Item> storageItems = getItems();
            for (InventoryType type : InventoryType.values()) {
                typeItems.put(type, new ArrayList<>(storageItems));
            }

            currentNpcid = npcId;
            c.sendPacket(PacketCreator.getStorage(npcId, slots, storageItems, meso));
        } finally {
            lock.unlock();
        }
    }

    public void sendStored(Client c, InventoryType type) {
        lock.lock();
        try {
            c.sendPacket(PacketCreator.storeStorage(slots, type, typeItems.get(type)));
        } finally {
            lock.unlock();
        }
    }

    public void sendTakenOut(Client c, InventoryType type) {
        lock.lock();
        try {
            c.sendPacket(PacketCreator.takeOutStorage(slots, type, typeItems.get(type)));
        } finally {
            lock.unlock();
        }
    }

    public void arrangeItems(Client c) {
        lock.lock();
        try {
            StorageInventory msi = new StorageInventory(c, items);
            msi.mergeItems();
            items = msi.sortItems();

            for (InventoryType type : InventoryType.values()) {
                typeItems.put(type, new ArrayList<>(items));
            }
            
            // 整理后全量同步数据库
            StorageService storageService = SpringContextUtil.getBean(StorageService.class);
            storageService.syncStorageItems(this.id, items);

            c.sendPacket(PacketCreator.arrangeStorage(slots, items));
        } finally {
            lock.unlock();
        }
    }

    public int getMeso() {
        return meso;
    }

    public void setMeso(int meso) {
        if (meso < 0) {
            throw new RuntimeException("仓库金币不能为负数");
        }
        this.meso = meso;
        
        // 实时更新金币
        StorageService storageService = SpringContextUtil.getBean(StorageService.class);
        storageService.updateMeso(this.id, this.meso);
    }

    public void sendMeso(Client c) {
        c.sendPacket(PacketCreator.mesoStorage(slots, meso));
    }

    public int getStoreFee() {
        int npcId = currentNpcid;
        Integer fee = trunkPutCache.get(npcId);
        if (fee == null) {
            fee = 100;

            DataProvider npc = DataProviderFactory.getDataProvider(WZFiles.NPC);
            Data npcData = npc.getData(npcId + ".img");
            if (npcData != null) {
                fee = DataTool.getIntConvert("info/trunkPut", npcData, 100);
            }

            trunkPutCache.put(npcId, fee);
        }

        return fee;
    }

    public int getTakeOutFee() {
        int npcId = currentNpcid;
        Integer fee = trunkGetCache.get(npcId);
        if (fee == null) {
            fee = 0;

            DataProvider npc = DataProviderFactory.getDataProvider(WZFiles.NPC);
            Data npcData = npc.getData(npcId + ".img");
            if (npcData != null) {
                fee = DataTool.getIntConvert("info/trunkGet", npcData, 0);
            }

            trunkGetCache.put(npcId, fee);
        }

        return fee;
    }

    public boolean isFull() {
        lock.lock();
        try {
            return items.size() >= slots;
        } finally {
            lock.unlock();
        }
    }

    public void close() {
        lock.lock();
        try {
            typeItems.clear();
        } finally {
            lock.unlock();
        }
    }

}
