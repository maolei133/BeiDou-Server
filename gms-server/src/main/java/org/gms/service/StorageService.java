package org.gms.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mybatisflex.core.query.QueryWrapper;
import com.mybatisflex.core.update.UpdateChain;
import lombok.AllArgsConstructor;
import org.apache.logging.log4j.message.MapMessage;
import org.gms.client.inventory.Item;
import org.gms.dao.entity.StorageItemsDO;
import org.gms.dao.entity.StoragesDO;
import org.gms.dao.mapper.StorageItemsMapper;
import org.gms.dao.mapper.StoragesMapper;
import org.gms.model.dto.ItemInfoRtnDTO;
import org.gms.server.logging.AuditLogger;
import org.gms.server.logging.LogAction;
import org.gms.server.logging.LogModule;
import org.gms.util.ItemConverter;
import org.gms.util.SnowflakeIdGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * 仓库服务
 */
@Service
public class StorageService {
    private static final Logger log = LoggerFactory.getLogger(StorageService.class);
    private final StoragesMapper storagesMapper;
    private final StorageItemsMapper storageItemsMapper;
    private final ItemFactoryService itemFactoryService;
    private final TraceabilityService traceabilityService;
    private final ObjectMapper objectMapper;

    public StorageService(
            StoragesMapper storagesMapper,
            StorageItemsMapper storageItemsMapper,
            ItemFactoryService itemFactoryService,
            TraceabilityService traceabilityService,
            @Qualifier("sparseItemObjectMapper") ObjectMapper objectMapper
    ) {
        this.storagesMapper = storagesMapper;
        this.storageItemsMapper = storageItemsMapper;
        this.itemFactoryService = itemFactoryService;
        this.traceabilityService = traceabilityService;
        this.objectMapper = objectMapper;
    }

    /**
     * 存入单个物品 (增量更新)
     * @param storageId 仓库ID
     * @param item 物品对象
     */
    @Transactional
    public void addItem(int storageId, Item item) {
        if (item.getUid() > 0) {
            QueryWrapper checkUidQuery = QueryWrapper.create().select(StorageItemsDO::getId).where(StorageItemsDO::getUid).eq(item.getUid());
            if (storageItemsMapper.selectOneByQuery(checkUidQuery) != null) {
                log.error("发现重复 UID 物品入库尝试 (仓库)! UID: {}, ItemID: {}, StorageID: {}", item.getUid(), item.getItemId(), storageId);
                traceabilityService.log(item, 0, 0, 0, TraceabilityService.ActionType.SYSTEM, TraceabilityService.ActionSourceType.SYSTEM_DELETE, 0, "因UID重复，已阻止存入仓库", "仓库ID: " + storageId);
                throw new RuntimeException("检测到重复的UID: " + item.getUid());
            }
        }

        StorageItemsDO itemDO = new StorageItemsDO();
        itemDO.setStorageId(storageId);
        itemDO.setItemId(item.getItemId());
        itemDO.setQuantity((int) item.getQuantity());
        itemDO.setPosition((int) item.getPosition());
        itemDO.setCreateTime(new Timestamp(System.currentTimeMillis()));

        if (item.getUid() <= 0) {
            item.setUid(SnowflakeIdGenerator.getInstance().nextId());
        }
        itemDO.setUid(item.getUid());

        try {
            itemDO.setItemData(objectMapper.writeValueAsString(item.toInfoRtnDTO(false)));
        } catch (JsonProcessingException e) {
            log.error("序列化仓库物品失败", e);
            throw new RuntimeException("序列化物品数据失败", e);
        }

        storageItemsMapper.insert(itemDO);

        // 统一在 TraceabilityService.log 中记录，防止重复
        // AuditLogger.info(LogModule.ITEM, LogAction.STORAGE_IN, new MapMessage().with("storageId", storageId).with("itm", item.getItemId()).with("cnt", item.getQuantity()).with("uid", item.getUid()));
//        traceabilityService.log(item, 0, 0, 0, TraceabilityService.ActionType.STORAGE, TraceabilityService.ActionSourceType.STORAGE_PUT_IN, -item.getQuantity(), "StorageID: " + storageId);
    }

    /**
     * 取出单个物品 (增量更新)
     * @param storageId 仓库ID
     * @param item 物品对象
     */
    @Transactional
    public void removeItem(int storageId, Item item) {
        if (item.getUid() > 0) {
            QueryWrapper deleteQuery = QueryWrapper.create().where(StorageItemsDO::getUid).eq(item.getUid()).and(StorageItemsDO::getStorageId).eq(storageId);
            if (storageItemsMapper.deleteByQuery(deleteQuery) == 0) {
                log.warn("尝试删除不存在的仓库物品, UID: {}, StorageID: {}", item.getUid(), storageId);
            }
        } else {
            log.error("尝试删除无 UID 的仓库物品, ItemID: {}, StorageID: {}", item.getItemId(), storageId);
            throw new RuntimeException("无法移除没有UID的物品");
        }

        // 统一在 TraceabilityService.log 中记录，防止重复
        // AuditLogger.info(LogModule.ITEM, LogAction.STORAGE_OUT, new MapMessage().with("storageId", storageId).with("itm", item.getItemId()).with("cnt", item.getQuantity()).with("uid", item.getUid()));
        //traceabilityService.log(item, 0, 0, 0, TraceabilityService.ActionType.STORAGE, TraceabilityService.ActionSourceType.STORAGE_TAKE_OUT, item.getQuantity(), "StorageID: " + storageId);
    }

    /**
     * 更新单个物品的数量和JSON数据
     * @param storageId 仓库ID
     * @param item 物品对象
     */
    @Transactional
    public void updateItem(int storageId, Item item) {
        try {
            String json = objectMapper.writeValueAsString(item.toInfoRtnDTO(false));
            UpdateChain.of(StorageItemsDO.class)
                    .set(StorageItemsDO::getQuantity, item.getQuantity())
                    .set(StorageItemsDO::getItemData, json)
                    .where(StorageItemsDO::getUid).eq(item.getUid())
                    .and(StorageItemsDO::getStorageId).eq(storageId)
                    .update();
        } catch (JsonProcessingException e) {
            log.error("序列化仓库物品失败", e);
        }
    }

    /**
     * 同步仓库物品 (用于整理仓库后，处理合并、排序和删除)
     * @param storageId 仓库ID
     * @param items 物品列表
     */
    @Transactional
    public void syncStorageItems(int storageId, List<Item> items) {
        QueryWrapper query = QueryWrapper.create().select(StorageItemsDO::getUid).where(StorageItemsDO::getStorageId).eq(storageId);
        List<Long> dbUids = storageItemsMapper.selectListByQueryAs(query, Long.class);

        List<Long> memoryUids = new ArrayList<>();
        for (Item item : items) {
            if (item.getUid() <= 0) item.setUid(SnowflakeIdGenerator.getInstance().nextId());
            memoryUids.add(item.getUid());
            if (dbUids.contains(item.getUid())) {
                updateItem(storageId, item);
            } else {
                addItem(storageId, item);
            }
        }

        dbUids.removeAll(memoryUids);
        if (!dbUids.isEmpty()) {
            QueryWrapper deleteQuery = QueryWrapper.create().where(StorageItemsDO::getUid).in(dbUids).and(StorageItemsDO::getStorageId).eq(storageId);
            storageItemsMapper.deleteByQuery(deleteQuery);
        }
    }

    /**
     * 更新仓库金币
     * @param storageId 仓库ID
     * @param meso 金币数量
     */
    @Transactional
    public void updateMeso(int storageId, int meso) {
        UpdateChain.of(StoragesDO.class).set(StoragesDO::getMeso, meso).where(StoragesDO::getStorageid).eq(storageId).update();
    }

    /**
     * 更新仓库槽位
     * @param storageId 仓库ID
     * @param slots 槽位数量
     */
    @Transactional
    public void updateSlots(int storageId, int slots) {
        UpdateChain.of(StoragesDO.class).set(StoragesDO::getSlots, slots).where(StoragesDO::getStorageid).eq(storageId).update();
    }

    /**
     * 迁移旧数据 (仅在首次加载且新表为空时调用)
     * @param storageId 仓库ID
     * @param items 物品列表
     */
    @Transactional
    public void migrateOldData(int storageId, List<Item> items) {
        if (items != null && !items.isEmpty()) {
            int position = 0;
            for (Item item : items) {
                if (item.getUid() <= 0) item.setUid(SnowflakeIdGenerator.getInstance().nextId());
                StorageItemsDO itemDO = new StorageItemsDO();
                itemDO.setStorageId(storageId);
                itemDO.setItemId(item.getItemId());
                itemDO.setQuantity((int) item.getQuantity());
                itemDO.setPosition(position++);
                itemDO.setCreateTime(new Timestamp(System.currentTimeMillis()));
                itemDO.setUid(item.getUid());
                try {
                    itemDO.setItemData(objectMapper.writeValueAsString(item.toInfoRtnDTO(false)));
                } catch (JsonProcessingException e) {
                    log.error("迁移时序列化仓库物品失败", e);
                    continue;
                }
                storageItemsMapper.insert(itemDO);
            }
        }
        itemFactoryService.saveItems(2, true, new LinkedList<>(), storageId);
        log.info("仓库 ID: {} 数据迁移完成，迁移物品数: {}", storageId, items == null ? 0 : items.size());
        AuditLogger.info(LogModule.STORAGE, LogAction.STORAGE_MIGRATE, new MapMessage().with("storageId", storageId).with("cnt", items == null ? 0 : items.size()));
    }

    /**
     * 合并旧数据到新仓库
     * @param storageId 仓库ID
     * @param items 旧物品列表
     * @param startPosition 起始位置
     */
    @Transactional
    public void mergeOldData(int storageId, List<Item> items, int startPosition) {
        if (items != null && !items.isEmpty()) {
            int position = startPosition;
            for (Item item : items) {
                if (item.getUid() <= 0) item.setUid(SnowflakeIdGenerator.getInstance().nextId());
                StorageItemsDO itemDO = new StorageItemsDO();
                itemDO.setStorageId(storageId);
                itemDO.setItemId(item.getItemId());
                itemDO.setQuantity((int) item.getQuantity());
                itemDO.setPosition(position++);
                itemDO.setCreateTime(new Timestamp(System.currentTimeMillis()));
                itemDO.setUid(item.getUid());
                try {
                    itemDO.setItemData(objectMapper.writeValueAsString(item.toInfoRtnDTO(false)));
                } catch (JsonProcessingException e) {
                    log.error("合并时序列化仓库物品失败", e);
                    continue;
                }
                storageItemsMapper.insert(itemDO);
            }
        }
        itemFactoryService.saveItems(2, true, new LinkedList<>(), storageId);
        AuditLogger.info(LogModule.STORAGE, LogAction.STORAGE_MERGE, new MapMessage().with("storageId", storageId).with("cnt", items == null ? 0 : items.size()).with("type", "MERGE"));
    }

    /**
     * 从数据库加载仓库物品
     * @param storageId 仓库ID
     * @return 物品列表
     */
    public List<Item> loadStorageItems(int storageId) {
        List<Item> items = new ArrayList<>();
        QueryWrapper query = QueryWrapper.create().where(StorageItemsDO::getStorageId).eq(storageId).orderBy(StorageItemsDO::getPosition, true);
        List<StorageItemsDO> itemDOs = storageItemsMapper.selectListByQuery(query);

        for (StorageItemsDO itemDO : itemDOs) {
            try {
                ItemInfoRtnDTO itemDTO = objectMapper.readValue(itemDO.getItemData(), ItemInfoRtnDTO.class);
                // 调用新的转换方法, 明确传入从数据库独立字段读取的itemId和quantity
                Item item = ItemConverter.restoreItemFromDTO(itemDO.getItemId(), itemDO.getQuantity().shortValue(), itemDTO);
                item.setUid(itemDO.getUid());
                item.setPosition(itemDO.getPosition().shortValue());
                items.add(item);
            } catch (Exception e) {
                log.error("反序列化仓库物品失败, ID: " + itemDO.getId(), e);
            }
        }
        return items;
    }
}
