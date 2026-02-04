package org.gms.service;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mybatisflex.core.query.QueryWrapper;
import com.mybatisflex.core.update.UpdateChain;
import lombok.AllArgsConstructor;
import org.apache.logging.log4j.message.MapMessage;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.ItemFactory;
import org.gms.client.processor.npc.DueyProcessor;
import org.gms.dao.entity.StorageItemsDO;
import org.gms.dao.entity.StoragesDO;
import org.gms.dao.mapper.StorageItemsMapper;
import org.gms.dao.mapper.StoragesMapper;
import org.gms.model.dto.ItemInfoRtnDTO;
import org.gms.server.logging.AuditLogger;
import org.gms.server.logging.LogAction;
import org.gms.server.logging.LogModule;
import org.gms.util.Pair;
import org.gms.util.SnowflakeIdGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

@Service
@AllArgsConstructor
public class StorageService {
    private static final Logger log = LoggerFactory.getLogger(StorageService.class);
    private final StoragesMapper storagesMapper;
    private final StorageItemsMapper storageItemsMapper;
    private final ItemFactoryService itemFactoryService;
    private final TraceabilityService traceabilityService;
    private final ObjectMapper objectMapper = new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL);

    /**
     * 存入单个物品 (增量更新)
     */
    @Transactional
    public void addItem(int storageId, Item item) {
        // 检查 UID 是否重复
        if (item.getUid() > 0) {
            QueryWrapper checkUidQuery = QueryWrapper.create()
                    .select(StorageItemsDO::getId)
                    .where(StorageItemsDO::getUid).eq(item.getUid());

            Long existingId = storageItemsMapper.selectOneByQueryAs(checkUidQuery, Long.class);
            if (existingId != null) {
                log.error("发现重复 UID 物品入库尝试 (Storage)! UID: {}, ItemID: {}, StorageID: {}",
                        item.getUid(), item.getItemId(), storageId);
                // 记录异常日志
                traceabilityService.log(item, null, TraceabilityService.ActionType.ADMIN_DELETE,
                        "重复UID已阻止", 0, "因UID重复，已阻止存入仓库", "仓库ID: " + storageId);
                throw new RuntimeException("检测到重复的UID: " + item.getUid());
            }
        }

        StorageItemsDO itemDO = new StorageItemsDO();
        itemDO.setStorageId(storageId);
        itemDO.setItemId(item.getItemId());
        itemDO.setQuantity((int) item.getQuantity());
        itemDO.setPosition((int) item.getPosition());
        itemDO.setCreateTime(new Timestamp(System.currentTimeMillis()));

        // 确保 UID 存在
        if (item.getUid() == 0) {
            item.setUid(SnowflakeIdGenerator.getInstance().nextId());
        }
        itemDO.setUid(item.getUid());

        // 序列化物品完整数据
        ItemInfoRtnDTO itemDTO = DueyProcessor.convertItemToDTO(item);
        try {
            itemDO.setItemData(objectMapper.writeValueAsString(itemDTO));
        } catch (JsonProcessingException e) {
            log.error("序列化仓库物品失败", e);
            throw new RuntimeException("序列化物品数据失败", e);
        }

        storageItemsMapper.insert(itemDO);

        // 记录日志
        AuditLogger.info(LogModule.ITEM, LogAction.STORAGE_IN, new MapMessage()
                .with("storageId", storageId)
                .with("itm", item.getItemId())
                .with("cnt", item.getQuantity())
                .with("uid", item.getUid()));
        
        // 记录溯源日志
        traceabilityService.log(item, 0, 0, 0, TraceabilityService.ActionType.STORAGE_IN, "仓库存入", 0, "StorageID: " + storageId, null);
    }

    /**
     * 取出单个物品 (增量更新)
     */
    @Transactional
    public void removeItem(int storageId, Item item) {
        // 使用 UID 进行精确删除
        if (item.getUid() > 0) {
            QueryWrapper deleteQuery = QueryWrapper.create()
                    .where(StorageItemsDO::getUid).eq(item.getUid())
                    .and(StorageItemsDO::getStorageId).eq(storageId); // 双重校验

            int deleted = storageItemsMapper.deleteByQuery(deleteQuery);
            if (deleted == 0) {
                log.warn("尝试删除不存在的仓库物品, UID: {}, StorageID: {}", item.getUid(), storageId);
            }
        } else {
            // 如果没有 UID (理论上不应该发生，除非是旧数据未迁移完全)，尝试用位置删除
            // 但新架构下应该强制要求 UID
            log.error("尝试删除无 UID 的仓库物品, ItemID: {}, StorageID: {}", item.getItemId(), storageId);
            throw new RuntimeException("无法移除没有UID的物品");
        }

        // 记录日志
        AuditLogger.info(LogModule.ITEM, LogAction.STORAGE_OUT, new MapMessage()
                .with("storageId", storageId)
                .with("itm", item.getItemId())
                .with("cnt", item.getQuantity())
                .with("uid", item.getUid()));
        
        // 记录溯源日志
        traceabilityService.log(item, 0, 0, 0, TraceabilityService.ActionType.STORAGE_OUT, "仓库取出", 0, "StorageID: " + storageId, null);
    }

    /**
     * 更新单个物品的数量和JSON数据
     */
    @Transactional
    public void updateItem(int storageId, Item item) {
        ItemInfoRtnDTO itemDTO = DueyProcessor.convertItemToDTO(item);
        String json;
        try {
            json = objectMapper.writeValueAsString(itemDTO);
        } catch (JsonProcessingException e) {
            log.error("序列化仓库物品失败", e);
            return;
        }

        UpdateChain.of(StorageItemsDO.class)
                .set(StorageItemsDO::getQuantity, item.getQuantity())
                .set(StorageItemsDO::getItemData, json)
                .where(StorageItemsDO::getUid).eq(item.getUid())
                .and(StorageItemsDO::getStorageId).eq(storageId)
                .update();
    }

    /**
     * 同步仓库物品 (用于整理仓库后，处理合并、排序和删除)
     * 采用 Diff Sync 策略：更新存在的，删除消失的，插入新增的
     */
    @Transactional
    public void syncStorageItems(int storageId, List<Item> items) {
        // 1. 获取数据库中该仓库当前所有的物品 UID
        QueryWrapper query = QueryWrapper.create()
                .select(StorageItemsDO::getUid)
                .where(StorageItemsDO::getStorageId).eq(storageId);
        List<Long> dbUids = storageItemsMapper.selectListByQueryAs(query, Long.class);

        // 2. 构建内存中物品的 UID 集合
        List<Long> memoryUids = new ArrayList<>();
        for (Item item : items) {
            if (item.getUid() == 0) {
                item.setUid(SnowflakeIdGenerator.getInstance().nextId());
            }
            memoryUids.add(item.getUid());

            // 3. 更新或插入
            if (dbUids.contains(item.getUid())) {
                // 更新：位置、数量、ItemData (因为数量变了，JSON也变了)
                updateItem(storageId, item);
            } else {
                // 插入 (理论上整理操作不应该产生新UID，除非逻辑特殊，但为了健壮性加上)
                addItem(storageId, item);
            }
        }

        // 4. 删除在 DB 中存在但内存中不存在的物品 (即被合并掉的物品)
        dbUids.removeAll(memoryUids); // 此时 dbUids 仅包含需要删除的 UID
        if (!dbUids.isEmpty()) {
            QueryWrapper deleteQuery = QueryWrapper.create()
                    .where(StorageItemsDO::getUid).in(dbUids)
                    .and(StorageItemsDO::getStorageId).eq(storageId);
            storageItemsMapper.deleteByQuery(deleteQuery);
        }
    }

    /**
     * 更新仓库金币
     */
    @Transactional
    public void updateMeso(int storageId, int meso) {
        UpdateChain.of(StoragesDO.class)
                .set(StoragesDO::getMeso, meso)
                .where(StoragesDO::getStorageid).eq(storageId)
                .update();
    }

    /**
     * 更新仓库槽位
     */
    @Transactional
    public void updateSlots(int storageId, int slots) {
        UpdateChain.of(StoragesDO.class)
                .set(StoragesDO::getSlots, slots)
                .where(StoragesDO::getStorageid).eq(storageId)
                .update();
    }

    /**
     * 迁移旧数据 (仅在首次加载且新表为空时调用)
     */
    @Transactional
    public void migrateOldData(int storageId, List<Item> items) {
        // 1. 插入新表
        if (items != null && !items.isEmpty()) {
            int position = 0;
            for (Item item : items) {
                // 确保 UID 存在
                if (item.getUid() == 0) {
                    item.setUid(SnowflakeIdGenerator.getInstance().nextId());
                }

                StorageItemsDO itemDO = new StorageItemsDO();
                itemDO.setStorageId(storageId);
                itemDO.setItemId(item.getItemId());
                itemDO.setQuantity((int) item.getQuantity());
                itemDO.setPosition(position++); // 重新分配位置
                itemDO.setCreateTime(new Timestamp(System.currentTimeMillis()));
                itemDO.setUid(item.getUid());

                ItemInfoRtnDTO itemDTO = DueyProcessor.convertItemToDTO(item);
                try {
                    itemDO.setItemData(objectMapper.writeValueAsString(itemDTO));
                } catch (JsonProcessingException e) {
                    log.error("迁移时序列化仓库物品失败", e);
                    continue;
                }

                storageItemsMapper.insert(itemDO);
            }
        }

        // 2. 清理旧表 (inventoryitems type=2)
        // ItemFactory.STORAGE 的 typeValue 是 2
        itemFactoryService.saveItems(2, true, new LinkedList<>(), storageId);

        log.info("仓库 ID: {} 数据迁移完成，迁移物品数: {}", storageId, items == null ? 0 : items.size());

        // 记录迁移日志
        AuditLogger.info(LogModule.ITEM, LogAction.STORAGE_MIGRATE, new MapMessage()
                .with("storageId", storageId)
                .with("cnt", items == null ? 0 : items.size()));
    }

    public List<Item> loadStorageItems(int storageId) {
        List<Item> items = new ArrayList<>();
        QueryWrapper query = QueryWrapper.create()
                .where(StorageItemsDO::getStorageId).eq(storageId)
                .orderBy(StorageItemsDO::getPosition, true);

        List<StorageItemsDO> itemDOs = storageItemsMapper.selectListByQuery(query);

        for (StorageItemsDO itemDO : itemDOs) {
            try {
                ItemInfoRtnDTO itemDTO = objectMapper.readValue(itemDO.getItemData(), ItemInfoRtnDTO.class);
                Item item = restoreItemFromDTO(itemDTO);
                item.setUid(itemDO.getUid());
                item.setPosition(itemDO.getPosition().shortValue()); // 恢复位置
                items.add(item);
            } catch (Exception e) {
                log.error("反序列化仓库物品失败, ID: " + itemDO.getId(), e);
            }
        }

        return items;
    }

    // 复用 DueyProcessor 中的逻辑，或者提取到公共工具类
    // 这里为了解耦，暂时复制一份，建议后续重构到 ItemUtil 或类似位置
    private Item restoreItemFromDTO(ItemInfoRtnDTO itemDTO) {
        // ... (逻辑同 DueyProcessor.restoreItemFromDTO)
        // 由于 DueyProcessor.restoreItemFromDTO 是 private 的，这里需要复制
        // 或者将 DueyProcessor.restoreItemFromDTO 改为 public static
        // 鉴于 DueyProcessor 已经修改过，我们假设它已经是 public static 或者我们这里复制一份
        // 为了稳妥，这里复制一份逻辑

        // 注意：需要导入相关类
        return org.gms.client.processor.npc.DueyProcessor.restoreItemFromDTO(itemDTO);
    }
}
