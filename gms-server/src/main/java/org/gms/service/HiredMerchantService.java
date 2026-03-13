package org.gms.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mybatisflex.core.query.QueryWrapper;
import com.mybatisflex.core.update.UpdateChain;
import lombok.RequiredArgsConstructor;
import org.gms.client.inventory.Item;
import org.gms.dao.entity.HiredMerchantItemsDO;
import org.gms.dao.entity.HiredMerchantTransactionsDO;
import org.gms.dao.entity.HiredMerchantsDO;
import org.gms.dao.mapper.HiredMerchantItemsMapper;
import org.gms.dao.mapper.HiredMerchantTransactionsMapper;
import org.gms.dao.mapper.HiredMerchantsMapper;
import org.gms.model.dto.ItemInfoRtnDTO;
import org.gms.util.ItemConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.File;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class HiredMerchantService {

    private static final Logger log = LoggerFactory.getLogger(HiredMerchantService.class);
    private final HiredMerchantsMapper hiredMerchantsMapper;
    private final HiredMerchantItemsMapper hiredMerchantItemsMapper;
    private final HiredMerchantTransactionsMapper hiredMerchantTransactionsMapper;
    private final TraceabilityService traceabilityService;
    private final ObjectMapper objectMapper;

    public HiredMerchantsDO getActiveMerchantByOwnerId(int ownerId) {
        return hiredMerchantsMapper.selectOneByQuery(QueryWrapper.create()
                .where(HiredMerchantsDO::getOwnerId).eq(ownerId)
                .and(HiredMerchantsDO::getStatus).eq(HiredMerchantsDO.STATUS_ACTIVE));
    }

    public HiredMerchantsDO getPreparingMerchantByOwnerId(int ownerId) {
        return hiredMerchantsMapper.selectOneByQuery(QueryWrapper.create()
                .where(HiredMerchantsDO::getOwnerId).eq(ownerId)
                .and(HiredMerchantsDO::getStatus).eq(HiredMerchantsDO.STATUS_PREPARING));
    }

    public List<HiredMerchantsDO> getActiveMerchantsByWorldId(int worldId) {
        return hiredMerchantsMapper.selectListByQuery(QueryWrapper.create()
                .where(HiredMerchantsDO::getWorldId).eq(worldId)
                .and(HiredMerchantsDO::getStatus).eq(HiredMerchantsDO.STATUS_ACTIVE));
    }

    public HiredMerchantsDO getMerchantById(int merchantId) {
        return hiredMerchantsMapper.selectOneById(merchantId);
    }

    @Transactional
    public int createMerchant(HiredMerchantsDO merchant) {
        return hiredMerchantsMapper.insert(merchant);
    }

    @Transactional
    public void updateMerchant(HiredMerchantsDO merchant) {
        hiredMerchantsMapper.update(merchant);
    }

    @Transactional
    public void addItem(HiredMerchantItemsDO item, HiredMerchantTransactionsDO transaction) {
        if (item.getUid() != null && item.getUid() > 0) {
            QueryWrapper checkUidQuery = QueryWrapper.create()
                    .select(HiredMerchantItemsDO::getId)
                    .where(HiredMerchantItemsDO::getUid).eq(item.getUid())
                    .and(HiredMerchantItemsDO::getStatus).eq(HiredMerchantItemsDO.STATUS_ON_SALE);
            
            Long existingId = hiredMerchantItemsMapper.selectOneByQueryAs(checkUidQuery, Long.class);
            if (existingId != null) {
                log.error("发现重复 UID 物品入库尝试 (雇佣商店)! UID: {}, 物品ID: {}, 商店ID: {}", 
                        item.getUid(), item.getItemId(), item.getMerchantId());
                traceabilityService.log(null, null, TraceabilityService.ActionType.ADMIN_DELETE, 
                        "DUPLICATE_UID_BLOCKED", 0, "由于重复的UID阻止了雇佣商店添加: " + item.getUid(), "商店ID: " + item.getMerchantId());
                throw new RuntimeException("检测到重复 UID: " + item.getUid());
            }
        }

        hiredMerchantItemsMapper.insert(item);
        if (transaction != null) {
            transaction.setItemId(item.getItemId());
            hiredMerchantTransactionsMapper.insert(transaction);
        }
    }

    @Transactional
    public void updateItem(HiredMerchantItemsDO item) {
        hiredMerchantItemsMapper.update(item);
    }

    @Transactional
    public void removeItem(int itemId, HiredMerchantTransactionsDO transaction) {
        UpdateChain.of(HiredMerchantItemsDO.class)
                .set(HiredMerchantItemsDO::getStatus, HiredMerchantItemsDO.STATUS_RETURNED)
                .where(HiredMerchantItemsDO::getId).eq(itemId)
                .update();
        
        if (transaction != null) {
            hiredMerchantTransactionsMapper.insert(transaction);
        }
    }

    @Transactional
    public void addTransaction(HiredMerchantTransactionsDO transaction) {
        hiredMerchantTransactionsMapper.insert(transaction);
    }

    @Transactional
    public void incrementSoldQuantity(int itemId, int amount) {
        UpdateChain.of(HiredMerchantItemsDO.class)
                .setRaw(HiredMerchantItemsDO::getSoldQuantity, "sold_quantity + " + amount)
                .where(HiredMerchantItemsDO::getId).eq(itemId)
                .update();
    }
    
    @Transactional
    public void addMesos(int merchantId, long amount) {
        UpdateChain.of(HiredMerchantsDO.class)
                .setRaw(HiredMerchantsDO::getMesos, "mesos + " + amount)
                .where(HiredMerchantsDO::getId).eq(merchantId)
                .update();
    }

    @Transactional
    public void processPurchase(int merchantId, int itemDbId, int itemId, int quantity, int unitPrice, long totalPrice, int buyerId) {
        HiredMerchantTransactionsDO transaction = HiredMerchantTransactionsDO.builder()
                .merchantId(merchantId)
                .itemId(itemId)
                .buyerId(buyerId)
                .type(HiredMerchantTransactionsDO.TYPE_BUY)
                .quantity(quantity)
                .price(unitPrice)
                .totalPrice(totalPrice)
                .timestamp(System.currentTimeMillis())
                .build();
        hiredMerchantTransactionsMapper.insert(transaction);

        UpdateChain.of(HiredMerchantItemsDO.class)
                .setRaw(HiredMerchantItemsDO::getSoldQuantity, "sold_quantity + " + quantity)
                .setRaw(HiredMerchantItemsDO::getStatus, "CASE WHEN sold_quantity + " + quantity + " >= bundles THEN '" + HiredMerchantItemsDO.STATUS_SOLD_OUT + "' ELSE status END")
                .where(HiredMerchantItemsDO::getId).eq(itemDbId)
                .update();

        UpdateChain.of(HiredMerchantsDO.class)
                .setRaw(HiredMerchantsDO::getMesos, "mesos + " + totalPrice)
                .where(HiredMerchantsDO::getId).eq(merchantId)
                .update();
    }

    @Transactional
    public long withdrawAllMesos(int merchantId) {
        HiredMerchantsDO merchant = hiredMerchantsMapper.selectOneById(merchantId);
        if (merchant != null && merchant.getMesos() > 0) {
            long mesos = merchant.getMesos();
            merchant.setMesos(0L);
            hiredMerchantsMapper.update(merchant);
            
            UpdateChain.of(HiredMerchantItemsDO.class)
                    .set(HiredMerchantItemsDO::getSettledTime, System.currentTimeMillis())
                    .where(HiredMerchantItemsDO::getMerchantId).eq(merchantId)
                    .and(HiredMerchantItemsDO::getStatus).eq(HiredMerchantItemsDO.STATUS_SOLD_OUT)
                    .and(HiredMerchantItemsDO::getSettledTime).isNull()
                    .update();
            
            return mesos;
        }
        return 0;
    }

    public List<HiredMerchantItemsDO> getMerchantItems(int merchantId) {
        return hiredMerchantItemsMapper.selectListByQuery(QueryWrapper.create()
                .where(HiredMerchantItemsDO::getMerchantId).eq(merchantId)
                .and(HiredMerchantItemsDO::getStatus).ne(HiredMerchantItemsDO.STATUS_RETURNED)
                .and("(status = '" + HiredMerchantItemsDO.STATUS_ON_SALE + "' OR (status = '" + HiredMerchantItemsDO.STATUS_SOLD_OUT + "' AND settled_time IS NULL))"));
    }

    public List<HiredMerchantsDO> getRetrieveableMerchants(int ownerId) {
        return hiredMerchantsMapper.selectListByQuery(QueryWrapper.create()
                .where(HiredMerchantsDO::getOwnerId).eq(ownerId)
                .and(HiredMerchantsDO::getStatus).in(HiredMerchantsDO.STATUS_CLOSED, HiredMerchantsDO.STATUS_EXPIRED));
    }

    public List<HiredMerchantsDO> getZombieMerchants(int ownerId) {
        return hiredMerchantsMapper.selectListByQuery(QueryWrapper.create()
                .where(HiredMerchantsDO::getOwnerId).eq(ownerId)
                .and(HiredMerchantsDO::getStatus).eq(HiredMerchantsDO.STATUS_ACTIVE));
    }

    public List<HiredMerchantItemsDO> getRetrieveableItems(int merchantId) {
        return hiredMerchantItemsMapper.selectListByQuery(QueryWrapper.create()
                .where(HiredMerchantItemsDO::getMerchantId).eq(merchantId)
                .and(HiredMerchantItemsDO::getStatus).ne(HiredMerchantItemsDO.STATUS_RETURNED)
                .and("bundles > sold_quantity"));
    }

    public List<HiredMerchantsDO> getAllActiveMerchants() {
        return hiredMerchantsMapper.selectListByQuery(QueryWrapper.create()
                .where(HiredMerchantsDO::getStatus).eq(HiredMerchantsDO.STATUS_ACTIVE));
    }

    @Transactional
    public void cleanupOldRecords(int days) {
        long cutoffTime = System.currentTimeMillis() - (days * 24 * 60 * 60 * 1000L);

        hiredMerchantTransactionsMapper.deleteByQuery(QueryWrapper.create()
                .where(HiredMerchantTransactionsDO::getTimestamp).lt(cutoffTime));

        List<HiredMerchantsDO> candidates = hiredMerchantsMapper.selectListByQuery(QueryWrapper.create()
                .select(HiredMerchantsDO::getId)
                .where(HiredMerchantsDO::getStatus).in(HiredMerchantsDO.STATUS_CLOSED, HiredMerchantsDO.STATUS_EXPIRED)
                .and(HiredMerchantsDO::getCloseTime).lt(cutoffTime)
                .and(HiredMerchantsDO::getMesos).eq(0));

        for (HiredMerchantsDO merchant : candidates) {
            long count = hiredMerchantItemsMapper.selectCountByQuery(QueryWrapper.create()
                    .where(HiredMerchantItemsDO::getMerchantId).eq(merchant.getId())
                    .and(HiredMerchantItemsDO::getStatus).ne(HiredMerchantItemsDO.STATUS_RETURNED));

            if (count == 0) {
                hiredMerchantItemsMapper.deleteByQuery(QueryWrapper.create()
                        .where(HiredMerchantItemsDO::getMerchantId).eq(merchant.getId()));
                hiredMerchantsMapper.deleteById(merchant.getId());
            }
        }
    }

    /**
     * 从JSON反序列化物品对象
     * @param json 物品的JSON数据
     * @param itemId 物品的模板ID
     * @param quantity 物品的数量
     * @return 反序列化后的Item对象
     */
    public Item deserializeItem(String json, int itemId, short quantity) {
        try {
            ItemInfoRtnDTO itemDTO = objectMapper.readValue(json, ItemInfoRtnDTO.class);
            return ItemConverter.restoreItemFromDTO(itemId, quantity, itemDTO);
        } catch (Exception e) {
            log.error("反序列化雇佣商店物品失败, ItemID: {}, Quantity: {}", itemId, quantity, e);
            return null;
        }
    }

    @Transactional
    public void restoreMerchantItems(int merchantId) {
        HiredMerchantsDO merchant = hiredMerchantsMapper.selectOneById(merchantId);
        if (merchant == null) {
            throw new IllegalArgumentException("未找到商店: " + merchantId);
        }

        List<HiredMerchantItemsDO> items = hiredMerchantItemsMapper.selectListByQuery(QueryWrapper.create()
                .where(HiredMerchantItemsDO::getMerchantId).eq(merchantId)
                .and(HiredMerchantItemsDO::getStatus).ne(HiredMerchantItemsDO.STATUS_RETURNED));

        if (HiredMerchantsDO.STATUS_ACTIVE.equals(merchant.getStatus())) {
            merchant.setStatus(HiredMerchantsDO.STATUS_CLOSED);
            merchant.setCloseTime(System.currentTimeMillis());
            hiredMerchantsMapper.update(merchant);
        }
        
        for (HiredMerchantItemsDO item : items) {
            if (item.getBundles() > item.getSoldQuantity() && HiredMerchantItemsDO.STATUS_SOLD_OUT.equals(item.getStatus())) {
                item.setStatus(HiredMerchantItemsDO.STATUS_ON_SALE);
                hiredMerchantItemsMapper.update(item);
            }
        }
    }

    @Transactional
    public void restoreFromBackup(File backupFile) throws Exception {
        Map<String, Object> backupData = objectMapper.readValue(backupFile, Map.class);
        
        int ownerId = (int) backupData.get("ownerId");
        int itemId = (int) backupData.get("itemId");
        long mesos = ((Number) backupData.get("mesos")).longValue();
        int channel = (int) backupData.get("channel");
        int mapId = (int) backupData.get("mapId");
        
        List<Map<String, Object>> items = (List<Map<String, Object>>) backupData.get("items");
        
        HiredMerchantsDO merchant = HiredMerchantsDO.builder()
                .ownerId(ownerId)
                .description((String) backupData.get("description"))
                .itemId(itemId > 0 ? itemId : 5030000)
                .status(HiredMerchantsDO.STATUS_CLOSED)
                .startTime(System.currentTimeMillis())
                .closeTime(System.currentTimeMillis())
                .mesos(mesos)
                .channel(channel)
                .mapId(mapId)
                .build();
        
        hiredMerchantsMapper.insert(merchant);
        
        for (Map<String, Object> itemData : items) {
            HiredMerchantItemsDO itemDO = HiredMerchantItemsDO.builder()
                    .merchantId(merchant.getId())
                    .itemId((int) itemData.get("itemId"))
                    .quantity((int) itemData.get("quantity"))
                    .soldQuantity(0)
                    .price((int) itemData.get("price"))
                    .bundles((int) itemData.get("bundles"))
                    .status(HiredMerchantItemsDO.STATUS_ON_SALE)
                    .itemData((String) itemData.get("itemData"))
                    .build();
            
            hiredMerchantItemsMapper.insert(itemDO);
        }
    }
    
    public List<HiredMerchantTransactionsDO> getMerchantTransactions(int merchantId) {
        return hiredMerchantTransactionsMapper.selectListByQuery(QueryWrapper.create()
                .where(HiredMerchantTransactionsDO::getMerchantId).eq(merchantId)
                .and(HiredMerchantTransactionsDO::getType).eq(HiredMerchantTransactionsDO.TYPE_BUY));
    }
}
