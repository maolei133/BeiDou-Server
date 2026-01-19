package org.gms.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mybatisflex.core.query.QueryWrapper;
import com.mybatisflex.core.update.UpdateChain;
import lombok.RequiredArgsConstructor;
import org.gms.client.inventory.Equip;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.InventoryType;
import org.gms.constants.inventory.ItemConstants;
import org.gms.dao.entity.HiredMerchantItemsDO;
import org.gms.dao.entity.HiredMerchantTransactionsDO;
import org.gms.dao.entity.HiredMerchantsDO;
import org.gms.dao.mapper.HiredMerchantItemsMapper;
import org.gms.dao.mapper.HiredMerchantTransactionsMapper;
import org.gms.dao.mapper.HiredMerchantsMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class HiredMerchantService {

    private final HiredMerchantsMapper hiredMerchantsMapper;
    private final HiredMerchantItemsMapper hiredMerchantItemsMapper;
    private final HiredMerchantTransactionsMapper hiredMerchantTransactionsMapper;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public HiredMerchantsDO getActiveMerchantByOwnerId(int ownerId) {
        return hiredMerchantsMapper.selectOneByQuery(QueryWrapper.create()
                .select()
                .from(HiredMerchantsDO.class)
                .where(HiredMerchantsDO::getOwnerId).eq(ownerId)
                .and(HiredMerchantsDO::getStatus).eq("ACTIVE"));
    }

    public HiredMerchantsDO getPreparingMerchantByOwnerId(int ownerId) {
        return hiredMerchantsMapper.selectOneByQuery(QueryWrapper.create()
                .select()
                .from(HiredMerchantsDO.class)
                .where(HiredMerchantsDO::getOwnerId).eq(ownerId)
                .and(HiredMerchantsDO::getStatus).eq("PREPARING"));
    }

    public List<HiredMerchantsDO> getActiveMerchantsByWorldId(int worldId) {
        return hiredMerchantsMapper.selectListByQuery(QueryWrapper.create()
                .select()
                .from(HiredMerchantsDO.class)
                .where(HiredMerchantsDO::getWorldId).eq(worldId)
                .and(HiredMerchantsDO::getStatus).eq("ACTIVE"));
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
                .set(HiredMerchantItemsDO::getStatus, "RETURNED")
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
        // 1. Add Transaction
        HiredMerchantTransactionsDO transaction = HiredMerchantTransactionsDO.builder()
                .merchantId(merchantId)
                .itemId(itemId)
                .buyerId(buyerId)
                .type("BUY")
                .quantity(quantity)
                .price(unitPrice)
                .totalPrice(totalPrice)
                .timestamp(System.currentTimeMillis())
                .build();
        hiredMerchantTransactionsMapper.insert(transaction);

        // 2. Update Sold Quantity
        // 如果售罄，更新状态为 SOLD_OUT
        UpdateChain.of(HiredMerchantItemsDO.class)
                .setRaw(HiredMerchantItemsDO::getSoldQuantity, "sold_quantity + " + quantity)
                .setRaw(HiredMerchantItemsDO::getStatus, "CASE WHEN sold_quantity + " + quantity + " >= bundles THEN 'SOLD_OUT' ELSE status END")
                .where(HiredMerchantItemsDO::getId).eq(itemDbId)
                .update();

        // 3. Update Mesos
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
            
            // 更新所有已售罄且未结算的物品为已结算
            UpdateChain.of(HiredMerchantItemsDO.class)
                    .set(HiredMerchantItemsDO::getSettledTime, System.currentTimeMillis())
                    .where(HiredMerchantItemsDO::getMerchantId).eq(merchantId)
                    .and(HiredMerchantItemsDO::getStatus).eq("SOLD_OUT")
                    .and(HiredMerchantItemsDO::getSettledTime).isNull()
                    .update();
            
            return mesos;
        }
        return 0;
    }

    public List<HiredMerchantItemsDO> getMerchantItems(int merchantId) {
        // 销售列表：展示当前待售、售罄（已售未结算）的物品
        return hiredMerchantItemsMapper.selectListByQuery(QueryWrapper.create()
                .select()
                .from(HiredMerchantItemsDO.class)
                .where(HiredMerchantItemsDO::getMerchantId).eq(merchantId)
                .and(HiredMerchantItemsDO::getStatus).ne("RETURNED")
                .and("(status = 'ON_SALE' OR (status = 'SOLD_OUT' AND settled_time IS NULL))"));
    }

    public List<HiredMerchantsDO> getRetrieveableMerchants(int ownerId) {
        return hiredMerchantsMapper.selectListByQuery(QueryWrapper.create()
                .select()
                .from(HiredMerchantsDO.class)
                .where(HiredMerchantsDO::getOwnerId).eq(ownerId)
                .and(HiredMerchantsDO::getStatus).in("CLOSED", "EXPIRED"));
    }

    public List<HiredMerchantsDO> getZombieMerchants(int ownerId) {
        return hiredMerchantsMapper.selectListByQuery(QueryWrapper.create()
                .select()
                .from(HiredMerchantsDO.class)
                .where(HiredMerchantsDO::getOwnerId).eq(ownerId)
                .and(HiredMerchantsDO::getStatus).eq("ACTIVE"));
    }

    public List<HiredMerchantItemsDO> getRetrieveableItems(int merchantId) {
        return hiredMerchantItemsMapper.selectListByQuery(QueryWrapper.create()
                .select()
                .from(HiredMerchantItemsDO.class)
                .where(HiredMerchantItemsDO::getMerchantId).eq(merchantId)
                .and(HiredMerchantItemsDO::getStatus).ne("RETURNED")
                .and("bundles > sold_quantity")); // 使用原生 SQL 片段进行列比较
    }

    public List<HiredMerchantsDO> getAllActiveMerchants() {
        return hiredMerchantsMapper.selectListByQuery(QueryWrapper.create()
                .select()
                .from(HiredMerchantsDO.class)
                .where(HiredMerchantsDO::getStatus).eq("ACTIVE"));
    }

    @Transactional
    public void cleanupOldRecords(int days) {
        long cutoffTime = System.currentTimeMillis() - (days * 24 * 60 * 60 * 1000L);

        // 1. 删除旧的交易记录
        hiredMerchantTransactionsMapper.deleteByQuery(QueryWrapper.create()
                .where(HiredMerchantTransactionsDO::getTimestamp).lt(cutoffTime));

        // 2. 查找待删除的候选记录（已关闭/已过期，旧记录，无金币）
        List<HiredMerchantsDO> candidates = hiredMerchantsMapper.selectListByQuery(QueryWrapper.create()
                .select(HiredMerchantsDO::getId)
                .from(HiredMerchantsDO.class)
                .where(HiredMerchantsDO::getStatus).in("CLOSED", "EXPIRED")
                .and(HiredMerchantsDO::getCloseTime).lt(cutoffTime)
                .and(HiredMerchantsDO::getMesos).eq(0));

        for (HiredMerchantsDO merchant : candidates) {
            // 检查是否有物品未归还
            long count = hiredMerchantItemsMapper.selectCountByQuery(QueryWrapper.create()
                    .where(HiredMerchantItemsDO::getMerchantId).eq(merchant.getId())
                    .and(HiredMerchantItemsDO::getStatus).ne("RETURNED"));
            
            // 如果所有物品都已归还或售罄，则可以删除
            // 这里简化逻辑：只要没有未归还的物品，就认为可以删除（假设售罄的物品不需要保留太久）
            // 如果需要保留售罄记录，可以增加条件

            if (count == 0) {
                // 安全删除
                hiredMerchantItemsMapper.deleteByQuery(QueryWrapper.create()
                        .where(HiredMerchantItemsDO::getMerchantId).eq(merchant.getId()));
                hiredMerchantsMapper.deleteById(merchant.getId());
            }
        }
    }

    public String serializeItem(Item item) {
        try {
            Map<String, Object> map = new HashMap<>();
            map.put("itemId", item.getItemId());
            map.put("position", item.getPosition());
            map.put("quantity", item.getQuantity());

            if (item.getPetId() > -1) {
                map.put("petId", item.getPetId());
            }
            if (item.getOwner() != null && !item.getOwner().isEmpty()) {
                map.put("owner", item.getOwner());
            }
            if (item.getFlag() != 0) {
                map.put("flag", item.getFlag());
            }
            if (item.getExpiration() != -1) {
                map.put("expiration", item.getExpiration());
            }
            if (item.getGiftFrom() != null && !item.getGiftFrom().isEmpty()) {
                map.put("giftFrom", item.getGiftFrom());
            }
            if (item.getSN() > 0) {
                map.put("sn", item.getSN());
            }

            if (item instanceof Equip) {
                Equip equip = (Equip) item;
                if (equip.getUpgradeSlots() != 0) map.put("upgradeSlots", equip.getUpgradeSlots());
                if (equip.getLevel() != 0) map.put("level", equip.getLevel());
                if (equip.getStr() != 0) map.put("str", equip.getStr());
                if (equip.getDex() != 0) map.put("dex", equip.getDex());
                if (equip.getInt() != 0) map.put("int", equip.getInt());
                if (equip.getLuk() != 0) map.put("luk", equip.getLuk());
                if (equip.getHp() != 0) map.put("hp", equip.getHp());
                if (equip.getMp() != 0) map.put("mp", equip.getMp());
                if (equip.getWatk() != 0) map.put("watk", equip.getWatk());
                if (equip.getMatk() != 0) map.put("matk", equip.getMatk());
                if (equip.getWdef() != 0) map.put("wdef", equip.getWdef());
                if (equip.getMdef() != 0) map.put("mdef", equip.getMdef());
                if (equip.getAcc() != 0) map.put("acc", equip.getAcc());
                if (equip.getAvoid() != 0) map.put("avoid", equip.getAvoid());
                if (equip.getHands() != 0) map.put("hands", equip.getHands());
                if (equip.getSpeed() != 0) map.put("speed", equip.getSpeed());
                if (equip.getJump() != 0) map.put("jump", equip.getJump());
                if (equip.getVicious() != 0) map.put("vicious", equip.getVicious());
                if (equip.getItemLevel() > 1) map.put("itemLevel", equip.getItemLevel());
                if (equip.getItemExp() > 0) map.put("itemExp", equip.getItemExp());
                if (equip.getRingId() > -1) map.put("ringId", equip.getRingId());
            }

            return objectMapper.writeValueAsString(map);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public Item deserializeItem(String json) {
        try {
            Map<String, Object> map = objectMapper.readValue(json, Map.class);
            int itemId = (int) map.get("itemId");
            short position = ((Number) map.get("position")).shortValue();
            short quantity = ((Number) map.get("quantity")).shortValue();
            int petId = map.containsKey("petId") ? (int) map.get("petId") : -1;
            
            Item item;
            if (ItemConstants.getInventoryType(itemId) == InventoryType.EQUIP) {
                item = new Equip(itemId, position, 0);
            } else {
                item = new Item(itemId, position, quantity, petId);
            }
            
            if (map.containsKey("owner")) item.setOwner((String) map.get("owner"));
            if (map.containsKey("flag")) item.setFlag(((Number) map.get("flag")).shortValue());
            if (map.containsKey("expiration")) item.setExpiration(((Number) map.get("expiration")).longValue());
            if (map.containsKey("giftFrom")) item.setGiftFrom((String) map.get("giftFrom"));
            if (map.containsKey("sn")) item.setSN(((Number) map.get("sn")).intValue());
            
            if (item instanceof Equip equip) {
                if (map.containsKey("upgradeSlots")) equip.setUpgradeSlots(((Number) map.get("upgradeSlots")).byteValue());
                if (map.containsKey("level")) equip.setLevel(((Number) map.get("level")).shortValue());
                if (map.containsKey("str")) equip.setStr(((Number) map.get("str")).shortValue());
                if (map.containsKey("dex")) equip.setDex(((Number) map.get("dex")).shortValue());
                if (map.containsKey("int")) equip.setInt(((Number) map.get("int")).shortValue());
                if (map.containsKey("luk")) equip.setLuk(((Number) map.get("luk")).shortValue());
                if (map.containsKey("hp")) equip.setHp(((Number) map.get("hp")).shortValue());
                if (map.containsKey("mp")) equip.setMp(((Number) map.get("mp")).shortValue());
                if (map.containsKey("watk")) equip.setWatk(((Number) map.get("watk")).shortValue());
                if (map.containsKey("matk")) equip.setMatk(((Number) map.get("matk")).shortValue());
                if (map.containsKey("wdef")) equip.setWdef(((Number) map.get("wdef")).shortValue());
                if (map.containsKey("mdef")) equip.setMdef(((Number) map.get("mdef")).shortValue());
                if (map.containsKey("acc")) equip.setAcc(((Number) map.get("acc")).shortValue());
                if (map.containsKey("avoid")) equip.setAvoid(((Number) map.get("avoid")).shortValue());
                if (map.containsKey("hands")) equip.setHands(((Number) map.get("hands")).shortValue());
                if (map.containsKey("speed")) equip.setSpeed(((Number) map.get("speed")).shortValue());
                if (map.containsKey("jump")) equip.setJump(((Number) map.get("jump")).shortValue());
                if (map.containsKey("vicious")) equip.setVicious(((Number) map.get("vicious")).shortValue());
                if (map.containsKey("itemLevel")) equip.setItemLevel(((Number) map.get("itemLevel")).shortValue());
                if (map.containsKey("itemExp")) equip.setItemExp(((Number) map.get("itemExp")).intValue());
                if (map.containsKey("ringId")) equip.setRingId(((Number) map.get("ringId")).intValue());
            }
            
            return item;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Transactional
    public void restoreMerchantItems(int merchantId) {
        // 1. 检查商店是否存在
        HiredMerchantsDO merchant = hiredMerchantsMapper.selectOneById(merchantId);
        if (merchant == null) {
            throw new IllegalArgumentException("未找到商店: " + merchantId);
        }

        // 2. 查找所有未归还的物品
        List<HiredMerchantItemsDO> items = hiredMerchantItemsMapper.selectListByQuery(QueryWrapper.create()
                .select()
                .from(HiredMerchantItemsDO.class)
                .where(HiredMerchantItemsDO::getMerchantId).eq(merchantId)
                .and(HiredMerchantItemsDO::getStatus).ne("RETURNED"));

        // 3. 将物品状态重置为 ON_SALE
        if ("ACTIVE".equals(merchant.getStatus())) {
            merchant.setStatus("CLOSED");
            merchant.setCloseTime(System.currentTimeMillis());
            hiredMerchantsMapper.update(merchant);
        }
        
        for (HiredMerchantItemsDO item : items) {
            if (item.getBundles() > item.getSoldQuantity() && "SOLD_OUT".equals(item.getStatus())) {
                item.setStatus("ON_SALE");
                hiredMerchantItemsMapper.update(item);
            }
        }
    }

    @Transactional
    public void restoreFromBackup(File backupFile) throws Exception {
        Map<String, Object> backupData = objectMapper.readValue(backupFile, Map.class);
        
        int ownerId = (int) backupData.get("ownerId");
        String ownerName = (String) backupData.get("ownerName");
        String description = (String) backupData.get("description");
        int itemId = (int) backupData.get("itemId");
        long mesos = ((Number) backupData.get("mesos")).longValue();
        int channel = (int) backupData.get("channel");
        int mapId = (int) backupData.get("mapId");
        
        List<Map<String, Object>> items = (List<Map<String, Object>>) backupData.get("items");
        
        HiredMerchantsDO merchant = HiredMerchantsDO.builder()
                .ownerId(ownerId)
                .description(description != null ? description : "从备份恢复")
                .itemId(itemId > 0 ? itemId : 5030000)
                .status("CLOSED")
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
                    .status("ON_SALE")
                    .itemData((String) itemData.get("itemData"))
                    .build();
            
            hiredMerchantItemsMapper.insert(itemDO);
        }
    }
    
    public List<HiredMerchantTransactionsDO> getMerchantTransactions(int merchantId) {
        // 交易记录：查看本次主动闭店前的所有销售数据
        // 因此返回所有 BUY 类型的记录，无论是否结算
        return hiredMerchantTransactionsMapper.selectListByQuery(QueryWrapper.create()
                .select()
                .from(HiredMerchantTransactionsDO.class)
                .where(HiredMerchantTransactionsDO::getMerchantId).eq(merchantId)
                .and(HiredMerchantTransactionsDO::getType).eq("BUY"));
    }
}
