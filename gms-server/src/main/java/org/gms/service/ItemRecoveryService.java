package org.gms.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mybatisflex.core.query.QueryWrapper;
import lombok.AllArgsConstructor;
import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.manipulator.InventoryManipulator;
import org.gms.client.processor.npc.DueyProcessor;
import org.gms.config.GameConfig;
import org.gms.dao.entity.ItemRecoveryLogsDO;
import org.gms.dao.mapper.ItemRecoveryLogsMapper;
import org.gms.model.dto.ItemInfoRtnDTO;
import org.gms.server.CashShop;
import org.gms.server.ItemInformationProvider;
import org.gms.util.I18nUtil;
import org.gms.util.ItemConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.gms.dao.entity.table.ItemTraceLogsDOTableDef.ITEM_TRACE_LOGS_DO;

/**
 * 物品找回服务
 */
@Service
@AllArgsConstructor
public class ItemRecoveryService {
    private static final Logger log = LoggerFactory.getLogger(ItemRecoveryService.class);
    private static final ExecutorService logExecutor = Executors.newSingleThreadExecutor();

    // 用于在内存中暂存被丢弃物品的UID，以优化拾取时的数据库操作
    private static final Set<Long> droppedItemUids = ConcurrentHashMap.newKeySet();

    private final ItemRecoveryLogsMapper itemRecoveryLogsMapper;
    private final TraceabilityService traceabilityService;
    private final ObjectMapper objectMapper;

    /**
     * 物品处理方式枚举
     */
    public enum DisposalType {
        /** 出售 */
        SELL,
        /** 丢弃 */
        DROP,
        /** 已过期 */
        EXPIRED,
        /** (脚本)删除 */
        DELETE,
        /** 卷轴失败 */
        SCROLL_FAIL,
        /** 合成失败 */
        MAKER_FAIL,
        /** 任务消耗 */
        QUEST;

        public String getI18nKey() {
            return "itemRecovery.disposalType." + this.name();
        }

        public String getI18nVal() {
            return I18nUtil.getLogMessage(getI18nKey());
        }
    }

    /**
     * 物品找回状态枚举
     */
    public enum RecoveryStatus {
        /** 待定 (用于丢弃的物品，等待地图上消失) */
        PENDING,
        /** 可找回 */
        RECOVERABLE,
        /** 已找回 */
        RECOVERED,
        /** 已拾取 */
        PICKED_UP,
        /** 已过期 */
        EXPIRED,
        /** 由 GM 找回 */
        RECOVERED_BY_GM;

        public String getI18nKey() {
            return "itemRecovery.status." + this.name();
        }

        public String getI18nVal() {
            return I18nUtil.getLogMessage(getI18nKey());
        }
    }

    /**
     * 服务启动时，修复因服务器重启而未被激活的丢弃物品记录。
     */

    public void updatePendingDrop() {
        ItemRecoveryLogsDO updateEntity = new ItemRecoveryLogsDO();
        updateEntity.setStatus(RecoveryStatus.RECOVERABLE.name());

        QueryWrapper where = QueryWrapper.create()
                .where(ItemRecoveryLogsDO::getStatus).eq(RecoveryStatus.PENDING.name())
                .and(ItemRecoveryLogsDO::getDisposalType).eq(DisposalType.DROP.name());

        int updatedCount = itemRecoveryLogsMapper.updateByQuery(updateEntity, where);
        if (updatedCount > 0) {
            log.info("【物品找回系统】启动修复：已将 {} 条处于 PENDING 状态的丢弃记录更新为 RECOVERABLE。", updatedCount);
        }
    }

    /**
     * 获取玩家可找回的物品列表
     * @param characterId 角色ID
     * @return 可找回物品的日志列表
     */
    public List<ItemRecoveryLogsDO> getRecoverableItems(int characterId) {
        QueryWrapper query = QueryWrapper.create()
                .where(ItemRecoveryLogsDO::getCharacterId).eq(characterId)
                .and(ItemRecoveryLogsDO::getDisposalType).ne(DisposalType.EXPIRED.name())
                .and(ItemRecoveryLogsDO::getStatus).eq(RecoveryStatus.RECOVERABLE.name())
                .and(ItemRecoveryLogsDO::getRecoveryDeadline).gt(System.currentTimeMillis())
                .orderBy(ItemRecoveryLogsDO::getDisposalTime, false); // 按时间倒序
        
        List<ItemRecoveryLogsDO> logs = itemRecoveryLogsMapper.selectListByQuery(query);

        // 填充i18n文本
        for (ItemRecoveryLogsDO logEntry : logs) {
            RecoveryStatus statusEnum = RecoveryStatus.valueOf(logEntry.getStatus());
            logEntry.setStatus(statusEnum.getI18nVal());

            DisposalType disposalTypeEnum = DisposalType.valueOf(logEntry.getDisposalType());
            logEntry.setDisposalType(disposalTypeEnum.getI18nVal());
        }
        
        return logs;
    }

    /**
     * 计算物品找回费用
     * @param item 物品对象
     * @return 费用数组 [金币, 点券]
     */
    public long[] calculateRecoveryFee(Item item) {
        long baseMeso = GameConfig.getServerLong("item_recovery_base_fee_meso", 50000L);
        long baseNx = GameConfig.getServerLong("item_recovery_base_fee_nx", 0L);
        double rate = GameConfig.getServerDouble("item_recovery_valuation_rate", 1.5);
        
        long itemPrice = 0;
        if (rate > 0) {
            ItemInformationProvider ii = ItemInformationProvider.getInstance();
            // 获取物品商店售价，如果为0则默认为1
            double price = ii.getPrice(item.getItemId(), 1);
            if (price <= 0) price = 1;
            itemPrice = (long) (price * item.getQuantity() * rate);
        }
        
        return new long[] { baseMeso + itemPrice, baseNx };
    }

    /**
     * 执行物品找回
     * @param c 客户端
     * @param logId 日志ID
     */
    @Transactional
    public boolean recoverItem(Client c, long logId) {
        Character chr = c.getPlayer();
        ItemRecoveryLogsDO logEntry = itemRecoveryLogsMapper.selectOneById(logId);

        if (logEntry == null) {
            chr.dropMessage(1, "找不到该找回记录。");
            return false;
        }

        if (logEntry.getCharacterId() != chr.getId()) {
            chr.dropMessage(1, "这不是您的物品。");
            return false;
        }

        if (!RecoveryStatus.RECOVERABLE.name().equals(logEntry.getStatus())) {
            chr.dropMessage(1, "该物品已找回或已过期。");
            return false;
        }

        if (System.currentTimeMillis() > logEntry.getRecoveryDeadline()) {
            logEntry.setStatus(RecoveryStatus.EXPIRED.name());
            itemRecoveryLogsMapper.update(logEntry);
            chr.dropMessage(1, "该物品已过期，无法找回。");
            return false;
        }

        try {
            // 反序列化物品
            ItemInfoRtnDTO itemDTO = objectMapper.readValue(logEntry.getItemData(), ItemInfoRtnDTO.class);
            
            // TODO: 长期建议: 为 item_recovery_logs 表增加 quantity 字段，以支持可堆叠物品的正确数量找回。
            int quantity = itemDTO.getQuantity();
            Item item = ItemConverter.restoreItemFromDTO(logEntry.getItemId(), (short) quantity, itemDTO);

            // 恢复原始 UID
            item.setUid(logEntry.getUid());

            // 计算费用
            long[] fees = calculateRecoveryFee(item);
            long mesoFee = fees[0];
            long nxFee = fees[1];
            int costType = GameConfig.getServerInt("item_recovery_cost_type", 0); // 0=金币, 1=点券, 2=混合

            // 检查费用
            if (costType == 0 || costType == 2) {
                if (chr.getMeso() < mesoFee) {
                    chr.dropMessage(1, "找回物品需要支付 " + mesoFee + " 金币。\r\n你当前只有 " + chr.getMeso() + " 金币。");
                    return false;
                }
            }
            if (costType == 1 || costType == 2) {
                if (chr.getCashShop().getCash(CashShop.NX_CREDIT) < nxFee) { // 使用点券
                    chr.dropMessage(1, "找回物品需要支付 " + nxFee + " 点券。\r\n你当前只有 " + chr.getCashShop().getCash(CashShop.NX_CREDIT) + " 点券。");
                    return false;
                }
            }

            // 扣除费用
            if (costType == 0 || costType == 2) {
                chr.gainMeso((int) -mesoFee, true);
            }
            if (costType == 1 || costType == 2) {
                chr.getCashShop().gainCash(CashShop.NX_CREDIT, (int) -nxFee);
            }

            // 通过快递发送物品
            String message = "您找回的物品已送达，请查收。";
            
            int packageId = DueyProcessor.createPackage(0, message, "找回系统", chr.getId(), true, item, 9010000, -1);
            
            if (packageId != -1) {
                // 物品数据已在 createPackage 中处理，这里无需额外操作

                // 记录溯源日志：物品找回
                traceabilityService.log(item, chr, TraceabilityService.ActionType.RECOVER, TraceabilityService.ActionSourceType.RECOVER_COMPLETE, item.getQuantity(), "包裹ID: " + packageId + ", 日志ID: " + logId, "物品找回");

                // 更新状态
                logEntry.setStatus(RecoveryStatus.RECOVERED.name());
                itemRecoveryLogsMapper.update(logEntry);

                // 发送快递通知
                DueyProcessor.showDueyNotification(chr);

                return true;
            } else {
                // 如果快递发送失败，回滚费用扣除
                throw new RuntimeException("创建快递包裹失败");
            }

        } catch (Exception e) {
            log.error("物品找回失败, LogID: " + logId, e);
            chr.dropMessage(1, "系统错误，找回失败。请联系管理员。");
            // 抛出异常以触发事务回滚
            throw new RuntimeException(e);
        }
    }
    /**
     * 记录物品找回日志
     * @param item 被处理的物品
     * @param character 所属角色
     * @param disposalType 处理方式
     */
    public boolean logRecovery(Item item, Character character, short quantity, ItemRecoveryService.DisposalType disposalType) {
        ItemRecoveryService.RecoveryStatus initialStatus = (disposalType == ItemRecoveryService.DisposalType.DROP)
                ? ItemRecoveryService.RecoveryStatus.PENDING
                : ItemRecoveryService.RecoveryStatus.RECOVERABLE;
        return logRecovery(item, character, quantity, disposalType, initialStatus);
    }
    /**
     * 记录物品找回日志
     * @param item 被处理的物品
     * @param character 所属角色
     * @param disposalType 处理方式
     * @param status 初始状态
     */
    public boolean logRecovery(Item item, Character character, short quantity, ItemRecoveryService.DisposalType disposalType, ItemRecoveryService.RecoveryStatus status) {
        if (item == null || character == null) return false;
        if (!InventoryManipulator.isValuableForRecovery(item)) return false;
        Item target = item.copy();
        logExecutor.submit(() -> {
            try {
                target.setQuantity(quantity);
                int recoveryHours = GameConfig.getServerInt("item_recovery_hours", 72);
                ItemInfoRtnDTO itemDTO = target.toInfoRtnDTO(true);
                long now = System.currentTimeMillis();
                long deadline = now + TimeUnit.HOURS.toMillis(recoveryHours);
                String initialStatus = status.name();
                ItemRecoveryLogsDO recoveryLogDO = ItemRecoveryLogsDO.builder()
                        .characterId(character.getId())
                        .uid(target.getUid())
                        .itemId(target.getItemId())
                        .itemData(objectMapper.writeValueAsString(itemDTO))
                        .disposalType(disposalType.name())
                        .disposalTime(now)
                        .recoveryDeadline(deadline)
                        .status(initialStatus)
                        .build();
                
                if (itemRecoveryLogsMapper.insert(recoveryLogDO) > 0) {
                    // 如果是丢弃操作，则将UID加入内存列表
                    if (disposalType == DisposalType.DROP) {
                        droppedItemUids.add(item.getUid());
                    }
                    return true;
                }
                return false;

            } catch (Exception e) {
                log.error("写入物品找回日志失败，物品UID: " + target.getUid(), e);
                return false;
            }
        });
        return false;
    }

    /**
     * 当物品被拾取时调用，检查并更新其找回状态。
     * @param uid 被拾取物品的UID
     */
    public void processItemPickup(long uid) {
        if (uid <= 0) {
            return;
        }
        // 检查UID是否存在于内存的丢弃列表中
        // remove 方法是原子操作，它会尝试移除元素并返回是否存在
        if (droppedItemUids.remove(uid)) {
            // 如果成功从内存列表中移除，说明该物品确实是刚刚被丢弃且现在被拾取了
            // 异步更新数据库状态，避免阻塞拾取操作
            logExecutor.submit(() -> {
                try {
                    ItemRecoveryLogsDO updateEntity = new ItemRecoveryLogsDO();
                    updateEntity.setStatus(RecoveryStatus.PICKED_UP.name());

                    QueryWrapper where = QueryWrapper.create()
                            .where(ItemRecoveryLogsDO::getUid).eq(uid)
                            .and(ItemRecoveryLogsDO::getStatus).eq(RecoveryStatus.PENDING.name()) // 确保只更新 PENDING 状态的记录
                            .and(ItemRecoveryLogsDO::getDisposalType).eq(DisposalType.DROP.name());

                    itemRecoveryLogsMapper.updateByQuery(updateEntity, where);
                } catch (Exception e) {
                    log.error("更新物品拾取状态失败，物品UID: " + uid, e);
                    // 如果更新失败，可以选择将UID重新加回列表以便重试，或者记录下来单独处理
                    // 为简单起见，这里只记录日志
                }
            });
        }
    }

    /**
     * 激活丢弃物品的找回状态
     * @param uid 物品UID
     */
    public void activateRecovery(long uid) {
        if (uid <= 0) return;
        // 当物品从地图上消失时，它可能还在内存列表中，需要先移除
        droppedItemUids.remove(uid);
        logExecutor.submit(() -> {
            try {
                ItemRecoveryLogsDO updateEntity = new ItemRecoveryLogsDO();
                updateEntity.setStatus(ItemRecoveryService.RecoveryStatus.RECOVERABLE.name());
                QueryWrapper where = QueryWrapper.create()
                        .where(ItemRecoveryLogsDO::getUid).eq(uid)
                        .and(ItemRecoveryLogsDO::getStatus).eq(ItemRecoveryService.RecoveryStatus.PENDING.name())
                        .and(ItemRecoveryLogsDO::getDisposalType).eq(ItemRecoveryService.DisposalType.DROP.name());
                itemRecoveryLogsMapper.updateByQuery(updateEntity, where);
            } catch (Exception e) {
                log.error("激活物品找回状态失败，物品UID: " + uid, e);
            }
        });
    }

    /**
     * 定时清理过期记录
     * 每天凌晨 4 点执行
     */
    @Scheduled(cron = "0 0 4 * * ?")
    public void cleanupExpiredLogs() {
        long now = System.currentTimeMillis();
        
        // 1. 将过期的 RECOVERABLE 记录更新为 EXPIRED
        ItemRecoveryLogsDO updateDO = new ItemRecoveryLogsDO();
        updateDO.setStatus(RecoveryStatus.EXPIRED.name());
        
        QueryWrapper updateQuery = QueryWrapper.create()
                .where(ItemRecoveryLogsDO::getStatus).eq(RecoveryStatus.RECOVERABLE.name())
                .and(ItemRecoveryLogsDO::getRecoveryDeadline).lt(now);
        
        int expiredCount = itemRecoveryLogsMapper.updateByQuery(updateDO, updateQuery);
        if (expiredCount > 0) {
            log.info("已将 {} 条过期的物品找回记录标记为 EXPIRED。", expiredCount);
        }

        // 2. 物理删除超过保留期限的 EXPIRED 记录
        int retentionDays = GameConfig.getServerInt("item_recovery_expiration_days", 7);
        long retentionMillis = TimeUnit.DAYS.toMillis(retentionDays);
        long deleteDeadline = now - retentionMillis;

        QueryWrapper deleteQuery = QueryWrapper.create()
                .where(ItemRecoveryLogsDO::getStatus).eq(RecoveryStatus.EXPIRED.name())
                .and(ItemRecoveryLogsDO::getDisposalTime).lt(deleteDeadline);

        int deletedCount = itemRecoveryLogsMapper.deleteByQuery(deleteQuery);
        if (deletedCount > 0) {
            log.info("已物理删除 {} 条超过 {} 天保留期的物品找回记录。", deletedCount, retentionDays);
        }
    }
}
