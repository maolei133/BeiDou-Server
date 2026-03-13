package org.gms.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mybatisflex.core.query.QueryWrapper;
import lombok.RequiredArgsConstructor;
import org.gms.client.Character;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.manipulator.InventoryManipulator;
import org.gms.config.GameConfig;
import org.gms.dao.entity.ItemRecoveryLogsDO;
import org.gms.dao.entity.ItemTraceLogsDO;
import org.gms.dao.mapper.ItemRecoveryLogsMapper;
import org.gms.dao.mapper.ItemTraceLogsMapper;
import org.gms.model.dto.ItemInfoRtnDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.gms.dao.entity.table.ItemTraceLogsDOTableDef.ITEM_TRACE_LOGS_D_O;

/**
 * 物品溯源服务
 * 负责记录物品的全生命周期流转日志
 */
@Service
@RequiredArgsConstructor
public class TraceabilityService {

    private static final Logger log = LoggerFactory.getLogger(TraceabilityService.class);
    private static final ExecutorService logExecutor = Executors.newSingleThreadExecutor();
    
    private final ItemTraceLogsMapper itemTraceLogsMapper;
    private final ItemRecoveryLogsMapper itemRecoveryLogsMapper;
    private final ObjectMapper objectMapper;

    public enum ActionType {
        // 基础操作
        CREATE, DROP, SELL, TRADE, 
        
        // 仓库与商城
        STORAGE_IN, STORAGE_OUT, CS_IN, CS_OUT,
        
        // 雇佣商人与个人商店
        HIRED_MERCHANT_ADD, HIRED_MERCHANT_BUY, HIRED_MERCHANT_RETURN,
        PLAYER_SHOP_ADD, PLAYER_SHOP_BUY, PLAYER_SHOP_RETURN,
        
        // NPC商店
        SHOP_BUY, SHOP_SELL,
        
        // 快递
        DUEY_SEND, DUEY_RECEIVE, DUEY_RETURN, DUEY_DELETE,
        
        // 消耗与使用
        USE, CONSUME, SCROLL, UPGRADE, 
        
        // 获取来源
        REWARD, LOOT, GACHAPON_REWARD, QUEST_REWARD, QUEST_CONSUME,
        
        // 制作与合成
        CRAFT_CREATE, CRAFT_CONSUME, MERGE,
        
        // 地图生成与消失
        SPAWN, DESPAWN_EXPIRED, PICKUP,
        
        // 管理员操作
        ADMIN_CREATE, ADMIN_DELETE, GM_CREATE, GM_MODIFY
    }

    /**
     * 记录物品流转日志
     * @param item 涉及的物品对象
     * @param character 操作的角色
     * @param actionType 行为类型
     * @param actionSource 行为来源 (如 "NPC商店", "玩家交易")
     */
    public void log(Item item, Character character, ActionType actionType, String actionSource) {
        log(item, character, actionType, actionSource, 0, null, null);
    }

    /**
     * 记录物品流转日志 (带数量变化)
     * @param item 涉及的物品对象
     * @param character 操作的角色
     * @param actionType 行为类型
     * @param actionSource 行为来源
     * @param quantityChange 数量变化
     */
    public void log(Item item, Character character, ActionType actionType, String actionSource, int quantityChange) {
        log(item, character, actionType, actionSource, quantityChange, null, null);
    }

    /**
     * 记录物品流转日志 (全参数)
     * @param item 涉及的物品对象
     * @param character 操作的角色
     * @param actionType 行为类型
     * @param actionSource 行为来源 (如 "NPC商店", "玩家交易")
     * @param quantityChange 数量变化 (正数增加，负数减少，0表示状态变更)
     * @param targetInfo 交互对象信息 (如交易对手角色名)
     * @param memo 备注
     */
    public void log(Item item, Character character, ActionType actionType, String actionSource, int quantityChange, String targetInfo, String memo) {
        if (item == null || character == null) return;
        log(item, character.getAccountId(), character.getId(), character.getMapId(), actionType, actionSource, quantityChange, targetInfo, memo);
    }

    /**
     * 记录物品流转日志 (通过ID)
     * @param item 涉及的物品对象
     * @param accountId 账号ID
     * @param characterId 角色ID
     * @param mapId 地图ID
     * @param actionType 行为类型
     * @param actionSource 行为来源
     * @param quantityChange 数量变化
     * @param targetInfo 交互对象信息
     * @param memo 备注
     */
    public void log(Item item, int accountId, int characterId, int mapId, ActionType actionType, String actionSource, int quantityChange, String targetInfo, String memo) {
        if (item == null) return;

        // 价值判断过滤，防止记录大量低价值物品
        if (!InventoryManipulator.isValuableForRecovery(item)) return;

        logExecutor.submit(() -> {
            try {
                ItemTraceLogsDO.ItemTraceLogsDOBuilder builder = ItemTraceLogsDO.builder()
                        .uid(item.getUid())
                        .accountId(accountId)
                        .characterId(characterId)
                        .actionType(actionType.name())
                        .actionSource(actionSource)
                        .mapId(mapId)
                        .itemId(item.getItemId())
                        .quantityChange(quantityChange)
                        .targetInfo(targetInfo)
                        .itemSnapshot(objectMapper.writeValueAsString(item.toInfoRtnDTO(true))) // **修正**: 确保包含数量
                        .timestamp(System.currentTimeMillis())
                        .memo(memo);
                itemTraceLogsMapper.insert(builder.build());
            } catch (Exception e) {
                log.error("插入物品溯源日志失败，物品UID: " + item.getUid(), e);
            }
        });
    }

    /**
     * 记录物品找回日志
     * @param item 被处理的物品
     * @param character 所属角色
     * @param disposalType 处理方式 (SELL, DROP)
     */
    public void logRecovery(Item item, Character character, String disposalType) {
        if (item == null || character == null) return;
        if (!InventoryManipulator.isValuableForRecovery(item)) return;

        logExecutor.submit(() -> {
            try {
                // **核心修正**: 调用 toInfoRtnDTO(true) 以确保包含 quantity 字段
                ItemInfoRtnDTO itemDTO = item.toInfoRtnDTO(true);
                long now = System.currentTimeMillis();
                long deadline = now + (GameConfig.getServerInt("item_recovery_hours", 24) * 60 * 60 * 1000L);
                String initialStatus = "DROP".equals(disposalType) ? "PENDING" : "RECOVERABLE";

                ItemRecoveryLogsDO recoveryLogDO = ItemRecoveryLogsDO.builder()
                        .characterId(character.getId())
                        .uid(item.getUid())
                        .itemId(item.getItemId())
                        .itemData(objectMapper.writeValueAsString(itemDTO))
                        .disposalType(disposalType)
                        .disposalTime(now)
                        .recoveryDeadline(deadline)
                        .status(initialStatus)
                        .build();
                itemRecoveryLogsMapper.insert(recoveryLogDO);
            } catch (Exception e) {
                log.error("插入物品找回日志失败，物品UID: " + item.getUid(), e);
            }
        });
    }
    
    /**
     * 激活丢弃物品的找回状态
     * @param uid 物品UID
     */
    public void activateRecovery(long uid) {
        if (uid <= 0) return;
        logExecutor.submit(() -> {
            try {
                ItemRecoveryLogsDO updateEntity = new ItemRecoveryLogsDO();
                updateEntity.setStatus("RECOVERABLE");
                QueryWrapper where = QueryWrapper.create()
                        .where(ItemRecoveryLogsDO::getUid).eq(uid)
                        .and(ItemRecoveryLogsDO::getStatus).eq("PENDING")
                        .and(ItemRecoveryLogsDO::getDisposalType).eq("DROP");
                itemRecoveryLogsMapper.updateByQuery(updateEntity, where);
            } catch (Exception e) {
                log.error("激活物品找回状态失败，物品UID: " + uid, e);
            }
        });
    }

    /**
     * 定时清理过期溯源日志 (每天凌晨3点)
     */
    @Scheduled(cron = "0 0 3 * * ?")
    public void cleanupTraceLogs() {
        long now = System.currentTimeMillis();
        int retentionDays = GameConfig.getServerInt("trace_log_retention_days", 30);
        long deleteDeadline = now - TimeUnit.DAYS.toMillis(retentionDays);
        int deletedCount = itemTraceLogsMapper.deleteByQuery(QueryWrapper.create().where(ITEM_TRACE_LOGS_D_O.TIMESTAMP.lt(deleteDeadline)));
        if (deletedCount > 0) log.info("已物理删除 {} 条超过 {} 天保留期的物品溯源日志。", deletedCount, retentionDays);

        int shortRetentionDays = GameConfig.getServerInt("trace_log_short_retention_days", 3);
        long shortDeleteDeadline = now - TimeUnit.DAYS.toMillis(shortRetentionDays);
        int shortDeletedCount = itemTraceLogsMapper.deleteByQuery(QueryWrapper.create()
                .where(ITEM_TRACE_LOGS_D_O.TIMESTAMP.lt(shortDeleteDeadline))
                .and(ITEM_TRACE_LOGS_D_O.ACTION_TYPE.in(ActionType.SPAWN.name(), ActionType.DESPAWN_EXPIRED.name())));
        if (shortDeletedCount > 0) log.info("已物理删除 {} 条超过 {} 天保留期的短期物品溯源日志 (SPAWN/DESPAWN)。", shortDeletedCount, shortRetentionDays);
    }
}
