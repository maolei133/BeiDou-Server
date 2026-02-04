package org.gms.service;

import com.alibaba.fastjson2.JSON;
import lombok.RequiredArgsConstructor;
import org.gms.client.Character;
import org.gms.client.inventory.Item;
import org.gms.client.processor.npc.DueyProcessor;
import org.gms.config.GameConfig;
import org.gms.dao.entity.ItemRecoveryLogsDO;
import org.gms.dao.entity.ItemTraceLogsDO;
import org.gms.dao.mapper.ItemRecoveryLogsMapper;
import org.gms.dao.mapper.ItemTraceLogsMapper;
import org.gms.model.dto.ItemInfoRtnDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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

    public enum ActionType {
        CREATE, DROP, SELL, TRADE, STORAGE_IN, STORAGE_OUT, 
        HIRED_MERCHANT_ADD, HIRED_MERCHANT_BUY, HIRED_MERCHANT_RETURN,
        PLAYER_SHOP_ADD, PLAYER_SHOP_BUY, PLAYER_SHOP_RETURN,
        SHOP_BUY, SHOP_SELL,
        DUEY_SEND, DUEY_RECEIVE, DUEY_RETURN, DUEY_DELETE,
        USE, CONSUME, SCROLL, UPGRADE, REWARD, LOOT, ADMIN_CREATE, ADMIN_DELETE
    }

    /**
     * 记录物品流转日志
     *
     * @param item           涉及的物品对象
     * @param character      操作的角色
     * @param actionType     行为类型
     * @param actionSource   行为来源 (如 "NPC商店", "玩家交易")
     * @param quantityChange 数量变化 (正数增加，负数减少，0表示状态变更)
     * @param targetInfo     交互对象信息 (如交易对手角色名)
     * @param memo           备注
     */
    public void log(Item item, Character character, ActionType actionType, String actionSource, int quantityChange, String targetInfo, String memo) {
        if (item == null || character == null) {
            return;
        }
        log(item, character.getAccountId(), character.getId(), character.getMapId(), actionType, actionSource, quantityChange, targetInfo, memo);
    }

    /**
     * 记录物品流转日志 (通过ID)
     */
    public void log(Item item, int accountId, int characterId, int mapId, ActionType actionType, String actionSource, int quantityChange, String targetInfo, String memo) {
        if (item == null) {
            return;
        }

        // 异步写入数据库，避免阻塞主线程
        logExecutor.submit(() -> {
            try {
                ItemTraceLogsDO logDO = ItemTraceLogsDO.builder()
                        .uid(item.getUid())
                        .accountId(accountId)
                        .characterId(characterId)
                        .actionType(actionType.name())
                        .actionSource(actionSource)
                        .mapId(mapId)
                        .itemId(item.getItemId())
                        .quantityChange(quantityChange)
                        .targetInfo(targetInfo)
                        .itemSnapshot(JSON.toJSONString(item)) // 序列化物品快照
                        .timestamp(System.currentTimeMillis())
                        .memo(memo)
                        .build();

                itemTraceLogsMapper.insert(logDO);

            } catch (Exception e) {
                log.error("插入物品溯源日志失败，物品UID: " + item.getUid(), e);
            }
        });
    }

    /**
     * 简化的日志记录方法
     */
    public void log(Item item, Character character, ActionType actionType, String actionSource) {
        log(item, character, actionType, actionSource, 0, null, null);
    }

    /**
     * 记录物品找回日志
     *
     * @param item         被处理的物品
     * @param character    所属角色
     * @param disposalType 处理方式 (SELL, DROP)
     */
    public void logRecovery(Item item, Character character, String disposalType) {
        if (item == null || character == null) {
            return;
        }

        logExecutor.submit(() -> {
            try {
                // 使用 DueyProcessor 的转换逻辑来序列化物品，保证格式统一
                ItemInfoRtnDTO itemDTO = DueyProcessor.convertItemToDTO(item);
                
                long now = System.currentTimeMillis();
                // 默认找回有效期 24 小时，可配置
                long deadline = now + (GameConfig.getServerInt("item_recovery_hours", 24) * 60 * 60 * 1000L);

                ItemRecoveryLogsDO recoveryLogDO = ItemRecoveryLogsDO.builder()
                        .characterId(character.getId())
                        .uid(item.getUid())
                        .itemId(item.getItemId())
                        .itemData(JSON.toJSONString(itemDTO))
                        .disposalType(disposalType)
                        .disposalTime(now)
                        .recoveryDeadline(deadline)
                        .status("RECOVERABLE")
                        .build();

                itemRecoveryLogsMapper.insert(recoveryLogDO);

            } catch (Exception e) {
                log.error("插入物品找回日志失败，物品UID: " + item.getUid(), e);
            }
        });
    }
}
