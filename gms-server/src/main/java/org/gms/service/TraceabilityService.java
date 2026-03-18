package org.gms.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mybatisflex.core.paginate.Page;
import com.mybatisflex.core.query.QueryWrapper;
import org.apache.logging.log4j.message.MapMessage;
import org.gms.client.Character;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.manipulator.InventoryManipulator;
import org.gms.config.GameConfig;
import org.gms.dao.entity.ItemRecoveryLogsDO;
import org.gms.dao.entity.ItemTraceLogsDO;
import org.gms.dao.mapper.ItemRecoveryLogsMapper;
import org.gms.dao.mapper.ItemTraceLogsMapper;
import org.gms.model.dto.ItemInfoRtnDTO;
import org.gms.model.dto.TraceabilityQueryDTO;
import org.gms.model.pojo.TraceabilityRules;
import org.gms.net.server.Server;
import org.gms.server.ItemInformationProvider;
import org.gms.server.logging.AuditContext;
import org.gms.server.logging.AuditLogger;
import org.gms.server.logging.LogModule;
import org.gms.server.maps.MapFactory;
import org.gms.util.RequireUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Lazy;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.gms.dao.entity.table.ItemTraceLogsDOTableDef.ITEM_TRACE_LOGS_D_O;

/**
 * 物品溯源服务 (V2.9 - 完善数据，移除角色名称获取).
 * <p>
 * 负责记录物品的全生命周期流转日志，其行为由 TraceabilityConfigService 提供的动态配置驱动。
 * 查询结果中将包含物品名称和地图名称，并使用带缓存的方法获取。
 * 移除角色名称的获取，以避免潜在的性能问题。
 * </p>
 */
@Service
public class TraceabilityService {

    private static final Logger log = LoggerFactory.getLogger(TraceabilityService.class);
    private static final ExecutorService logExecutor = Executors.newSingleThreadExecutor();

    private final ItemTraceLogsMapper itemTraceLogsMapper;
    private final ItemRecoveryLogsMapper itemRecoveryLogsMapper;
    private final ObjectMapper objectMapper;
    private final TraceabilityConfigService configService;
    // private final MapFactory mapFactory; // 移除 MapFactory 字段
    @Lazy
    private final CharacterService characterService; // 注入CharacterService

    @Autowired
    public TraceabilityService(
            ItemTraceLogsMapper itemTraceLogsMapper,
            ItemRecoveryLogsMapper itemRecoveryLogsMapper,
            @Qualifier("sparseItemObjectMapper") ObjectMapper objectMapper,
            TraceabilityConfigService configService,
            // MapFactory mapFactory, // 移除 MapFactory 注入
            @Lazy CharacterService characterService
    ) {
        this.itemTraceLogsMapper = itemTraceLogsMapper;
        this.itemRecoveryLogsMapper = itemRecoveryLogsMapper;
        this.objectMapper = objectMapper;
        this.configService = configService;
        // this.mapFactory = mapFactory; // 移除 MapFactory 赋值
        this.characterService = characterService;
    }

    /**
     * 根据条件分页查询物品溯源日志。
     *
     * @param queryDTO 查询条件和分页参数
     * @return 分页后的日志数据
     */
    public Page<ItemTraceLogsDO> queryLogs(TraceabilityQueryDTO queryDTO) {
        // [FIXED] Parse String UID from frontend to Long for database query
        Long uidForQuery = null;
        if (queryDTO.getUid() != null && !queryDTO.getUid().isEmpty()) {
            try {
                uidForQuery = Long.parseLong(queryDTO.getUid());
            } catch (NumberFormatException e) {
                log.warn("Invalid UID format received from frontend: {}", queryDTO.getUid());
                // 如果UID格式不正确，返回空页面，避免查询错误
                return new Page<>();
            }
        }

        QueryWrapper queryWrapper = QueryWrapper.create()
                .where(ITEM_TRACE_LOGS_D_O.UID.eq(uidForQuery, uidForQuery != null)) // Use parsed Long UID
                .and(ITEM_TRACE_LOGS_D_O.ITEM_ID.eq(queryDTO.getItemId(), queryDTO.getItemId() != null))
                .and(ITEM_TRACE_LOGS_D_O.CHARACTER_ID.eq(queryDTO.getCharacterId(), queryDTO.getCharacterId() != null))
                .and(ITEM_TRACE_LOGS_D_O.ACTION_TYPE.like(queryDTO.getActionType(), RequireUtil.isNotEmpty(queryDTO.getActionType())))
                .and(ITEM_TRACE_LOGS_D_O.ACTION_SOURCE.like(queryDTO.getActionSource(), RequireUtil.isNotEmpty(queryDTO.getActionSource())))
                .and(ITEM_TRACE_LOGS_D_O.TIMESTAMP.ge(queryDTO.getStartTime(), queryDTO.getStartTime() != null))
                .and(ITEM_TRACE_LOGS_D_O.TIMESTAMP.le(queryDTO.getEndTime(), queryDTO.getEndTime() != null))
                .orderBy(ITEM_TRACE_LOGS_D_O.TIMESTAMP.desc());

        Page<ItemTraceLogsDO> page = itemTraceLogsMapper.paginate(queryDTO.getPageNumber(), queryDTO.getPageSize(), queryWrapper);

        if (page.getRecords().isEmpty()) {
            return page;
        }

        // 1. 收集所有需要查询的角色ID
        Set<Integer> characterIds = page.getRecords().stream()
                .map(ItemTraceLogsDO::getCharacterId)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        // 2. 批量查询角色名称
        Map<Integer, String> characterNames = characterService.getChrNamesByIds(characterIds);

        // 3. 使用带缓存的方法填充物品名称、地图名称和角色名称
        ItemInformationProvider ii = ItemInformationProvider.getInstance();
        for (ItemTraceLogsDO record : page.getRecords()) {
            record.setItemName(ii.getName(record.getItemId()));
            if (record.getMapId() != null) {
                record.setMapName(MapFactory.loadPlaceName(record.getMapId()));
            }
            if (record.getCharacterId() != null) {
                record.setCharacterName(characterNames.getOrDefault(record.getCharacterId(), "未知角色"));
            }
        }

        return page;
    }

    /**
     * 获取溯源系统状态看板的统计数据。
     *
     * @return 包含多维度统计数据的Map
     */
    public Map<String, Object> getTraceabilityStats() {
        Map<String, Object> stats = new HashMap<>();

        // 1. 核心指标
        long totalRecords = itemTraceLogsMapper.selectCountByQuery(new QueryWrapper());
        long todayAdded = itemTraceLogsMapper.countToday();
        stats.put("totalRecords", totalRecords);
        stats.put("todayAdded", todayAdded);
        stats.put("avgPerHour", todayAdded > 0 ? todayAdded / 24.0 : 0);
        // 数据库表大小难以通过JDBC通用方式获取，暂时返回0，或需要特定数据库的查询
        stats.put("dbTableSizeMB", 0.0);

        // 2. 过去24小时每小时记录数 (用于折线图)
        long twentyFourHoursAgo = System.currentTimeMillis() - TimeUnit.HOURS.toMillis(24);
        List<Map<String, Object>> hourlyCounts = itemTraceLogsMapper.countHourlyLast24h(twentyFourHoursAgo);
        stats.put("hourlyCounts", hourlyCounts);

        // 3. ActionType占比 (用于饼图)
        List<Map<String, Object>> actionTypeCounts = itemTraceLogsMapper.countByActionType();
        stats.put("actionTypeCounts", actionTypeCounts);

        // 4. 记录最多的物品Top 10
        List<Map<String, Object>> topItems = itemTraceLogsMapper.findTopItems();
        stats.put("topItems", topItems);

        return stats;
    }

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

        TraceabilityRules config = configService.getTraceabilityConfig();
        TraceabilityRules.Enabled enabled = config.getEnabled();

        if (enabled == null || (!enabled.isDatabase() && !enabled.isLoki())) {
            return;
        }

        TraceabilityRules.LogActionSwitches logActionSwitches = config.getLogActionSwitches();
        if (logActionSwitches != null) {
            boolean isActionEnabled = false;
            switch (actionType) {
                case TRADE: isActionEnabled = logActionSwitches.isTRADE(); break;
                case DROP: isActionEnabled = logActionSwitches.isDROP(); break;
                case SELL: isActionEnabled = logActionSwitches.isSELL(); break;
                case STORAGE_IN: isActionEnabled = logActionSwitches.isSTORAGE_IN(); break;
                case STORAGE_OUT: isActionEnabled = logActionSwitches.isSTORAGE_OUT(); break;
                case GM_CREATE: isActionEnabled = logActionSwitches.isGM_CREATE(); break;
                default: isActionEnabled = true; // 如果不在开关列表里，默认认为是开启的或者根据其他逻辑处理
            }
            if (!isActionEnabled) {
                return;
            }
        }

        TraceabilityRules.TemporaryDisables temporaryDisables = config.getTemporaryDisables();
        if (temporaryDisables != null) {
            TraceabilityRules.DisableDetail disableRule = null;
            if (actionType == ActionType.LOOT) disableRule = temporaryDisables.getLOOT();
            else if (actionType == ActionType.SHOP_BUY) disableRule = temporaryDisables.getSHOP_BUY();

            if (disableRule != null && disableRule.isEnabled() && disableRule.getDisableUntil() != null) {
                try {
                    // ISO 8601 format
                    Date disableUntil = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").parse(disableRule.getDisableUntil());
                    if (new Date().before(disableUntil)) {
                        return;
                    }
                } catch (ParseException e) {
                    log.warn("解析临时禁用时间失败: {}", disableRule.getDisableUntil());
                }
            }
        }

        TraceabilityRules.Performance performance = config.getPerformance();
        if (performance != null && performance.getIgnoredMapIds() != null) {
            if (performance.getIgnoredMapIds().contains(mapId)) {
                return;
            }
        }

        boolean isValuable = InventoryManipulator.isValuableForRecovery(item);
        TraceabilityRules.RecordingTargets recordingTargets = config.getRecordingTargets();
        if (recordingTargets == null) return;
        
        TraceabilityRules.Target target = isValuable ? recordingTargets.getValuable() : recordingTargets.getNonValuable();

        boolean recordToDb = enabled.isDatabase() && target != null && target.isDatabase();
        boolean recordToLoki = enabled.isLoki() && target != null && target.isLoki();

        if (!recordToDb && !recordToLoki) {
            return;
        }

        Map<String, String> contextData = AuditContext.get();

        logExecutor.submit(() -> {
            try {
                String itemSnapshotJson = objectMapper.writeValueAsString(item.toInfoRtnDTO(true));

                if (recordToDb) {
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
                            .itemSnapshot(itemSnapshotJson)
                            .timestamp(System.currentTimeMillis())
                            .memo(memo);
                    itemTraceLogsMapper.insert(builder.build());
                }

                if (recordToLoki) {
                    MapMessage logData = new MapMessage()
                            .with("msg", actionSource)
                            .with("itm", item.getItemId())
                            .with("itemName", ItemInformationProvider.getInstance().getName(item.getItemId()))
                            .with("cnt", quantityChange)
                            .with("itemData", itemSnapshotJson);
                    
                    for (Map.Entry<String, String> entry : contextData.entrySet()) {
                        logData.with(entry.getKey(), entry.getValue());
                    }
                    if (targetInfo != null && !targetInfo.isEmpty()) {
                        logData.with("targetChr", targetInfo);
                    }

                    AuditLogger.info(LogModule.ITEM.name(), actionType.name(), logData);
                }
            } catch (Exception e) {
                log.error("写入物品溯源双重日志失败，物品UID: " + item.getUid(), e);
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
                int recoveryHours = GameConfig.getServerInt("item_recovery_hours", 72);

                ItemInfoRtnDTO itemDTO = item.toInfoRtnDTO(true);
                long now = System.currentTimeMillis();
                long deadline = now + TimeUnit.HOURS.toMillis(recoveryHours);
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
                log.error("写入物品找回日志失败，物品UID: " + item.getUid(), e);
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
