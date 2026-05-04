package org.gms.net.server.task;

import com.mybatisflex.core.query.QueryWrapper;
import org.gms.dao.mapper.ItemTraceLogsMapper;
import org.gms.model.pojo.TraceabilityRules;
import org.gms.service.TraceabilityConfigService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

import static org.gms.dao.entity.table.ItemTraceLogsDOTableDef.ITEM_TRACE_LOGS_DO;

/**
 * 物品溯源日志清理定时任务 (V2.3 - 强类型配置版).
 */
@Component
public class TraceabilityCleanupTask {

    private static final Logger log = LoggerFactory.getLogger(TraceabilityCleanupTask.class);

    private final ItemTraceLogsMapper itemTraceLogsMapper;
    private final TraceabilityConfigService configService;

    public TraceabilityCleanupTask(ItemTraceLogsMapper itemTraceLogsMapper, TraceabilityConfigService configService) {
        this.itemTraceLogsMapper = itemTraceLogsMapper;
        this.configService = configService;
    }

    @Scheduled(cron = "0 0 4 * * ?") // 每天凌晨4点执行
    public void cleanupTraceLogs() {
        TraceabilityRules config = configService.getTraceabilityConfig();
        TraceabilityRules.Retention retention = config.getRetention();

        if (retention == null) {
            log.warn("溯源日志清理任务中止：未找到 retention 配置。");
            return;
        }

        // 清理有价值物品的日志
        cleanupByRule(retention.getValuable(), true);

        // 清理无价值物品的日志
        cleanupByRule(retention.getNonValuable(), false);
    }

    private void cleanupByRule(TraceabilityRules.RetentionDetail rule, boolean isValuable) {
        if (rule == null) return;

        String logType = isValuable ? "有价值" : "无价值";
        long totalCount = countLogs(isValuable);

        // 1. 按天数清理
        int days = rule.getDays();
        if (days > 0) {
            long deleteDeadline = System.currentTimeMillis() - TimeUnit.DAYS.toMillis(days);
            QueryWrapper timeQuery = new QueryWrapper()
                    .where(ITEM_TRACE_LOGS_DO.IS_VALUABLE.eq(isValuable))
                    .and(ITEM_TRACE_LOGS_DO.TIMESTAMP.lt(deleteDeadline));
            int deletedByTime = itemTraceLogsMapper.deleteByQuery(timeQuery);
            if (deletedByTime > 0) {
                log.info("溯源日志清理({}): 已通过时间策略(超过{}天)删除 {} 条记录。", logType, days, deletedByTime);
                totalCount -= deletedByTime;
            }
        }

        // 2. 按数量清理
        long maxCount = rule.getMaxCount();
        if (maxCount > 0 && totalCount > maxCount) {
            long excessCount = totalCount - maxCount;
            log.info("溯源日志清理({}): 记录数 {} 超过上限 {}，需要删除 {} 条最旧的记录。", logType, totalCount, maxCount, excessCount);

            QueryWrapper subQuery = new QueryWrapper()
                    .select(ITEM_TRACE_LOGS_DO.ID)
                    .where(ITEM_TRACE_LOGS_DO.IS_VALUABLE.eq(isValuable))
                    .orderBy(ITEM_TRACE_LOGS_DO.TIMESTAMP.asc())
                    .limit(excessCount);

            java.util.List<Long> idsToDelete = itemTraceLogsMapper.selectListByQueryAs(subQuery, Long.class);

            if (!idsToDelete.isEmpty()) {
                QueryWrapper deleteQuery = new QueryWrapper().where(ITEM_TRACE_LOGS_DO.ID.in(idsToDelete));
                int deletedByCount = itemTraceLogsMapper.deleteByQuery(deleteQuery);
                log.info("溯源日志清理({}): 已通过数量策略成功删除 {} 条记录。", logType, deletedByCount);
            }
        }
    }

    private long countLogs(boolean isValuable) {
        QueryWrapper countQuery = new QueryWrapper().where(ITEM_TRACE_LOGS_DO.IS_VALUABLE.eq(isValuable));
        return itemTraceLogsMapper.selectCountByQuery(countQuery);
    }
}
