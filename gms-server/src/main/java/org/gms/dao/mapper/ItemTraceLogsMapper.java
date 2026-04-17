package org.gms.dao.mapper;

import com.mybatisflex.core.BaseMapper;
import com.mybatisflex.core.query.QueryWrapper;
import org.apache.ibatis.annotations.Select;
import org.gms.dao.entity.ItemTraceLogsDO;

import java.util.List;
import java.util.Map;

import static org.gms.dao.entity.table.ItemTraceLogsDOTableDef.ITEM_TRACE_LOGS_DO;

/**
 * 物品溯源日志表 Mapper
 */
public interface ItemTraceLogsMapper extends BaseMapper<ItemTraceLogsDO> {

    /**
     * 统计今天新增的记录数
     *
     * @return 今天新增的记录数
     */
    default long countToday() {
        long todayStart = java.time.LocalDate.now().atStartOfDay().toInstant(java.time.ZoneOffset.UTC).toEpochMilli();
        return selectCountByQuery(QueryWrapper.create().where(ITEM_TRACE_LOGS_DO.TIMESTAMP.ge(todayStart)));
    }

    /**
     * 按 ActionType 分组统计数量
     *
     * @return 每种 ActionType 的数量列表
     */
    @Select("SELECT action_type, COUNT(*) as count FROM item_trace_logs GROUP BY action_type")
    List<Map<String, Object>> countByActionType();

    /**
     * 统计过去24小时每小时的记录数
     *
     * @return 每小时记录数列表
     */
    @Select("SELECT HOUR(FROM_UNIXTIME(timestamp / 1000)) as hour, COUNT(*) as count " +
            "FROM item_trace_logs " +
            "WHERE timestamp >= #{twentyFourHoursAgo} " +
            "GROUP BY hour ORDER BY hour ASC")
    List<Map<String, Object>> countHourlyLast24h(long twentyFourHoursAgo);

    /**
     * 查找记录最多的前10个物品
     *
     * @return Top 10 物品列表
     */
    @Select("SELECT item_id, COUNT(*) as count FROM item_trace_logs GROUP BY item_id ORDER BY count DESC LIMIT 10")
    List<Map<String, Object>> findTopItems();
}
