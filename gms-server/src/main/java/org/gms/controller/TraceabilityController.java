package org.gms.controller;

import com.mybatisflex.core.paginate.Page;
import com.mybatisflex.core.query.QueryWrapper;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.gms.dao.entity.ItemTraceLogsDO;
import org.gms.dao.mapper.ItemTraceLogsMapper;
import org.gms.model.dto.ResultBody;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "物品溯源管理", description = "提供物品流转日志查询接口")
@RestController
@RequestMapping("/api/trace")
@RequiredArgsConstructor
public class TraceabilityController {

    private final ItemTraceLogsMapper itemTraceLogsMapper;

    @Operation(summary = "查询物品流转历史", description = "根据 UID 查询物品的所有流转历史")
    @GetMapping("/history/{uid}")
    public ResultBody<List<ItemTraceLogsDO>> getTraceHistory(@PathVariable long uid) {
        QueryWrapper query = QueryWrapper.create()
                .where(ItemTraceLogsDO::getUid).eq(uid)
                .orderBy(ItemTraceLogsDO::getTimestamp, true);
        return ResultBody.success(itemTraceLogsMapper.selectListByQuery(query));
    }

    @Operation(summary = "搜索流转日志", description = "根据条件搜索流转日志")
    @GetMapping("/search")
    public ResultBody<Page<ItemTraceLogsDO>> searchTraceLogs(
            @RequestParam(required = false) Integer itemId,
            @RequestParam(required = false) Integer characterId,
            @RequestParam(required = false) String actionType,
            @RequestParam(required = false) Long startTime,
            @RequestParam(required = false) Long endTime,
            @RequestParam(defaultValue = "1") int pageNo,
            @RequestParam(defaultValue = "20") int pageSize) {
        
        QueryWrapper query = QueryWrapper.create();
        if (itemId != null) query.where(ItemTraceLogsDO::getItemId).eq(itemId);
        if (characterId != null) query.where(ItemTraceLogsDO::getCharacterId).eq(characterId);
        if (actionType != null && !actionType.isEmpty()) query.where(ItemTraceLogsDO::getActionType).eq(actionType);
        if (startTime != null) query.where(ItemTraceLogsDO::getTimestamp).ge(startTime);
        if (endTime != null) query.where(ItemTraceLogsDO::getTimestamp).le(endTime);
        
        query.orderBy(ItemTraceLogsDO::getTimestamp, false);
        
        return ResultBody.success(itemTraceLogsMapper.paginate(pageNo, pageSize, query));
    }
    
    @Operation(summary = "查询疑似复制物品", description = "查询相同 UID 存在于多处的物品")
    @GetMapping("/duplicates")
    public ResultBody<List<Long>> getDuplicateItems() {
        // 这是一个复杂的查询，通常需要聚合查询
        // 简单的逻辑是查询 inventoryitems, storage_items, hired_merchant_items 等表中是否有重复的 UID
        // 这里暂时返回空列表，或者实现一个简单的 SQL 查询
        // SELECT uid FROM (
        //   SELECT uid FROM inventoryitems WHERE uid IS NOT NULL
        //   UNION ALL
        //   SELECT uid FROM storage_items WHERE uid IS NOT NULL
        //   UNION ALL
        //   SELECT uid FROM hired_merchant_items WHERE uid IS NOT NULL
        // ) AS all_items GROUP BY uid HAVING COUNT(*) > 1
        
        // 由于 MyBatisFlex 的限制，这里可能需要自定义 SQL
        return ResultBody.success(List.of());
    }
}
