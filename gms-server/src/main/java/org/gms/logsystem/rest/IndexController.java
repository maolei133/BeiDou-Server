package org.gms.logsystem.rest;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.index.LogIndexService;
import org.gms.model.dto.ResultBody;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * 索引管理REST API控制器
 * 提供日志索引管理和查询功能
 */
@Slf4j
@RestController("logSystemIndexController")
@RequestMapping("/logsystem/index")
public class IndexController {

    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final LogIndexService indexService;

    public IndexController(LogIndexService indexService) {
        this.indexService = indexService;
    }

    /**
     * 获取索引统计信息
     */
    @GetMapping("/stats")
    public ResultBody<Map<String, Object>> getIndexStats() {
        LogIndexService.IndexStats stats = indexService.getIndexStats();
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("totalIndexedLogs", stats.totalIndexedLogs);
        result.put("dateIndexHits", stats.dateIndexHits);
        result.put("categoryIndexHits", stats.categoryIndexHits);
        result.put("accountIndexHits", stats.accountIndexHits);
        result.put("ipIndexHits", stats.ipIndexHits);
        result.put("keywordSearchCount", stats.keywordSearchCount);
        result.put("fullScanCount", stats.fullScanCount);
        result.put("indexHitRate", String.format("%.2f%%", stats.getIndexHitRate()));
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 获取索引日期范围
     */
    @GetMapping("/date-range")
    public ResultBody<Map<String, Object>> getDateRange() {
        Map<String, String> dateRange = indexService.getDateRange();
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("startDate", dateRange.get("start"));
        result.put("endDate", dateRange.get("end"));
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 获取所有已索引的分类
     */
    @GetMapping("/categories")
    public ResultBody<Map<String, Object>> getIndexedCategories() {
        Set<String> categories = indexService.getAllCategories();
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("categories", categories);
        result.put("count", categories.size());
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 清空索引
     */
    @PostMapping("/clear")
    public ResultBody<Map<String, Object>> clearIndex() {
        indexService.clearIndex();
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("message", "索引已清空");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 获取账号日志数量
     */
    @GetMapping("/account/{accountId}/count")
    public ResultBody<Map<String, Object>> getAccountLogCount(@PathVariable int accountId) {
        int count = indexService.getAccountLogCount(accountId);
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("accountId", accountId);
        result.put("logCount", count);
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 按关键词搜索日志ID
     */
    @GetMapping("/search")
    public ResultBody<Map<String, Object>> searchByKeyword(@RequestParam String keyword) {
        Set<Integer> logIds = indexService.queryByKeyword(keyword);
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("keyword", keyword);
        result.put("matchCount", logIds.size());
        result.put("logIds", logIds.size() > 100 ? 
                new ArrayList<>(logIds).subList(0, 100) : logIds);
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }
}
