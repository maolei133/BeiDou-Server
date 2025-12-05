package org.gms.logsystem.rest;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.query.LogQueryRequest;
import org.gms.logsystem.query.LogQueryResult;
import org.gms.logsystem.query.LogQueryService;
import org.gms.model.dto.ResultBody;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 高级搜索REST API控制器
 * 提供高级搜索、保存查询和查询历史功能
 */
@Slf4j
@RestController("logSystemAdvancedSearchController")
@RequestMapping("/logsystem/search")
public class AdvancedSearchController {

    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final LogQueryService queryService;
    
    // 保存的查询（内存存储，重启后丢失）
    private final Map<String, Map<String, Object>> savedQueries = new ConcurrentHashMap<>();
    
    // 查询历史
    private final List<Map<String, Object>> queryHistory = Collections.synchronizedList(new ArrayList<>());

    public AdvancedSearchController(LogQueryService queryService) {
        this.queryService = queryService;
    }

    /**
     * 高级搜索
     */
    @PostMapping("/advanced")
    public ResultBody<LogQueryResult> advancedSearch(@RequestBody LogQueryRequest request) {
        // 设置默认值
        if (request.getStartDate() == null) {
            request.setStartDate(LocalDate.now().minusDays(7));
        }
        if (request.getEndDate() == null) {
            request.setEndDate(LocalDate.now());
        }
        if (request.getPageNum() <= 0) {
            request.setPageNum(1);
        }
        if (request.getPageSize() <= 0) {
            request.setPageSize(20);
        }

        LogQueryResult result = queryService.query(request);
        
        // 记录查询历史
        recordQueryHistory(request, result);
        
        return ResultBody.success(result);
    }

    /**
     * 获取搜索建议
     */
    @GetMapping("/suggestions")
    public ResultBody<Map<String, Object>> getSuggestions(@RequestParam String keyword) {
        Map<String, Object> result = new LinkedHashMap<>();
        
        List<String> suggestions = new ArrayList<>();
        // 基于关键词提供搜索建议
        if (keyword != null && !keyword.isEmpty()) {
            suggestions.add(keyword);
            suggestions.add(keyword + " error");
            suggestions.add(keyword + " warning");
        }
        
        result.put("keyword", keyword);
        result.put("suggestions", suggestions);
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 保存查询
     */
    @PostMapping("/saved")
    public ResultBody<Map<String, Object>> saveQuery(@RequestBody Map<String, Object> queryData) {
        String id = UUID.randomUUID().toString().substring(0, 8);
        queryData.put("id", id);
        queryData.put("createdAt", LocalDateTime.now().format(formatter));
        savedQueries.put(id, queryData);
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("id", id);
        result.put("message", "查询已保存");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 获取保存的查询列表
     */
    @GetMapping("/saved")
    public ResultBody<Map<String, Object>> getSavedQueries() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("queries", new ArrayList<>(savedQueries.values()));
        result.put("count", savedQueries.size());
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 获取保存的查询详情
     */
    @GetMapping("/saved/{id}")
    public ResultBody<Map<String, Object>> getSavedQuery(@PathVariable String id) {
        Map<String, Object> query = savedQueries.get(id);
        if (query == null) {
            throw new RuntimeException("查询不存在: " + id);
        }
        return ResultBody.success(query);
    }

    /**
     * 删除保存的查询
     */
    @DeleteMapping("/saved/{id}")
    public ResultBody<Map<String, Object>> deleteSavedQuery(@PathVariable String id) {
        savedQueries.remove(id);
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("id", id);
        result.put("message", "查询已删除");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 获取查询历史
     */
    @GetMapping("/history")
    public ResultBody<Map<String, Object>> getQueryHistory(
            @RequestParam(defaultValue = "20") int limit) {
        Map<String, Object> result = new LinkedHashMap<>();
        
        int size = Math.min(limit, queryHistory.size());
        List<Map<String, Object>> history = size > 0 ? 
                queryHistory.subList(queryHistory.size() - size, queryHistory.size()) : new ArrayList<>();
        
        result.put("history", history);
        result.put("count", history.size());
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 记录查询历史
     */
    private void recordQueryHistory(LogQueryRequest request, LogQueryResult result) {
        Map<String, Object> history = new LinkedHashMap<>();
        history.put("keyword", request.getKeyword());
        history.put("category", request.getMajorCategory());
        history.put("resultCount", result.getTotal());
        history.put("timestamp", LocalDateTime.now().format(formatter));
        
        queryHistory.add(history);
        
        // 限制历史记录数量
        while (queryHistory.size() > 100) {
            queryHistory.remove(0);
        }
    }
}
