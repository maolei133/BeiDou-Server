package org.gms.logsystem.rest;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.cache.QueryCacheService;
import org.gms.model.dto.ResultBody;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * 缓存管理REST API控制器
 * 提供缓存监控和管理功能
 */
@Slf4j
@RestController("logSystemCacheController")
@RequestMapping("/logsystem/cache")
public class CacheController {

    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final QueryCacheService cacheService;

    public CacheController(QueryCacheService cacheService) {
        this.cacheService = cacheService;
    }

    /**
     * 获取缓存统计信息
     */
    @GetMapping("/stats")
    public ResultBody<Map<String, Object>> getCacheStats() {
        Map<String, Object> stats = cacheService.getCacheStats();
        stats.put("timestamp", LocalDateTime.now().format(formatter));
        return ResultBody.success(stats);
    }

    /**
     * 获取缓存健康状态
     */
    @GetMapping("/health")
    public ResultBody<Map<String, Object>> getCacheHealth() {
        Map<String, Object> health = cacheService.getCacheHealth();
        health.put("timestamp", LocalDateTime.now().format(formatter));
        return ResultBody.success(health);
    }

    /**
     * 清空缓存
     */
    @PostMapping("/clear")
    public ResultBody<Map<String, Object>> clearCache() {
        cacheService.clearCache();
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("message", "缓存已清空");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 启用缓存
     */
    @PostMapping("/enable")
    public ResultBody<Map<String, Object>> enableCache() {
        cacheService.enableCache();
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("enabled", true);
        result.put("message", "缓存已启用");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 禁用缓存
     */
    @PostMapping("/disable")
    public ResultBody<Map<String, Object>> disableCache() {
        cacheService.disableCache();
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("enabled", false);
        result.put("message", "缓存已禁用");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 获取缓存配置
     */
    @GetMapping("/config")
    public ResultBody<Map<String, Object>> getCacheConfig() {
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("enabled", cacheService.isCacheEnabled());
        config.put("currentSize", cacheService.getCacheSize());
        config.put("hitRate", String.format("%.2f%%", cacheService.getCacheHitRate()));
        config.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(config);
    }
}
