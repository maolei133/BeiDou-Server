/* This file is part of the BeiDou Maple Story Server
Copyright (C) 2025 BeiDou Server https://github.com/BeiDouMS/BeiDou-Server
Magical-H https://github.com/Magical-H

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation version 3 as published by
the Free Software Foundation. You may not use, modify or distribute
this program under any otheer version of the GNU Affero General Public
License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; witout even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.


You should have received a copy of the GNU Affero General Public License
along with this program. If not, see http://www.gnu.org/licenses/.
*/

package org.gms.logsystem.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.query.LogQueryRequest;
import org.gms.logsystem.query.LogQueryResult;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * 日志查询缓存服务
 * 使用 Caffeine 缓存库实现高性能的查询结果缓存
 * 缓存策略：
 * - 过期时间：1小时
 * - 最大容量：10000个查询
 * - LRU淘汰：最近最少使用
 */
@Slf4j
@Service
public class QueryCacheService {
    
    /**
     * 使用 Caffeine 缓存查询结果
     * Key: 查询参数的MD5哈希值
     * Value: LogQueryResult查询结果
     */
    private final Cache<String, LogQueryResult> queryCache = 
        Caffeine.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)  // 1小时后过期
            .maximumSize(10000)                   // 最多缓存10000个查询
            .recordStats()                        // 记录缓存统计信息
            .build();
    
    /**
     * 缓存配置信息
     */
    private volatile CacheConfig cacheConfig = new CacheConfig();
    
    /**
     * 生成缓存键
     * 使用MD5哈希查询参数生成唯一的缓存键
     */
    private String generateCacheKey(LogQueryRequest request) {
        try {
            String queryString = request.toJsonString();
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(queryString.getBytes());
            
            StringBuilder sb = new StringBuilder();
            for (byte b : messageDigest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            log.warn("Failed to generate cache key, using toString fallback", e);
            return request.hashCode() + "";
        }
    }
    
    /**
     * 从缓存获取查询结果
     * 如果缓存中存在该查询结果，则直接返回
     */
    public LogQueryResult getFromCache(LogQueryRequest request) {
        if (!cacheConfig.enabled) {
            return null;
        }
        
        try {
            String cacheKey = generateCacheKey(request);
            LogQueryResult result = queryCache.getIfPresent(cacheKey);
            
            if (result != null) {
                cacheConfig.hitCount++;
                log.debug("Cache hit for query: {}", cacheKey);
            } else {
                cacheConfig.missCount++;
            }
            
            return result;
        } catch (Exception e) {
            log.error("Error retrieving from cache", e);
            return null;
        }
    }
    
    /**
     * 将查询结果存入缓存
     * 使用查询参数的哈希值作为键
     */
    public void putInCache(LogQueryRequest request, LogQueryResult result) {
        if (!cacheConfig.enabled || request == null || result == null) {
            return;
        }
        
        try {
            String cacheKey = generateCacheKey(request);
            queryCache.put(cacheKey, result);
            cacheConfig.putCount++;
            log.debug("Cached query result: {}", cacheKey);
        } catch (Exception e) {
            log.error("Error putting into cache", e);
        }
    }
    
    /**
     * 清空所有缓存
     */
    public void clearCache() {
        try {
            queryCache.invalidateAll();
            cacheConfig.clearCount++;
            log.info("Query cache cleared");
        } catch (Exception e) {
            log.error("Error clearing cache", e);
        }
    }
    
    /**
     * 获取缓存统计信息
     */
    public Map<String, Object> getCacheStats() {
        var stats = queryCache.stats();
        
        Map<String, Object> result = new HashMap<>();
        result.put("requestCount", stats.requestCount());
        result.put("hitCount", stats.hitCount());
        result.put("missCount", stats.missCount());
        result.put("loadSuccessCount", stats.loadSuccessCount());
        result.put("loadFailureCount", stats.loadFailureCount());
        result.put("totalLoadTime", stats.totalLoadTime());
        result.put("evictionCount", stats.evictionCount());
        result.put("hitRate", String.format("%.2f%%", stats.hitRate() * 100));
        result.put("avgLoadPenalty", stats.averageLoadPenalty());
        result.put("estimatedSize", queryCache.estimatedSize());
        result.put("maxSize", cacheConfig.maxSize);
        result.put("enabled", cacheConfig.enabled);
        
        return result;
    }
    
    /**
     * 启用缓存
     */
    public void enableCache() {
        cacheConfig.enabled = true;
        log.info("Query cache enabled");
    }
    
    /**
     * 禁用缓存
     */
    public void disableCache() {
        cacheConfig.enabled = false;
        log.info("Query cache disabled");
    }
    
    /**
     * 检查缓存是否启用
     */
    public boolean isCacheEnabled() {
        return cacheConfig.enabled;
    }
    
    /**
     * 获取缓存命中率
     */
    public double getCacheHitRate() {
        var stats = queryCache.stats();
        return stats.hitRate() * 100;
    }
    
    /**
     * 获取缓存当前大小
     */
    public long getCacheSize() {
        return queryCache.estimatedSize();
    }
    
    /**
     * 获取缓存健康状态
     */
    public Map<String, Object> getCacheHealth() {
        var stats = queryCache.stats();
        
        Map<String, Object> result = new HashMap<>();
        result.put("healthy", stats.hitRate() > 0.5);  // 命中率>50%为健康
        result.put("hitRate", String.format("%.2f%%", stats.hitRate() * 100));
        result.put("currentSize", queryCache.estimatedSize());
        result.put("maxSize", cacheConfig.maxSize);
        result.put("utilizationRate", String.format("%.2f%%", 
            (double) queryCache.estimatedSize() / cacheConfig.maxSize * 100));
        result.put("enabled", cacheConfig.enabled);
        result.put("recommendation", generateRecommendation(stats));
        
        return result;
    }
    
    /**
     * 生成优化建议
     */
    private String generateRecommendation(Object stats) {
        try {
            // 使用反射获取hitRate()方法的返回值
            double hitRate = ((Number) stats.getClass()
                .getMethod("hitRate")
                .invoke(stats)).doubleValue();
            
            if (hitRate < 0.3) {
                return "缓存命中率偏低(<30%)，建议增加缓存大小或调整过期时间";
            } else if (hitRate < 0.6) {
                return "缓存命中率一般(30-60%)，建议关注热点查询";
            } else if (hitRate < 0.8) {
                return "缓存命中率良好(60-80%)，系统运行正常";
            } else {
                return "缓存命中率优秀(>80%)，缓存策略有效";
            }
        } catch (Exception e) {
            return "无法计算命中率";
        }
    }
    
    /**
     * 缓存配置信息
     */
    public static class CacheConfig {
        public boolean enabled = true;
        public long maxSize = 10000L;
        public long ttlMinutes = 60L;
        public long hitCount = 0;
        public long missCount = 0;
        public long putCount = 0;
        public long clearCount = 0;
        
        /**
         * 获取缓存命中率
         */
        public double getHitRate() {
            long total = hitCount + missCount;
            if (total == 0) return 0.0;
            return (double) hitCount / total * 100;
        }
    }
}
