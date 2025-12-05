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

package org.gms.logsystem.monitor;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 日志监控类 - 收集和统计日志系统的性能指标
 * 支持QPS、延迟、内存等关键指标的监控
 *
 * @author logs-system
 */
@Slf4j
@Component
public class LogMonitor {
    /**
     * 日志统计信息
     */
    @Data
    public static class LogStats {
        /**
         * 分类ID
         */
        private String categoryId;

        /**
         * 日志总数
         */
        private AtomicLong totalCount = new AtomicLong(0);

        /**
         * 成功数
         */
        private AtomicLong successCount = new AtomicLong(0);

        /**
         * 失败数
         */
        private AtomicLong failureCount = new AtomicLong(0);

        /**
         * 总耗时（毫秒）
         */
        private AtomicLong totalTime = new AtomicLong(0);

        /**
         * 最后更新时间
         */
        private long lastUpdateTime = System.currentTimeMillis();

        /**
         * 获取平均延迟
         */
        public double getAverageLatency() {
            long count = totalCount.get();
            if (count == 0) return 0;
            return (double) totalTime.get() / count;
        }

        /**
         * 获取QPS
         */
        public double getQPS(long timeWindowMs) {
            long elapsedTime = System.currentTimeMillis() - lastUpdateTime;
            if (elapsedTime == 0) return 0;
            return totalCount.get() * 1000.0 / elapsedTime;
        }
    }

    /**
     * 按分类统计日志
     */
    private final Map<String, LogStats> categoryStats = new ConcurrentHashMap<>();

    /**
     * 系统级统计
     */
    private final AtomicLong systemTotalCount = new AtomicLong(0);
    private final AtomicLong systemSuccessCount = new AtomicLong(0);
    private final AtomicLong systemFailureCount = new AtomicLong(0);
    private final AtomicLong systemTotalTime = new AtomicLong(0);

    /**
     * 监控数据采集时间
     */
    private long monitorStartTime = System.currentTimeMillis();

    /**
     * 记录一次日志操作
     *
     * @param categoryId 分类ID
     * @param success 是否成功
     * @param executionTime 执行耗时（毫秒）
     */
    public void recordLogOperation(String categoryId, boolean success, long executionTime) {
        // 更新系统级统计
        systemTotalCount.incrementAndGet();
        systemTotalTime.addAndGet(executionTime);
        if (success) {
            systemSuccessCount.incrementAndGet();
        } else {
            systemFailureCount.incrementAndGet();
        }

        // 更新分类级统计
        LogStats stats = categoryStats.computeIfAbsent(categoryId, k -> {
            LogStats s = new LogStats();
            s.setCategoryId(categoryId);
            return s;
        });

        stats.getTotalCount().incrementAndGet();
        stats.getTotalTime().addAndGet(executionTime);
        if (success) {
            stats.getSuccessCount().incrementAndGet();
        } else {
            stats.getFailureCount().incrementAndGet();
        }
        stats.setLastUpdateTime(System.currentTimeMillis());
    }

    /**
     * 获取系统级统计
     */
    public LogStats getSystemStats() {
        LogStats stats = new LogStats();
        stats.setCategoryId("SYSTEM");
        stats.getTotalCount().set(systemTotalCount.get());
        stats.getSuccessCount().set(systemSuccessCount.get());
        stats.getFailureCount().set(systemFailureCount.get());
        stats.getTotalTime().set(systemTotalTime.get());
        return stats;
    }

    /**
     * 获取指定分类的统计
     */
    public LogStats getCategoryStats(String categoryId) {
        return categoryStats.get(categoryId);
    }

    /**
     * 获取所有分类的统计
     */
    public Collection<LogStats> getAllCategoryStats() {
        return categoryStats.values();
    }

    /**
     * 获取系统QPS
     */
    public double getSystemQPS() {
        long elapsedTime = System.currentTimeMillis() - monitorStartTime;
        if (elapsedTime == 0) return 0;
        return systemTotalCount.get() * 1000.0 / elapsedTime;
    }

    /**
     * 获取系统平均延迟
     */
    public double getSystemAverageLatency() {
        long count = systemTotalCount.get();
        if (count == 0) return 0;
        return (double) systemTotalTime.get() / count;
    }

    /**
     * 获取系统成功率
     */
    public double getSystemSuccessRate() {
        long total = systemTotalCount.get();
        if (total == 0) return 0;
        return (double) systemSuccessCount.get() / total * 100;
    }

    /**
     * 清除所有统计数据
     */
    public void clearStats() {
        categoryStats.clear();
        systemTotalCount.set(0);
        systemSuccessCount.set(0);
        systemFailureCount.set(0);
        systemTotalTime.set(0);
        monitorStartTime = System.currentTimeMillis();
        log.info("日志监控数据已清除");
    }

    /**
     * 清除旧数据（基于最后更新时间，超过1小时未更新的分类数据将被清除）
     */
    public void clearOldData() {
        long currentTime = System.currentTimeMillis();
        long expirationTime = 60 * 60 * 1000; // 1小时
        
        int removedCount = 0;
        List<String> keysToRemove = new ArrayList<>();
        
        // 找出超时的分类
        for (Map.Entry<String, LogStats> entry : categoryStats.entrySet()) {
            long lastUpdateTime = entry.getValue().getLastUpdateTime();
            if (currentTime - lastUpdateTime > expirationTime) {
                keysToRemove.add(entry.getKey());
            }
        }
        
        // 删除超时的分类数据
        for (String key : keysToRemove) {
            if (categoryStats.remove(key) != null) {
                removedCount++;
            }
        }
        
        if (removedCount > 0) {
            log.info("已清除{}条超时的分类监控数据，剩余分类数: {}", removedCount, categoryStats.size());
        } else {
            log.debug("无需清除监控数据");
        }
    }

    /**
     * 清除所有统计数据
     */

    /**
     * 获取监控统计汇总
     */
    public String getSummary() {
        return String.format(
                "系统监控统计 - 总计: %d, 成功: %d, 失败: %d, QPS: %.2f, 平均延迟: %.2fms, 成功率: %.2f%%",
                systemTotalCount.get(),
                systemSuccessCount.get(),
                systemFailureCount.get(),
                getSystemQPS(),
                getSystemAverageLatency(),
                getSystemSuccessRate()
        );
    }

    /**
     * 获取系统健康状况
     */
    public Map<String, Object> getSystemHealth() {
        Map<String, Object> health = new LinkedHashMap<>();
        
        // 收集系统指标
        double successRate = getSystemSuccessRate();
        double averageLatency = getSystemAverageLatency();
        double qps = getSystemQPS();
        long totalLogs = systemTotalCount.get();
        
        // 判断健康状态
        String status = "健康";
        if (successRate < 95 || averageLatency > 100 || totalLogs == 0) {
            status = "异常";
        } else if (successRate < 99 || averageLatency > 50) {
            status = "警告";
        }
        
        health.put("status", status);
        health.put("successRate", successRate);
        health.put("averageLatency", averageLatency);
        health.put("qps", qps);
        health.put("totalLogs", totalLogs);
        health.put("successLogs", systemSuccessCount.get());
        health.put("failureLogs", systemFailureCount.get());
        health.put("categoryCount", categoryStats.size());
        health.put("timestamp", System.currentTimeMillis());
        
        return health;
    }
}
