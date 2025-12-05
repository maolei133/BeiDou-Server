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
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 性能指标收集服务
 * 收集实时性能数据，支持性能趋势分析
 */
@Slf4j
@Service
public class PerformanceMetricsCollector {
    
    /**
     * 性能指标快照
     */
    @Data
    public static class MetricsSnapshot {
        private long timestamp;           // 时间戳
        private String category;          // 分类
        private long logCount;            // 日志数量
        private long successCount;        // 成功数
        private long failureCount;        // 失败数
        private double averageLatency;    // 平均延迟(ms)
        private double qps;               // 每秒查询数
        private double successRate;       // 成功率(%)
        private long memoryUsed;          // 内存使用(MB)
        private int threadCount;          // 线程数
    }

    /**
     * 按小时存储的性能指标
     */
    private final Map<String, List<MetricsSnapshot>> hourlyMetrics = new ConcurrentHashMap<>();
    
    /**
     * 当前小时的指标
     */
    private final Map<String, MetricsSnapshot> currentHourMetrics = new ConcurrentHashMap<>();
    
    /**
     * 收集时间间隔（毫秒）
     */
    private static final long COLLECTION_INTERVAL = 60 * 1000; // 1分钟
    
    /**
     * 上次收集时间
     */
    private volatile long lastCollectionTime = System.currentTimeMillis();

    /**
     * 收集性能指标
     */
    public synchronized void collectMetrics(String category, long logCount, long successCount, 
                                           long failureCount, double averageLatency, double qps) {
        long currentTime = System.currentTimeMillis();
        
        MetricsSnapshot snapshot = new MetricsSnapshot();
        snapshot.setTimestamp(currentTime);
        snapshot.setCategory(category);
        snapshot.setLogCount(logCount);
        snapshot.setSuccessCount(successCount);
        snapshot.setFailureCount(failureCount);
        snapshot.setAverageLatency(averageLatency);
        snapshot.setQps(qps);
        snapshot.setSuccessRate(logCount > 0 ? (double) successCount / logCount * 100 : 0);
        snapshot.setMemoryUsed(getUsedMemory());
        snapshot.setThreadCount(Thread.activeCount());
        
        String key = category + "_" + currentTime / 3600000; // 按小时分组
        hourlyMetrics.computeIfAbsent(key, k -> new ArrayList<>()).add(snapshot);
        currentHourMetrics.put(category, snapshot);
        
        log.debug("已收集{}的性能指标: QPS={}, 延迟={}ms", category, qps, averageLatency);
    }

    /**
     * 获取指定分类的当前指标
     */
    public MetricsSnapshot getCurrentMetrics(String category) {
        return currentHourMetrics.get(category);
    }

    /**
     * 获取指定分类的小时历史指标
     */
    public List<MetricsSnapshot> getHourlyMetrics(String category, int hours) {
        List<MetricsSnapshot> result = new ArrayList<>();
        long currentHour = System.currentTimeMillis() / 3600000;
        
        for (int i = 0; i < hours; i++) {
            String key = category + "_" + (currentHour - i);
            List<MetricsSnapshot> snapshots = hourlyMetrics.get(key);
            if (snapshots != null) {
                result.addAll(snapshots);
            }
        }
        
        result.sort((a, b) -> Long.compare(a.getTimestamp(), b.getTimestamp()));
        return result;
    }

    /**
     * 获取所有分类的当前指标
     */
    public Map<String, MetricsSnapshot> getAllCurrentMetrics() {
        return new HashMap<>(currentHourMetrics);
    }

    /**
     * 获取系统内存使用情况
     */
    private long getUsedMemory() {
        Runtime runtime = Runtime.getRuntime();
        return (runtime.totalMemory() - runtime.freeMemory()) / 1024 / 1024; // 转换为MB
    }

    /**
     * 获取系统内存信息
     */
    public Map<String, Long> getMemoryInfo() {
        Runtime runtime = Runtime.getRuntime();
        Map<String, Long> info = new HashMap<>();
        info.put("totalMemory", runtime.totalMemory() / 1024 / 1024);  // 总内存
        info.put("freeMemory", runtime.freeMemory() / 1024 / 1024);    // 可用内存
        info.put("usedMemory", getUsedMemory());                       // 已用内存
        info.put("maxMemory", runtime.maxMemory() / 1024 / 1024);      // 最大内存
        return info;
    }

    /**
     * 获取系统信息
     */
    public Map<String, Object> getSystemInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("threadCount", Thread.activeCount());
        info.put("processorCount", Runtime.getRuntime().availableProcessors());
        info.put("memory", getMemoryInfo());
        info.put("timestamp", System.currentTimeMillis());
        return info;
    }

    /**
     * 清除旧指标数据
     */
    public synchronized void clearOldMetrics(int hoursToKeep) {
        long currentHour = System.currentTimeMillis() / 3600000;
        List<String> keysToRemove = new ArrayList<>();
        
        for (String key : hourlyMetrics.keySet()) {
            String[] parts = key.split("_");
            if (parts.length == 2) {
                try {
                    long hour = Long.parseLong(parts[1]);
                    if (currentHour - hour > hoursToKeep) {
                        keysToRemove.add(key);
                    }
                } catch (NumberFormatException e) {
                    log.warn("无法解析小时值: {}", key);
                }
            }
        }
        
        for (String key : keysToRemove) {
            hourlyMetrics.remove(key);
        }
        
        if (!keysToRemove.isEmpty()) {
            log.info("已清除{}个小时以前的性能指标数据", hoursToKeep);
        }
    }
}
