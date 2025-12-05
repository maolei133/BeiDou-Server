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

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * 实时性能分析服务
 * 提供性能数据的实时分析和统计功能
 */
@Slf4j
@Service
public class PerformanceAnalyzer {
    
    /**
     * 性能排行数据
     */
    @Data
    public static class PerformanceRank {
        private String category;
        private int rank;
        private double value;
        private String metricType;  // QPS, LATENCY, SUCCESS_RATE等
    }

    /**
     * 性能趋势
     */
    @Data
    public static class PerformanceTrend {
        private String category;
        private String metricType;
        private List<Double> values;
        private List<Long> timestamps;
        private double trend;  // 趋势值：正数表示上升，负数表示下降
    }

    private final LogMonitor logMonitor;
    private final PerformanceMetricsCollector metricsCollector;

    public PerformanceAnalyzer(LogMonitor logMonitor, PerformanceMetricsCollector metricsCollector) {
        this.logMonitor = logMonitor;
        this.metricsCollector = metricsCollector;
    }

    /**
     * 获取QPS排行Top N
     */
    public List<PerformanceRank> getQPSRanking(int limit) {
        List<PerformanceRank> ranks = logMonitor.getAllCategoryStats().stream()
                .map(stats -> {
                    PerformanceRank rank = new PerformanceRank();
                    rank.setCategory(stats.getCategoryId());
                    rank.setValue(stats.getQPS(60000));
                    rank.setMetricType("QPS");
                    return rank;
                })
                .sorted((a, b) -> Double.compare(b.getValue(), a.getValue()))
                .limit(limit)
                .collect(Collectors.toList());
        
        for (int i = 0; i < ranks.size(); i++) {
            ranks.get(i).setRank(i + 1);
        }
        return ranks;
    }

    /**
     * 获取延迟排行Top N（延迟最低的）
     */
    public List<PerformanceRank> getLatencyRanking(int limit) {
        List<PerformanceRank> ranks = logMonitor.getAllCategoryStats().stream()
                .map(stats -> {
                    PerformanceRank rank = new PerformanceRank();
                    rank.setCategory(stats.getCategoryId());
                    rank.setValue(stats.getAverageLatency());
                    rank.setMetricType("LATENCY");
                    return rank;
                })
                .sorted(Comparator.comparingDouble(PerformanceRank::getValue))
                .limit(limit)
                .collect(Collectors.toList());
        
        for (int i = 0; i < ranks.size(); i++) {
            ranks.get(i).setRank(i + 1);
        }
        return ranks;
    }

    /**
     * 获取成功率排行Top N
     */
    public List<PerformanceRank> getSuccessRateRanking(int limit) {
        List<PerformanceRank> ranks = logMonitor.getAllCategoryStats().stream()
                .map(stats -> {
                    PerformanceRank rank = new PerformanceRank();
                    rank.setCategory(stats.getCategoryId());
                    long total = stats.getTotalCount().get();
                    rank.setValue(total > 0 ? (double) stats.getSuccessCount().get() / total * 100 : 0);
                    rank.setMetricType("SUCCESS_RATE");
                    return rank;
                })
                .sorted((a, b) -> Double.compare(b.getValue(), a.getValue()))
                .limit(limit)
                .collect(Collectors.toList());
        
        for (int i = 0; i < ranks.size(); i++) {
            ranks.get(i).setRank(i + 1);
        }
        return ranks;
    }

    /**
     * 获取性能趋势
     */
    public PerformanceTrend getPerformanceTrend(String category, String metricType, int hours) {
        List<PerformanceMetricsCollector.MetricsSnapshot> snapshots = 
            metricsCollector.getHourlyMetrics(category, hours);
        
        PerformanceTrend trend = new PerformanceTrend();
        trend.setCategory(category);
        trend.setMetricType(metricType);
        trend.setValues(new ArrayList<>());
        trend.setTimestamps(new ArrayList<>());
        
        for (PerformanceMetricsCollector.MetricsSnapshot snapshot : snapshots) {
            double value = getMetricValue(snapshot, metricType);
            trend.getValues().add(value);
            trend.getTimestamps().add(snapshot.getTimestamp());
        }
        
        // 计算趋势（简单线性回归）
        if (trend.getValues().size() >= 2) {
            trend.setTrend(calculateTrend(trend.getValues()));
        }
        
        return trend;
    }

    /**
     * 获取指标值
     */
    private double getMetricValue(PerformanceMetricsCollector.MetricsSnapshot snapshot, String metricType) {
        return switch (metricType.toUpperCase()) {
            case "QPS" -> snapshot.getQps();
            case "LATENCY" -> snapshot.getAverageLatency();
            case "SUCCESS_RATE" -> snapshot.getSuccessRate();
            case "MEMORY" -> snapshot.getMemoryUsed();
            default -> 0.0;
        };
    }

    /**
     * 计算趋势（正数表示上升，负数表示下降）
     */
    private double calculateTrend(List<Double> values) {
        if (values.size() < 2) return 0.0;
        
        int n = values.size();
        double sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;
        
        for (int i = 0; i < n; i++) {
            sumX += i;
            sumY += values.get(i);
            sumXY += i * values.get(i);
            sumX2 += i * i;
        }
        
        // 线性回归斜率
        double slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
        return slope;
    }

    /**
     * 获取性能概览
     */
    public Map<String, Object> getPerformanceOverview() {
        Map<String, Object> overview = new HashMap<>();
        
        LogMonitor.LogStats systemStats = logMonitor.getSystemStats();
        
        overview.put("systemQPS", logMonitor.getSystemQPS());
        overview.put("systemLatency", logMonitor.getSystemAverageLatency());
        overview.put("systemSuccessRate", logMonitor.getSystemSuccessRate());
        overview.put("systemTotalLogs", systemStats.getTotalCount().get());
        overview.put("systemSuccessLogs", systemStats.getSuccessCount().get());
        overview.put("systemFailureLogs", systemStats.getFailureCount().get());
        overview.put("categoriesCount", logMonitor.getAllCategoryStats().size());
        overview.put("systemMemory", metricsCollector.getSystemInfo().get("memory"));
        
        return overview;
    }

    /**
     * 检测异常情况 - 增强版
     * 检测高延迟、高失败率、高内存占用等异常
     */
    public List<String> detectAnomalies() {
        List<String> anomalies = new ArrayList<>();
        
        // 1. 检测分类级别的高失败率
        logMonitor.getAllCategoryStats().forEach(stats -> {
            long total = stats.getTotalCount().get();
            if (total > 10) {  // 至少有10条日志才检测
                long failureCount = stats.getFailureCount().get();
                double failureRate = (double) failureCount / total * 100;
                
                // 失败率超过10%为严重异常
                if (failureRate > 10) {
                    anomalies.add(String.format("[严重] 分类%s的失败率过高: %.2f%% (%d/%d)", 
                        stats.getCategoryId(), failureRate, failureCount, total));
                } 
                // 失败率在5-10%为警告
                else if (failureRate > 5) {
                    anomalies.add(String.format("[警告] 分类%s的失败率异常: %.2f%% (%d/%d)", 
                        stats.getCategoryId(), failureRate, failureCount, total));
                }
            }
        });
        
        // 2. 检测分类级别的高延迟
        logMonitor.getAllCategoryStats().forEach(stats -> {
            double latency = stats.getAverageLatency();
            
            // 延迟超过200ms为严重异常
            if (latency > 200) {
                anomalies.add(String.format("[严重] 分类%s的延迟过高: %.2fms", 
                    stats.getCategoryId(), latency));
            }
            // 延迟在100-200ms为警告
            else if (latency > 100) {
                anomalies.add(String.format("[警告] 分类%s的延迟异常: %.2fms", 
                    stats.getCategoryId(), latency));
            }
        });
        
        // 3. 检测系统级别的高延迟
        double systemLatency = logMonitor.getSystemAverageLatency();
        if (systemLatency > 200) {
            anomalies.add(String.format("[严重] 系统平均延迟过高: %.2fms", systemLatency));
        } else if (systemLatency > 100) {
            anomalies.add(String.format("[警告] 系统平均延迟异常: %.2fms", systemLatency));
        }
        
        // 4. 检测系统级别的高失败率
        LogMonitor.LogStats systemStats = logMonitor.getSystemStats();
        long totalLogs = systemStats.getTotalCount().get();
        if (totalLogs > 100) {
            long systemFailures = systemStats.getFailureCount().get();
            double systemFailureRate = (double) systemFailures / totalLogs * 100;
            
            if (systemFailureRate > 10) {
                anomalies.add(String.format("[严重] 系统整体失败率过高: %.2f%% (%d/%d)", 
                    systemFailureRate, systemFailures, totalLogs));
            } else if (systemFailureRate > 5) {
                anomalies.add(String.format("[警告] 系统整体失败率异常: %.2f%% (%d/%d)", 
                    systemFailureRate, systemFailures, totalLogs));
            }
        }
        
        // 5. 检测内存使用过高
        Map<String, Object> memoryInfo = metricsCollector.getSystemInfo();
        Object memoryObj = memoryInfo.get("memory");
        if (memoryObj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> memory = (Map<String, Object>) memoryObj;
            
            Object usedObj = memory.get("usedMemory");
            Object maxObj = memory.get("maxMemory");
            
            if (usedObj != null && maxObj != null) {
                long usedMemory = ((Number) usedObj).longValue();
                long maxMemory = ((Number) maxObj).longValue();
                double memoryUsagePercent = (double) usedMemory / maxMemory * 100;
                
                // 内存使用超过90%为严重异常
                if (memoryUsagePercent > 90) {
                    anomalies.add(String.format("[严重] 内存使用过高: %.2f%% (%dMB/%dMB)", 
                        memoryUsagePercent, usedMemory / 1024 / 1024, maxMemory / 1024 / 1024));
                }
                // 内存使用在80-90%为警告
                else if (memoryUsagePercent > 80) {
                    anomalies.add(String.format("[警告] 内存使用偏高: %.2f%% (%dMB/%dMB)", 
                        memoryUsagePercent, usedMemory / 1024 / 1024, maxMemory / 1024 / 1024));
                }
            }
        }
        
        // 6. 检测QPS异常（突增或突降）
        double currentQPS = logMonitor.getSystemQPS();
        if (currentQPS > 1000) {
            anomalies.add(String.format("[警告] QPS过高: %.2f req/min", currentQPS));
        }
        
        return anomalies;
    }

    /**
     * 获取异常检测数据
     */
    public Map<String, Object> getAnomalyDetectionData() {
        Map<String, Object> data = new HashMap<>();
        List<String> anomalies = detectAnomalies();
        data.put("anomalies", anomalies);
        data.put("anomalyCount", anomalies.size());
        data.put("timestamp", System.currentTimeMillis());
        return data;
    }
}
