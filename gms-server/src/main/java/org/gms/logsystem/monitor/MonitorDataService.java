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
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
@Service
public class MonitorDataService {
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    
    private final Map<String, CategoryPerformance> categoryPerformance = new ConcurrentHashMap<>();
    private final Map<String, DailyMetrics> dailyMetrics = new ConcurrentHashMap<>();
    private long lastClearTime = System.currentTimeMillis();
    private static final long CLEAR_INTERVAL = 24 * 60 * 60 * 1000; // 24小时

    public void recordPerformance(String category, long executionTime, boolean success) {
        CategoryPerformance perf = categoryPerformance.computeIfAbsent(category, k -> new CategoryPerformance(category));
        perf.recordOperation(executionTime, success);
        
        LocalDate today = LocalDate.now();
        String dateKey = today.toString();
        DailyMetrics metrics = dailyMetrics.computeIfAbsent(dateKey, k -> new DailyMetrics(dateKey));
        metrics.recordOperation(executionTime, success);
    }

    public CategoryPerformance getCategoryPerformance(String category) {
        return categoryPerformance.get(category);
    }

    public List<CategoryPerformance> getAllCategoryPerformance() {
        return new ArrayList<>(categoryPerformance.values());
    }

    public List<CategoryPerformance> getTopCategories(String sortBy, int limit) {
        List<CategoryPerformance> list = new ArrayList<>(categoryPerformance.values());
        
        if ("qps".equalsIgnoreCase(sortBy)) {
            list.sort((a, b) -> Double.compare(b.getQps(), a.getQps()));
        } else if ("latency".equalsIgnoreCase(sortBy)) {
            list.sort((a, b) -> Double.compare(b.getAverageLatency(), a.getAverageLatency()));
        } else if ("errorRate".equalsIgnoreCase(sortBy)) {
            list.sort((a, b) -> Double.compare(b.getErrorRate(), a.getErrorRate()));
        } else {
            list.sort((a, b) -> Long.compare(b.getTotalCount(), a.getTotalCount()));
        }
        
        return list.stream().limit(limit).collect(Collectors.toList());
    }

    public DailyMetrics getDailyMetrics(String date) {
        return dailyMetrics.get(date);
    }

    public List<DailyMetrics> getDailyMetricsRange(String startDate, String endDate) {
        return dailyMetrics.entrySet().stream()
                .filter(e -> e.getKey().compareTo(startDate) >= 0 && e.getKey().compareTo(endDate) <= 0)
                .map(Map.Entry::getValue)
                .sorted(Comparator.comparing(DailyMetrics::getDate))
                .collect(Collectors.toList());
    }

    public void clearOldData() {
        long now = System.currentTimeMillis();
        if (now - lastClearTime > CLEAR_INTERVAL) {
            LocalDate sevenDaysAgo = LocalDate.now().minusDays(7);
            String cutoffDate = sevenDaysAgo.toString();
            
            List<String> keysToRemove = dailyMetrics.keySet().stream()
                    .filter(key -> key.compareTo(cutoffDate) < 0)
                    .collect(Collectors.toList());
            
            for (String key : keysToRemove) {
                dailyMetrics.remove(key);
            }
            
            lastClearTime = now;
            log.info("已清除7天前的监控数据，移除 {} 条记录", keysToRemove.size());
        }
    }

    public Map<String, Object> getSystemMetrics() {
        Map<String, Object> metrics = new LinkedHashMap<>();
        
        long totalCount = categoryPerformance.values().stream()
                .mapToLong(CategoryPerformance::getTotalCount)
                .sum();
        long successCount = categoryPerformance.values().stream()
                .mapToLong(CategoryPerformance::getSuccessCount)
                .sum();
        long totalTime = categoryPerformance.values().stream()
                .mapToLong(CategoryPerformance::getTotalTime)
                .sum();
        
        metrics.put("totalCount", totalCount);
        metrics.put("successCount", successCount);
        metrics.put("failureCount", totalCount - successCount);
        metrics.put("successRate", totalCount > 0 ? (successCount * 100.0 / totalCount) : 0);
        metrics.put("averageLatency", totalCount > 0 ? (totalTime / (double) totalCount) : 0);
        metrics.put("qps", calculateSystemQps());
        metrics.put("categoryCount", categoryPerformance.size());
        metrics.put("timestamp", System.currentTimeMillis());
        
        return metrics;
    }

    private double calculateSystemQps() {
        LocalDate today = LocalDate.now();
        DailyMetrics metrics = dailyMetrics.get(today.toString());
        if (metrics == null) return 0;
        
        long secondsSinceStartOfDay = (System.currentTimeMillis() - metrics.getStartTime()) / 1000;
        if (secondsSinceStartOfDay == 0) return 0;
        
        return metrics.getTotalCount() / (double) secondsSinceStartOfDay;
    }

    @Data
    public static class CategoryPerformance {
        private String category;
        private long totalCount = 0;
        private long successCount = 0;
        private long failureCount = 0;
        private long totalTime = 0;
        private long minLatency = Long.MAX_VALUE;
        private long maxLatency = 0;
        private long lastUpdateTime = System.currentTimeMillis();

        public CategoryPerformance(String category) {
            this.category = category;
        }

        public void recordOperation(long executionTime, boolean success) {
            totalCount++;
            totalTime += executionTime;
            minLatency = Math.min(minLatency, executionTime);
            maxLatency = Math.max(maxLatency, executionTime);
            
            if (success) {
                successCount++;
            } else {
                failureCount++;
            }
            
            lastUpdateTime = System.currentTimeMillis();
        }

        public double getAverageLatency() {
            return totalCount > 0 ? totalTime / (double) totalCount : 0;
        }

        public double getErrorRate() {
            return totalCount > 0 ? failureCount * 100.0 / totalCount : 0;
        }

        public double getQps() {
            long elapsedSeconds = (System.currentTimeMillis() - lastUpdateTime) / 1000;
            return elapsedSeconds > 0 ? totalCount / (double) elapsedSeconds : 0;
        }

        public double getSuccessRate() {
            return totalCount > 0 ? successCount * 100.0 / totalCount : 0;
        }
    }

    @Data
    public static class DailyMetrics {
        private String date;
        private long startTime = System.currentTimeMillis();
        private long totalCount = 0;
        private long successCount = 0;
        private long failureCount = 0;
        private long totalTime = 0;

        public DailyMetrics(String date) {
            this.date = date;
        }

        public void recordOperation(long executionTime, boolean success) {
            totalCount++;
            totalTime += executionTime;
            
            if (success) {
                successCount++;
            } else {
                failureCount++;
            }
        }

        public double getAverageLatency() {
            return totalCount > 0 ? totalTime / (double) totalCount : 0;
        }

        public double getErrorRate() {
            return totalCount > 0 ? failureCount * 100.0 / totalCount : 0;
        }

        public double getSuccessRate() {
            return totalCount > 0 ? successCount * 100.0 / totalCount : 0;
        }

        public double getQps() {
            long elapsedSeconds = (System.currentTimeMillis() - startTime) / 1000;
            return elapsedSeconds > 0 ? totalCount / (double) elapsedSeconds : 0;
        }
    }

    /**
     * 获取队列监控数据
     */
    public Map<String, Object> getQueueMonitorData() {
        Map<String, Object> queueData = new LinkedHashMap<>();
        
        // 统计各个分类的队列情况
        List<Map<String, Object>> categoryQueues = new ArrayList<>();
        for (CategoryPerformance perf : categoryPerformance.values()) {
            Map<String, Object> catQueue = new LinkedHashMap<>();
            catQueue.put("category", perf.getCategory());
            catQueue.put("totalCount", perf.getTotalCount());
            catQueue.put("qps", perf.getQps());
            catQueue.put("averageLatency", perf.getAverageLatency());
            catQueue.put("successRate", perf.getSuccessRate());
            categoryQueues.add(catQueue);
        }
        
        queueData.put("categories", categoryQueues);
        queueData.put("totalCategories", categoryPerformance.size());
        queueData.put("timestamp", System.currentTimeMillis());
        
        return queueData;
    }
}
