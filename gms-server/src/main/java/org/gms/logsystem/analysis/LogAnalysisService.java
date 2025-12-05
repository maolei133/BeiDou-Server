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

package org.gms.logsystem.analysis;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.core.GameLogEntry;
import org.gms.logsystem.query.LogQueryRequest;
import org.gms.logsystem.query.LogQueryService;
import org.gms.logsystem.query.LogStatistics;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 日志分析服务 - 提供日志的深度分析和统计功能
 * 支持趋势分析、关键指标计算、数据对比等功能
 *
 * @author logs-system
 */
@Slf4j
@Service
public class LogAnalysisService {
    private final LogQueryService logQueryService;

    public LogAnalysisService(LogQueryService logQueryService) {
        this.logQueryService = logQueryService;
    }

    /**
     * 分析指定时间范围内的日志趋势
     */
    public LogTrendAnalysis analyzeTrend(LocalDate startDate, LocalDate endDate) {
        try {
            LogTrendAnalysis trend = new LogTrendAnalysis();
            trend.setStartDate(startDate);
            trend.setEndDate(endDate);

            // 按天统计
            Map<LocalDate, Integer> dailyCount = new TreeMap<>();
            for (LocalDate date = startDate; !date.isAfter(endDate); date = date.plusDays(1)) {
                LogQueryRequest request = LogQueryRequest.builder()
                        .startDate(date)
                        .endDate(date)
                        .pageSize(10000)
                        .build();

                LogStatistics stats = logQueryService.getStatistics(request);
                dailyCount.put(date, stats.getTotalCount());
            }

            trend.setDailyCount(dailyCount);

            // 计算平均值、最高值、最低值
            if (!dailyCount.isEmpty()) {
                List<Integer> values = new ArrayList<>(dailyCount.values());
                Collections.sort(values);

                trend.setAverageLogCount((int) values.stream().mapToInt(Integer::intValue).average().orElse(0));
                trend.setMaxLogCount(values.get(values.size() - 1));
                trend.setMinLogCount(values.get(0));
            }

            return trend;
        } catch (Exception e) {
            log.error("分析日志趋势失败", e);
            return new LogTrendAnalysis();
        }
    }

    /**
     * 计算日志的关键指标
     */
    public LogMetrics calculateMetrics(LocalDate startDate, LocalDate endDate) {
        try {
            LogQueryRequest request = LogQueryRequest.builder()
                    .startDate(startDate)
                    .endDate(endDate)
                    .pageSize(10000)
                    .build();

            LogStatistics stats = logQueryService.getStatistics(request);
            LogMetrics metrics = new LogMetrics();

            metrics.setTotalLogs(stats.getTotalCount());
            metrics.setTimeSpanSeconds(stats.getTimeSpanSeconds());
            metrics.setLogsPerSecond(stats.getLogsPerSecond());
            metrics.setUniqueCategories(stats.getCategoryCount());
            metrics.setUniqueAccounts(stats.getAccountCount());

            return metrics;
        } catch (Exception e) {
            log.error("计算日志指标失败", e);
            return new LogMetrics();
        }
    }

    /**
     * 获取热点分类排行
     */
    public List<CategoryRanking> getHotCategories(LocalDate startDate, LocalDate endDate, int topN) {
        try {
            LogQueryRequest request = LogQueryRequest.builder()
                    .startDate(startDate)
                    .endDate(endDate)
                    .pageSize(10000)
                    .build();

            LogStatistics stats = logQueryService.getStatistics(request);

            if (stats.getCategoryStats() == null || stats.getCategoryStats().isEmpty()) {
                return new ArrayList<>();
            }

            return stats.getCategoryStats().entrySet().stream()
                    .map(entry -> new CategoryRanking(entry.getKey(), entry.getValue().intValue()))
                    .sorted(Comparator.comparingInt(CategoryRanking::getCount).reversed())
                    .limit(topN)
                    .collect(Collectors.toList());
        } catch (Exception e) {
            log.error("获取热点分类失败", e);
            return new ArrayList<>();
        }
    }

    /**
     * 获取活跃账号排行
     */
    public List<AccountRanking> getActiveAccounts(LocalDate startDate, LocalDate endDate, int topN) {
        try {
            LogQueryRequest request = LogQueryRequest.builder()
                    .startDate(startDate)
                    .endDate(endDate)
                    .pageSize(10000)
                    .build();

            LogStatistics stats = logQueryService.getStatistics(request);

            if (stats.getAccountStats() == null || stats.getAccountStats().isEmpty()) {
                return new ArrayList<>();
            }

            return stats.getAccountStats().entrySet().stream()
                    .map(entry -> new AccountRanking(entry.getKey(), entry.getValue().intValue()))
                    .sorted(Comparator.comparingInt(AccountRanking::getLogCount).reversed())
                    .limit(topN)
                    .collect(Collectors.toList());
        } catch (Exception e) {
            log.error("获取活跃账号失败", e);
            return new ArrayList<>();
        }
    }

    /**
     * 日志趋势分析结果
     */
    public static class LogTrendAnalysis {
        private LocalDate startDate;
        private LocalDate endDate;
        private Map<LocalDate, Integer> dailyCount;
        private int averageLogCount;
        private int maxLogCount;
        private int minLogCount;

        // 省略getters/setters
        public LocalDate getStartDate() { return startDate; }
        public void setStartDate(LocalDate startDate) { this.startDate = startDate; }
        public LocalDate getEndDate() { return endDate; }
        public void setEndDate(LocalDate endDate) { this.endDate = endDate; }
        public Map<LocalDate, Integer> getDailyCount() { return dailyCount; }
        public void setDailyCount(Map<LocalDate, Integer> dailyCount) { this.dailyCount = dailyCount; }
        public int getAverageLogCount() { return averageLogCount; }
        public void setAverageLogCount(int averageLogCount) { this.averageLogCount = averageLogCount; }
        public int getMaxLogCount() { return maxLogCount; }
        public void setMaxLogCount(int maxLogCount) { this.maxLogCount = maxLogCount; }
        public int getMinLogCount() { return minLogCount; }
        public void setMinLogCount(int minLogCount) { this.minLogCount = minLogCount; }
    }

    /**
     * 日志指标
     */
    public static class LogMetrics {
        private int totalLogs;
        private long timeSpanSeconds;
        private double logsPerSecond;
        private int uniqueCategories;
        private int uniqueAccounts;

        // 省略getters/setters
        public int getTotalLogs() { return totalLogs; }
        public void setTotalLogs(int totalLogs) { this.totalLogs = totalLogs; }
        public long getTimeSpanSeconds() { return timeSpanSeconds; }
        public void setTimeSpanSeconds(long timeSpanSeconds) { this.timeSpanSeconds = timeSpanSeconds; }
        public double getLogsPerSecond() { return logsPerSecond; }
        public void setLogsPerSecond(double logsPerSecond) { this.logsPerSecond = logsPerSecond; }
        public int getUniqueCategories() { return uniqueCategories; }
        public void setUniqueCategories(int uniqueCategories) { this.uniqueCategories = uniqueCategories; }
        public int getUniqueAccounts() { return uniqueAccounts; }
        public void setUniqueAccounts(int uniqueAccounts) { this.uniqueAccounts = uniqueAccounts; }
    }

    /**
     * 分类排行
     */
    public static class CategoryRanking {
        private String category;
        private int count;

        public CategoryRanking(String category, int count) {
            this.category = category;
            this.count = count;
        }

        public String getCategory() { return category; }
        public void setCategory(String category) { this.category = category; }
        public int getCount() { return count; }
        public void setCount(int count) { this.count = count; }
    }

    /**
     * 账号排行
     */
    public static class AccountRanking {
        private String accountName;
        private int logCount;

        public AccountRanking(String accountName, int logCount) {
            this.accountName = accountName;
            this.logCount = logCount;
        }

        public String getAccountName() { return accountName; }
        public void setAccountName(String accountName) { this.accountName = accountName; }
        public int getLogCount() { return logCount; }
        public void setLogCount(int logCount) { this.logCount = logCount; }
    }
}
