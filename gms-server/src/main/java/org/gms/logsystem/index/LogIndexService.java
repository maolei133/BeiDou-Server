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

package org.gms.logsystem.index;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.core.GameLogEntry;
import org.gms.logsystem.query.LogQueryRequest;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * 日志索引服务
 * 提供高性能的日志查询索引支持
 * 支持按日期、分类、账号、内容等多维度索引
 */
@Slf4j
@Service
public class LogIndexService {
    
    /**
     * 时间索引: 按日期组织日志ID
     * Key: LocalDate (yyyy-MM-dd)
     * Value: 该日期的日志ID集合
     */
    private final Map<LocalDate, Set<Integer>> dateIndex = new ConcurrentHashMap<>();
    
    /**
     * 分类索引: 按大类:小类组织日志ID
     * Key: majorCategory:minorCategory
     * Value: 该分类的日志ID集合
     */
    private final Map<String, Set<Integer>> categoryIndex = new ConcurrentHashMap<>();
    
    /**
     * 账号索引: 按账号ID组织日志
     * Key: accountId
     * Value: 该账号的日志ID集合
     */
    private final Map<Integer, Set<Integer>> accountIndex = new ConcurrentHashMap<>();
    
    /**
     * 内容索引: 简单的关键词索引
     * Key: keyword (来自消息)
     * Value: 包含该关键词的日志ID集合
     */
    private final Map<String, Set<Integer>> contentIndex = new ConcurrentHashMap<>();
    
    /**
     * IP索引: 按来源IP组织日志
     * Key: IP地址
     * Value: 该IP的日志ID集合
     */
    private final Map<String, Set<Integer>> ipIndex = new ConcurrentHashMap<>();
    
    /**
     * 索引统计信息
     */
    private volatile IndexStats indexStats = new IndexStats();
    
    /**
     * 添加日志到索引
     */
    public synchronized void addLogToIndex(int logId, GameLogEntry entry) {
        try {
            // 1. 添加到日期索引
            if (entry.getTimestamp() > 0) {
                LocalDate logDate = new java.util.Date(entry.getTimestamp()).toInstant()
                    .atZone(java.time.ZoneId.systemDefault()).toLocalDate();
                dateIndex.computeIfAbsent(logDate, k -> ConcurrentHashMap.newKeySet())
                         .add(logId);
            }
            
            // 2. 添加到分类索引
            if (entry.getMajorCategory() != null && entry.getMinorCategory() != null) {
                String categoryKey = entry.getMajorCategory() + ":" + entry.getMinorCategory();
                categoryIndex.computeIfAbsent(categoryKey, k -> ConcurrentHashMap.newKeySet())
                             .add(logId);
            }
            
            // 3. 添加到账号索引
            if (entry.getAccountId() > 0) {
                accountIndex.computeIfAbsent(entry.getAccountId(), k -> ConcurrentHashMap.newKeySet())
                            .add(logId);
            }
            
            // 4. 添加到内容索引
            if (entry.getMessage() != null && !entry.getMessage().isEmpty()) {
                String[] keywords = extractKeywords(entry.getMessage());
                for (String keyword : keywords) {
                    if (keyword.length() > 2) {  // 只索引长度>2的关键词
                        contentIndex.computeIfAbsent(keyword.toLowerCase(), k -> ConcurrentHashMap.newKeySet())
                                    .add(logId);
                    }
                }
            }
            
            // 5. 添加到IP索引
            if (entry.getIpAddress() != null && !entry.getIpAddress().isEmpty()) {
                ipIndex.computeIfAbsent(entry.getIpAddress(), k -> ConcurrentHashMap.newKeySet())
                        .add(logId);
            }
            
            // 6. 更新统计信息
            indexStats.totalIndexedLogs++;
            
        } catch (Exception e) {
            log.error("添加日志到索引失败: {}", logId, e);
        }
    }
    
    /**
     * 批量添加日志到索引
     */
    public synchronized void addLogsToIndex(Map<Integer, GameLogEntry> logs) {
        for (Map.Entry<Integer, GameLogEntry> entry : logs.entrySet()) {
            addLogToIndex(entry.getKey(), entry.getValue());
        }
    }
    
    /**
     * 查询符合条件的日志ID列表
     * 使用索引优化查询性能
     */
    public Set<Integer> queryLogIds(LogQueryRequest request) {
        Set<Integer> result = null;
        
        // 1. 优先使用约束性最强的索引
        if (request.getAccountId() > 0) {
            // 使用账号索引 (约束性最强)
            result = new HashSet<>(accountIndex.getOrDefault(request.getAccountId(), new HashSet<>()));
            indexStats.accountIndexHits++;
        } else if (request.getMajorCategory() != null && !request.getMajorCategory().isEmpty()) {
            // 使用分类索引
            String categoryKey = request.getMajorCategory() + ":" + 
                (request.getMinorCategory() != null ? request.getMinorCategory() : "");
            
            if (request.getMinorCategory() != null && !request.getMinorCategory().isEmpty()) {
                result = new HashSet<>(categoryIndex.getOrDefault(categoryKey, new HashSet<>()));
            } else {
                // 如果只指定大类，则合并所有包含该大类的结果
                result = categoryIndex.entrySet().stream()
                    .filter(e -> e.getKey().startsWith(request.getMajorCategory() + ":"))
                    .flatMap(e -> e.getValue().stream())
                    .collect(Collectors.toSet());
            }
            indexStats.categoryIndexHits++;
        } else if (request.getStartDate() != null) {
            // 使用日期索引
            result = new HashSet<>(dateIndex.getOrDefault(
                request.getStartDate(),
                new HashSet<>()
            ));
            indexStats.dateIndexHits++;
        } else if (request.getIpAddress() != null && !request.getIpAddress().isEmpty()) {
            // 使用IP索引
            result = new HashSet<>(ipIndex.getOrDefault(request.getIpAddress(), new HashSet<>()));
            indexStats.ipIndexHits++;
        } else {
            // 无索引可用
            result = new HashSet<>();
            indexStats.fullScanCount++;
        }
        
        return result != null ? result : new HashSet<>();
    }
    
    /**
     * 查询包含关键词的日志ID
     */
    public Set<Integer> queryByKeyword(String keyword) {
        if (keyword == null || keyword.isEmpty()) {
            return new HashSet<>();
        }
        
        Set<Integer> result = contentIndex.getOrDefault(keyword.toLowerCase(), new HashSet<>());
        indexStats.keywordSearchCount++;
        return new HashSet<>(result);
    }
    
    /**
     * 接取关键词用于索引
     * 简单的按分隔符分割
     */
    private String[] extractKeywords(String message) {
        // 分割并过滤
        return Arrays.stream(message.toLowerCase()
                     .split("[\\s\\.,;!?\\-_/\\\\()\\[\\]{}]+"))
                     .filter(s -> !s.isEmpty())
                     .toArray(String[]::new);
    }
    
    /**
     * 清空所有索引
     */
    public synchronized void clearIndex() {
        dateIndex.clear();
        categoryIndex.clear();
        accountIndex.clear();
        contentIndex.clear();
        ipIndex.clear();
        indexStats = new IndexStats();
        log.info("所有索引已清空");
    }
    
    /**
     * 获取索引统计信息
     */
    public IndexStats getIndexStats() {
        return new IndexStats(indexStats);  // 返回拷贝以防止外部修改
    }
    
    /**
     * 获取索引覆盖的日期范围
     */
    public Map<String, String> getDateRange() {
        Map<String, String> result = new HashMap<>();
        if (dateIndex.isEmpty()) {
            result.put("start", "N/A");
            result.put("end", "N/A");
            return result;
        }
        
        LocalDate minDate = dateIndex.keySet().stream().min(LocalDate::compareTo).orElse(null);
        LocalDate maxDate = dateIndex.keySet().stream().max(LocalDate::compareTo).orElse(null);
        
        result.put("start", minDate != null ? minDate.toString() : "N/A");
        result.put("end", maxDate != null ? maxDate.toString() : "N/A");
        return result;
    }
    
    /**
     * 获取所有分类索引
     */
    public Set<String> getAllCategories() {
        return new HashSet<>(categoryIndex.keySet());
    }
    
    /**
     * 获取某个账号的日志总数
     */
    public int getAccountLogCount(int accountId) {
        return accountIndex.getOrDefault(accountId, new HashSet<>()).size();
    }
    
    /**
     * 索引统计信息类
     */
    public static class IndexStats {
        public long totalIndexedLogs = 0;
        public long dateIndexHits = 0;
        public long categoryIndexHits = 0;
        public long accountIndexHits = 0;
        public long ipIndexHits = 0;
        public long keywordSearchCount = 0;
        public long fullScanCount = 0;
        
        /**
         * 获取索引命中率
         */
        public double getIndexHitRate() {
            long totalQueries = dateIndexHits + categoryIndexHits + accountIndexHits + 
                               ipIndexHits + keywordSearchCount + fullScanCount;
            if (totalQueries == 0) return 0.0;
            long indexedQueries = dateIndexHits + categoryIndexHits + accountIndexHits + 
                                 ipIndexHits + keywordSearchCount;
            return (double) indexedQueries / totalQueries * 100;
        }
        
        /**
         * 拷贝构造函数
         */
        public IndexStats() {}
        
        public IndexStats(IndexStats other) {
            this.totalIndexedLogs = other.totalIndexedLogs;
            this.dateIndexHits = other.dateIndexHits;
            this.categoryIndexHits = other.categoryIndexHits;
            this.accountIndexHits = other.accountIndexHits;
            this.ipIndexHits = other.ipIndexHits;
            this.keywordSearchCount = other.keywordSearchCount;
            this.fullScanCount = other.fullScanCount;
        }
    }
}
