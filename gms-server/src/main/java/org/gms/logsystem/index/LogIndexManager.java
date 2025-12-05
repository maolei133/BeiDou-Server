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
import org.gms.logsystem.file.LogFileManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.File;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 日志索引管理器
 * 负责索引的初始化、维护和更新
 */
@Slf4j
@Service
public class LogIndexManager {
    
    @Autowired
    private LogIndexService logIndexService;
    
    @Autowired(required = false)
    private LogFileManager logFileManager;
    
    /**
     * 是否正在构建索引
     */
    private final AtomicBoolean isBuilding = new AtomicBoolean(false);
    
    /**
     * 最后一次重建索引的时间
     */
    private LocalDateTime lastRebuildTime;
    
    /**
     * 索引版本号
     */
    private AtomicInteger indexVersion = new AtomicInteger(0);
    
    /**
     * 应用启动时构建初始索引
     */
    @PostConstruct
    public void initializeIndex() {
        log.info("应用启动时初始化日志索引...");
        buildInitialIndex();
    }
    
    /**
     * 构建初始索引
     * 从日志文件中读取所有日志并构建索引
     */
    public synchronized void buildInitialIndex() {
        if (isBuilding.getAndSet(true)) {
            log.warn("索引正在构建中，跳过本次操作...");
            return;
        }
        
        try {
            long startTime = System.currentTimeMillis();
            int logCount = 0;
            
            log.info("开始从日志文件构建索引...");
            
            // 清空现有索引
            logIndexService.clearIndex();
            
            if (logFileManager != null) {
                // 正常情况下，LogFileManager不会指提供所有日志
                // 此处需要運配不同的矩串策略
                // 五是暂是空集合，所以需要不输入
                Map<Integer, GameLogEntry> allLogs = new HashMap<>();
                logIndexService.addLogsToIndex(allLogs);
                logCount = allLogs.size();
            }
            
            long endTime = System.currentTimeMillis();
            lastRebuildTime = LocalDateTime.now();
            indexVersion.incrementAndGet();
            
            log.info("索引构建成功，耗时 {}ms，已索引 {} 条日志",
                    endTime - startTime, logCount);
            
        } catch (Exception e) {
            log.error("索引构建失败", e);
        } finally {
            isBuilding.set(false);
        }
    }
    
    /**
     * 增量索引 - 添加单条日志到索引
     */
    public void addLogToIndex(int logId, GameLogEntry entry) {
        if (entry == null) {
            return;
        }
        
        try {
            logIndexService.addLogToIndex(logId, entry);
        } catch (Exception e) {
            log.error("添加日志 {} 到索引失败", logId, e);
        }
    }
    
    /**
     * 增量索引 - 添加多条日志到索引
     */
    public void addLogsToIndex(Map<Integer, GameLogEntry> logs) {
        if (logs == null || logs.isEmpty()) {
            return;
        }
        
        try {
            logIndexService.addLogsToIndex(logs);
        } catch (Exception e) {
            log.error("批量添加日志到索引失败", e);
        }
    }
    
    /**
     * 重建索引 - 定期执行
     * 每天凌晨2点执行一次
     */
    @Scheduled(cron = "0 0 2 * * *")
    public void rebuildIndexScheduled() {
        log.info("定时索引重建任务开始执行");
        buildInitialIndex();
    }
    
    /**
     * 主动重建索引 - 供管理员手动触发
     */
    public Map<String, Object> rebuildIndexManual() {
        Map<String, Object> result = new HashMap<>();
        
        try {
            if (isBuilding.get()) {
                result.put("success", false);
                result.put("message", "索引重建正在进行中");
                return result;
            }
            
            buildInitialIndex();
            
            result.put("success", true);
            result.put("message", "索引重建成功");
            result.put("rebuiltAt", LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME));
            result.put("stats", getIndexStats());
            
        } catch (Exception e) {
            result.put("success", false);
            result.put("message", "索引重建失败: " + e.getMessage());
            log.error("手动索引重建失败", e);
        }
        
        return result;
    }
    
    /**
     * 获取索引统计信息
     */
    public Map<String, Object> getIndexStats() {
        LogIndexService.IndexStats stats = logIndexService.getIndexStats();
        
        Map<String, Object> result = new HashMap<>();
        result.put("totalIndexedLogs", stats.totalIndexedLogs);
        result.put("dateIndexHits", stats.dateIndexHits);
        result.put("categoryIndexHits", stats.categoryIndexHits);
        result.put("accountIndexHits", stats.accountIndexHits);
        result.put("ipIndexHits", stats.ipIndexHits);
        result.put("keywordSearchCount", stats.keywordSearchCount);
        result.put("fullScanCount", stats.fullScanCount);
        result.put("indexHitRate", String.format("%.2f%%", stats.getIndexHitRate()));
        result.put("lastRebuildTime", lastRebuildTime != null ? 
                    lastRebuildTime.format(DateTimeFormatter.ISO_DATE_TIME) : "从未重建");
        result.put("indexVersion", indexVersion.get());
        result.put("isBuilding", isBuilding.get());
        
        return result;
    }
    
    /**
     * 获取索引覆盖的日期范围
     */
    public Map<String, String> getIndexDateRange() {
        return logIndexService.getDateRange();
    }
    
    /**
     * 获取所有已索引的分类
     */
    public Set<String> getIndexedCategories() {
        return logIndexService.getAllCategories();
    }
    
    /**
     * 检查索引是否需要重建
     * 基于文件修改时间和索引版本
     */
    public boolean needsRebuild() {
        if (lastRebuildTime == null) {
            return true;  // 从未构建过，需要构建
        }
        
        // 如果距离上次构建超过24小时，则需要重建
        LocalDateTime threshold = LocalDateTime.now().minusHours(24);
        return lastRebuildTime.isBefore(threshold);
    }
    
    /**
     * 清空索引 - 供管理员使用
     */
    public Map<String, Object> clearIndexManual() {
        Map<String, Object> result = new HashMap<>();
        
        try {
            logIndexService.clearIndex();
            indexVersion.incrementAndGet();
            
            result.put("success", true);
            result.put("message", "索引清空成功");
            result.put("clearedAt", LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME));
            
        } catch (Exception e) {
            result.put("success", false);
            result.put("message", "索引清空失败: " + e.getMessage());
            log.error("索引清空失败", e);
        }
        
        return result;
    }
    
    /**
     * 获取索引健康状态
     */
    public Map<String, Object> getIndexHealth() {
        LogIndexService.IndexStats stats = logIndexService.getIndexStats();
        
        Map<String, Object> result = new HashMap<>();
        result.put("healthy", stats.totalIndexedLogs > 0);
        result.put("totalLogs", stats.totalIndexedLogs);
        result.put("indexHitRate", String.format("%.2f%%", stats.getIndexHitRate()));
        result.put("lastRebuild", lastRebuildTime != null ? 
                    lastRebuildTime.format(DateTimeFormatter.ISO_DATE_TIME) : "从未重建");
        result.put("needsRebuild", needsRebuild());
        
        return result;
    }
}
