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

package org.gms.logsystem.core;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.category.DynamicCategoryManager;
import org.gms.logsystem.context.GameLogContext;
import org.gms.logsystem.context.LogContextManager;
import org.gms.logsystem.core.GameLogEntry;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * 混合日志记录器 - 整合简化日志和高性能异步日志
 * 根据分类等级自动选择合适的处理方式
 *
 * @author logs-system
 */
@Slf4j
@Component
public class HybridLogger {
    private final SimpleLogger simpleLogger;
    private final HighPerformanceLogger highPerformanceLogger;
    private final LogContextManager contextManager;
    private final DynamicCategoryManager categoryManager;

    public HybridLogger(SimpleLogger simpleLogger, HighPerformanceLogger highPerformanceLogger,
                       LogContextManager contextManager, DynamicCategoryManager categoryManager) {
        this.simpleLogger = simpleLogger;
        this.highPerformanceLogger = highPerformanceLogger;
        this.contextManager = contextManager;
        this.categoryManager = categoryManager;
    }

    /**
     * 记录日志 - 自动选择处理方式
     *
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @param message 日志消息
     */
    public void log(String majorCategory, String minorCategory, String message) {
        logWithContext(majorCategory, minorCategory, message, null);
    }

    /**
     * 记录日志 - 自动注入上下文
     *
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @param message 日志消息
     * @param customData 自定义数据（JSON格式）
     */
    public void logWithContext(String majorCategory, String minorCategory, String message, String customData) {
        // 获取当前上下文
        GameLogContext context = contextManager.getCurrentContext();

        // 获取分类信息
        var categoryInfo = categoryManager.getCategory(majorCategory, minorCategory);
        if (categoryInfo == null || !categoryInfo.isEnabled()) {
            log.warn("分类已禁用或不存在: {}.{}", majorCategory, minorCategory);
            return;
        }

        // 构建日志条目
        GameLogEntry entry = GameLogEntry.builder()
                .logId(UUID.randomUUID().toString())
                .timestamp(System.currentTimeMillis())
                .majorCategory(majorCategory)
                .minorCategory(minorCategory)
                .message(message)
                .performanceLevel(categoryInfo.getLevel())
                .extraData(customData)
                .build();

        // 根据性能等级选择处理方式
        String level = categoryInfo.getLevel();
        if ("HIGH".equals(level) || "MEDIUM".equals(level)) {
            // 高频和中频日志使用异步处理
            highPerformanceLogger.logAsync(entry, context);
        } else {
            // 低频日志使用简单处理
            simpleLogger.logWithContext(majorCategory, minorCategory, message, customData);
        }

        // 控制台输出
        if (categoryInfo.isConsoleOutput()) {
            log.info("[{}.{}] {}", majorCategory, minorCategory, message);
        }
    }

    /**
     * 记录异常日志
     *
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @param message 日志消息
     * @param exception 异常对象
     */
    public void logException(String majorCategory, String minorCategory, String message, Throwable exception) {
        GameLogContext context = contextManager.getCurrentContext();

        var categoryInfo = categoryManager.getCategory(majorCategory, minorCategory);
        if (categoryInfo == null || !categoryInfo.isEnabled()) {
            return;
        }

        GameLogEntry entry = GameLogEntry.builder()
                .logId(UUID.randomUUID().toString())
                .timestamp(System.currentTimeMillis())
                .majorCategory(majorCategory)
                .minorCategory(minorCategory)
                .message(message)
                .performanceLevel(categoryInfo.getLevel())
                .exception(true)
                .stackTrace(getStackTrace(exception))
                .build();

        // 异常日志始终使用异步处理
        highPerformanceLogger.logAsync(entry, context);
        log.error("[{}.{}] {}", majorCategory, minorCategory, message, exception);
    }

    /**
     * 批量记录日志
     *
     * @param entries 日志条目数组
     */
    public void logBatch(GameLogEntry... entries) {
        GameLogContext context = contextManager.getCurrentContext();

        for (GameLogEntry entry : entries) {
            var categoryInfo = categoryManager.getCategory(entry.getMajorCategory(), entry.getMinorCategory());
            if (categoryInfo != null && categoryInfo.isEnabled()) {
                highPerformanceLogger.logAsync(entry, context);
            }
        }
        log.debug("批量日志已提交: {} 条", entries.length);
    }

    /**
     * 获取堆栈跟踪
     */
    private String getStackTrace(Throwable exception) {
        StringBuilder sb = new StringBuilder();
        for (StackTraceElement element : exception.getStackTrace()) {
            sb.append(element.toString()).append("\n");
        }
        return sb.toString();
    }

    /**
     * 获取异步队列统计信息
     */
    public String getQueueStats() {
        return String.format("高频队列: %d, 中频队列: %d, 低频队列: %d",
                highPerformanceLogger.getQueueSize("HIGH"),
                highPerformanceLogger.getQueueSize("MEDIUM"),
                highPerformanceLogger.getQueueSize("LOW"));
    }

    /**
     * 获取上下文统计信息
     */
    public String getContextStats() {
        return String.format("活跃上下文: %d", contextManager.getContextCount());
    }
}
