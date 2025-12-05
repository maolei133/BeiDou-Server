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
import org.gms.logsystem.category.CategoryInfo;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * 简化日志记录器 - 提供简化的日志记录接口
 * 隐藏复杂的日志系统细节，提供易用的API
 *
 * @author logs-system
 */
@Slf4j
@Component
public class SimpleLogger {
    private final DynamicCategoryManager categoryManager;

    public SimpleLogger(DynamicCategoryManager categoryManager) {
        this.categoryManager = categoryManager;
    }

    /**
     * 记录一条日志
     *
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @param message       日志消息
     */
    public void log(String majorCategory, String minorCategory, String message) {
        logWithContext(majorCategory, minorCategory, message, null);
    }

    /**
     * 记录一条带上下文的日志
     *
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @param message       日志消息
     * @param context       日志上下文
     */
    public void logWithContext(String majorCategory, String minorCategory, String message, String context) {
        // 检查分类是否存在
        CategoryInfo categoryInfo = categoryManager.getCategory(majorCategory, minorCategory);
        if (categoryInfo == null) {
            log.warn("未找到分类: {}.{}", majorCategory, minorCategory);
            return;
        }

        // 检查分类是否启用
        if (!categoryInfo.isEnabled()) {
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
                .extraData(context)
                .build();

        // 输出日志
        if (categoryInfo.isConsoleOutput()) {
            log.info("[{}.{}] {}", majorCategory, minorCategory, message);
        }

        if (categoryInfo.isFileOutput()) {
            // 文件输出逻辑将在混合日志架构中实现
            log.debug("日志条目已准备写入文件: {}", entry.getLogId());
        }
    }

    public void logException(String majorCategory, String minorCategory, String message, Throwable exception) {
        CategoryInfo categoryInfo = categoryManager.getCategory(majorCategory, minorCategory);
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

        log.error("[{}.{}] {} - {}", majorCategory, minorCategory, message, exception.getMessage(), exception);
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
     * 批量记录日志
     *
     * @param entries 日志条目集合
     */
    public void logBatch(GameLogEntry... entries) {
        for (GameLogEntry entry : entries) {
            CategoryInfo categoryInfo = categoryManager.getCategory(entry.getMajorCategory(), entry.getMinorCategory());
            if (categoryInfo != null && categoryInfo.isEnabled()) {
                log.info("[{}.{}] {}", entry.getMajorCategory(), entry.getMinorCategory(), entry.getMessage());
            }
        }
    }

    /**
     * 获取分类管理器
     */
    public DynamicCategoryManager getCategoryManager() {
        return categoryManager;
    }
}
