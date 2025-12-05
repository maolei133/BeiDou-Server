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

package org.gms.logsystem.facade;

import lombok.extern.slf4j.Slf4j;
import org.gms.client.Character;
import org.gms.logsystem.category.DynamicCategoryManager;
import org.gms.logsystem.context.GameLogContextHolder;
import org.gms.logsystem.core.GameLogEntry;
import org.gms.logsystem.core.HighPerformanceLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * 内置辅助系统日志门面类
 * 为内置辅助系统提供统一的日志记录接口
 * 
 * 两层日志记录机制:
 * 1. 顶级方法（如插件激活）在入口初始化上下文，该层记录完整玩家信息
 * 2. 子级方法记录日志时使用logCheatSystemData()，只需提供关键数据，基础信息由AOP上下文自动填充
 */
@Slf4j
@Component
public class CheatSystemLoggerFacade {
    
    private static HighPerformanceLogger highPerformanceLogger;
    
    @Autowired
    public void setHighPerformanceLogger(HighPerformanceLogger logger) {
        CheatSystemLoggerFacade.highPerformanceLogger = logger;
    }

    /**
     * 通用内置辅助系统事件日志记录 - 仅关键数据版（子级调用，基础信息由上下文自动填充）
     */
    public static void logCheatSystemData(String minorCategory, String message, String level) {
        if (highPerformanceLogger == null) {
            return;
        }
        
        try {
            GameLogEntry entry = GameLogEntry.builder()
                    .majorCategory(DynamicCategoryManager.Category.MAJOR_CHEATSYSTEM)
                    .minorCategory(minorCategory)
                    .level(level)
                    .message(message)
                    .performanceLevel("HIGH")
                    .exception(false)
                    .build();
            
            // 传递上下文，由HighPerformanceLogger自动填充基础信息、uuid、时间戳
            highPerformanceLogger.logAsync(entry, GameLogContextHolder.getContext());
        } catch (Exception e) {
            log.error("[ERROR] 记录内置辅助系统日志失败: {}", e.getMessage(), e);
        }
    }
    
    /**
     * 插件激活日志 - 仅关键数据版（子级调用）
     */
    public static void logPluginActivationData(String pluginName, String message) {
        logCheatSystemData(DynamicCategoryManager.Category.MINOR_PLUGIN_ACTIVATION, 
                String.format("[%s] %s", pluginName, message), "INFO");
    }
    
    /**
     * 插件操作日志 - 仅关键数据版（子级调用）
     */
    public static void logPluginOperationData(String pluginName, String message) {
        logCheatSystemData(DynamicCategoryManager.Category.MINOR_PLUGIN_OPERATION,
                String.format("[%s] %s", pluginName, message), "INFO");
    }
    
    /**
     * 插件系统日志 - 仅关键数据版（子级调用）
     */
    public static void logPluginSystemData(String pluginName, String message) {
        logCheatSystemData(DynamicCategoryManager.Category.MINOR_PLUGIN_SYSTEM,
                String.format("[%s] %s", pluginName, message), "INFO");
    }

    /**
     * 自动执行上下文管理的内置辅助系统事件日志记录
     * 无需手动判断上下文是否存在，自动处理上下文的初始化和清理
     * 
     * @param chr 玩家角色对象（用于初始化上下文）
     * @param minorCategory 事件类别
     * @param message 日志消息
     * @param level 日志级别
     */
    public static void logCheatSystemEventAuto(Character chr, String minorCategory, String message, String level) {
        if (highPerformanceLogger == null || chr == null) {
            return;
        }

        try {
            if (GameLogContextHolder.hasValidContext()) {
                // 上下文存在，优先使用仅关键数据版本（防止重复记录）
                logCheatSystemData(minorCategory, message, level);
            } else {
                // 自动初始化临时上下文，使用后自动清理
                GameLogContextHolder.initializeContext(chr);
                try {
                    logCheatSystemData(minorCategory, message, level);
                } finally {
                    GameLogContextHolder.clearContext();
                }
            }
        } catch (Exception e) {
            log.error("[ERROR] 记录内置辅助系统日志失败: {}", e.getMessage(), e);
        }
    }
}