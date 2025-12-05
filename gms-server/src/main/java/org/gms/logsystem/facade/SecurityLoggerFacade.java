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
 * 安全日志门面类
 * 为反作弊、安全检测等模块提供统一的日志记录接口
 * 
 * 两层日志记录机制:
 * 1. 顶级方法（如玩家操作事件处理）在入口初始化上下文，该层记录完整玩家信息
 * 2. 子级方法记录日志时使用logSecurityEventData()，只需提供关键数据，基础信息由AOP上下文自动填充
 */
@Slf4j
@Component
public class SecurityLoggerFacade {
    
    private static HighPerformanceLogger highPerformanceLogger;
    
    @Autowired
    public void setHighPerformanceLogger(HighPerformanceLogger logger) {
        SecurityLoggerFacade.highPerformanceLogger = logger;
    }

    /**
     * 通用安全事件日志记录 - 仅关键数据版（子级调用，基础信息由上下文自动填充）
     */
    public static void logSecurityEventData(String minorCategory, String message, String level) {
        if (highPerformanceLogger == null) {
            return;
        }
        
        try {
            GameLogEntry entry = GameLogEntry.builder()
                    .majorCategory(DynamicCategoryManager.Category.MAJOR_SECURITY)
                    .minorCategory(minorCategory)
                    .level(level)
                    .message(message)
                    .performanceLevel("HIGH")
                    .exception(false)
                    .build();
            
            // 传递上下文，由HighPerformanceLogger自动填充基础信息、uuid、时间戳
            highPerformanceLogger.logAsync(entry, GameLogContextHolder.getContext());
        } catch (Exception e) {
            log.error("[ERROR] 记录安全日志失败: {}", e.getMessage(), e);
        }
    }
    
    /**
     * 外挂检测日志 - 仅关键数据版（子级调用）
     */
    public static void logHackDetectionData(String hackType, String message) {
        logSecurityEventData(DynamicCategoryManager.Category.MINOR_HACK_DETECTION, 
                String.format("[%s] %s", hackType, message), "WARN");
    }
    
    /**
     * 伤害外挂日志 - 仅关键数据版（子级调用）
     */
    public static void logDamageHackData(String message) {
        logHackDetectionData("damage_hack", message);
    }
    
    /**
     * 速度外挂日志 - 仅关键数据版（子级调用）
     */
    public static void logSpeedHackData(String message) {
        logHackDetectionData("speed_hack", message);
    }
    
    /**
     * 跳跃外挂日志 - 仅关键数据版（子级调用）
     */
    public static void logJumpHackData(String message) {
        logHackDetectionData("jump_hack", message);
    }
    
    /**
     * 快速攻击检测日志 - 仅关键数据版（子级调用）
     */
    public static void logFastAttackData(String skillName, long interval, long minInterval) {
        logHackDetectionData("fast_attack", 
                String.format("技能: %s, 攻击间隔: %dms (最小: %dms)", skillName, interval, minInterval));
    }
    
    /**
     * Miss无敌检测日志 - 仅关键数据版（子级调用）
     */
    public static void logMissHackData(int missCount) {
        logHackDetectionData("miss_hack", String.format("连续miss次数: %d", missCount));
    }
    
    /**
     * 账号安全相关日志 - 仅关键数据版（子级调用）
     */
    public static void logAccountSecurityData(String eventType, String message) {
        logSecurityEventData(DynamicCategoryManager.Category.MINOR_ACCOUNT_SECURITY,
                String.format("[%s] %s", eventType, message), "INFO");
    }
    
    /**
     * 登录异常日志 - 仅关键数据版（子级调用）
     */
    public static void logAbnormalLoginData(String reason) {
        logAccountSecurityData("abnormal_login", reason);
    }
    
    /**
     * IP变更日志 - 仅关键数据版（子级调用）
     */
    public static void logIPChangeData(String oldIP, String newIP) {
        logAccountSecurityData("ip_change", String.format("IP从 %s 变更为 %s", oldIP, newIP));
    }

    /**
     * 自动执行上下文管理的安全事件日志记录
     * 无需手动判断上下文是否存在，自动处理上下文的初始化和清理
     * 
     * @param chr 玩家角色对象（用于初始化上下文）
     * @param minorCategory 事件类别
     * @param message 日志消息
     * @param level 日志级别
     */
    public static void logSecurityEventAuto(Character chr, String minorCategory, String message, String level) {
        if (highPerformanceLogger == null || chr == null) {
            return;
        }

        try {
            if (GameLogContextHolder.hasValidContext()) {
                // 上下文存在，优先使用仅关键数据版本（防止重复记录）
                logSecurityEventData(minorCategory, message, level);
            } else {
                // 自动初始化临时上下文，使用后自动清理
                GameLogContextHolder.initializeContext(chr);
                try {
                    logSecurityEventData(minorCategory, message, level);
                } finally {
                    GameLogContextHolder.clearContext();
                }
            }
        } catch (Exception e) {
            log.error("[ERROR] 记录安全日志失败: {}", e.getMessage(), e);
        }
    }
}
