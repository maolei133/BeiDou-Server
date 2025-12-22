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
 * 玩家日志门面类
 * 为玩家相关的操作（如登录、登出、战斗、移动）提供统一的日志记录接口。
 *
 * <h3>使用方法:</h3>
 * <ol>
 *   <li>在需要记录完整上下文的顶级方法（如处理玩家登录），使用 {@code logLogin(chr)}。</li>
 *   <li>在已知上下文已存在的子级方法中，使用 {@code logMovementData("some message")}。</li>
 *   <li>推荐使用 {@code logPlayerEventAuto}，它能自动处理上下文，更安全。</li>
 * </ol>
 */
@Slf4j
@Component
public class PlayerLoggerFacade {

    private static HighPerformanceLogger highPerformanceLogger;

    @Autowired
    public void setHighPerformanceLogger(HighPerformanceLogger logger) {
        PlayerLoggerFacade.highPerformanceLogger = logger;
    }

    /**
     * 自动执行上下文管理的玩家事件日志记录
     * <p>
     * 无需手动判断上下文是否存在，自动处理上下文的初始化和清理。
     *
     * @param chr           玩家角色对象（用于在需要时初始化上下文）
     * @param minorCategory 事件的次要类别
     * @param message       日志消息
     * @param level         日志级别
     */
    public static void logPlayerEventAuto(Character chr, String minorCategory, String message, String level) {
        if (highPerformanceLogger == null || chr == null) {
            return;
        }

        try {
            if (GameLogContextHolder.hasValidContext()) {
                // 上下文已存在，直接记录数据，避免重复初始化
                logPlayerData(minorCategory, message, level);
            } else {
                // 上下文不存在，自动初始化临时上下文，并在使用后清理
                GameLogContextHolder.initializeContext(chr);
                try {
                    logPlayerData(minorCategory, message, level);
                } finally {
                    GameLogContextHolder.clearContext();
                }
            }
        } catch (Exception e) {
            log.error("[ERROR] 记录玩家日志失败: {}", e.getMessage(), e);
        }
    }

    /**
     * 通用玩家事件日志记录 - 仅关键数据版
     * <p>
     * 此方法假定日志上下文已由外部（如AOP切面或顶层调用）设置。
     * 基础信息（如玩家ID、地图）将从上下文中自动填充。
     *
     * @param minorCategory 事件的次要类别
     * @param message       日志消息
     * @param level         日志级别
     */
    public static void logPlayerData(String minorCategory, String message, String level) {
        if (highPerformanceLogger == null) {
            return;
        }

        try {
            GameLogEntry entry = GameLogEntry.builder()
                    .majorCategory(DynamicCategoryManager.Category.MAJOR_PLAYER)
                    .minorCategory(minorCategory)
                    .level(level)
                    .message(message)
                    .performanceLevel("HIGH") // 玩家操作通常是高优先级日志
                    .exception(false)
                    .build();

            // 异步记录日志，并传递当前上下文
            highPerformanceLogger.logAsync(entry, GameLogContextHolder.getContext());
        } catch (Exception e) {
            log.error("[ERROR] 记录玩家数据日志失败: {}", e.getMessage(), e);
        }
    }

    /**
     * 记录玩家登录日志。
     *
     * @param chr 登录的玩家角色对象
     */
    public static void logLogin(Character chr) {
        logPlayerEventAuto(chr, DynamicCategoryManager.Category.MINOR_PLAYER_LOGIN, "玩家登录成功", "INFO");
    }

    /**
     * 记录玩家登出日志。
     *
     * @param chr 登出的玩家角色对象
     */
    public static void logLogout(Character chr) {
        logPlayerEventAuto(chr, DynamicCategoryManager.Category.MINOR_PLAYER_LOGOUT, "玩家正常登出", "INFO");
    }

    /**
     * 记录玩家移动日志 - 仅关键数据版。
     * <p>
     * <strong>注意:</strong> 此方法应在已建立日志上下文的环境中调用。
     *
     * @param message 移动相关信息
     */
    public static void logMovementData(String message) {
        logPlayerData(DynamicCategoryManager.Category.MINOR_PLAYER_MOVEMENT, message, "INFO");
    }

    /**
     * 记录玩家战斗日志 - 仅关键数据版。
     * <p>
     * <strong>注意:</strong> 此方法应在已建立日志上下文的环境中调用。
     *
     * @param message 战斗相关信息
     */
    public static void logCombatData(String message) {
        logPlayerData(DynamicCategoryManager.Category.MINOR_PLAYER_COMBAT, message, "INFO");
    }
}
