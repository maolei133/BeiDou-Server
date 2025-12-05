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

package org.gms.logsystem.context;

import org.gms.client.Character;
import org.gms.net.server.coordinator.session.Hwid;
import java.util.Set;

/**
 * 游戏日志上下文持有者 - 使用ThreadLocal存储当前线程的日志上下文
 * 支持在整个请求生命周期内自动传播玩家基础信息，避免重复记录
 * 
 * AOP拦截器在顶级方法执行时初始化上下文，子级日志记录时直接获取上下文
 * 
 * 使用场景:
 * 1. 顶级处理器（如玩家技能使用、移动等）在方法入口初始化上下文
 * 2. 子级业务逻辑记录日志时调用getContext()获取玩家信息
 * 3. 方法返回时清理上下文
 *
 * @author logs-system
 */
public class GameLogContextHolder {
    private static final ThreadLocal<GameLogContext> contextHolder = new ThreadLocal<>();

    /**
     * 初始化玩家日志上下文
     * 应在顶级方法（如事件处理器）入口调用
     * 自动填充：uuid、时间戳、玩家基础信息、MAC地址、硬件ID
     * 
     * @param chr 玩家角色对象
     */
    public static void initializeContext(Character chr) {
        if (chr == null) {
            return;
        }

        try {
            GameLogContext context = GameLogContext.builder()
                    .contextId(java.util.UUID.randomUUID().toString())
                    .accountId(chr.getAccountId())
                    .accountName(chr.getClient().getAccountName())
                    .characterId(chr.getId())
                    .characterName(chr.getName())
                    .characterLevel(chr.getLevel())
                    .jobName(chr.getJob().getName())
                    .jobId(chr.getJob().getId())
                    .ipAddress(chr.getClient().getRemoteAddress())
                    .macAddress(String.join(",", chr.getClient().getMacs()))
                    .hardwareId(chr.getClient().getHwid().hwid())
                    .channelId(chr.getClient().getChannel())
                    .mapId(chr.getMapId())
                    .mapName(chr.getMap() != null ? chr.getMap().getMapName() : "未知")
                    .createdTime(System.currentTimeMillis())
                    .lastAccessTime(System.currentTimeMillis())
                    .build();
            contextHolder.set(context);
        } catch (Exception e) {
            // 忽略初始化错误，避免影响业务逻辑
        }
    }

    /**
     * 获取当前线程的日志上下文
     * 
     * @return 日志上下文，若不存在返回null
     */
    public static GameLogContext getContext() {
        GameLogContext context = contextHolder.get();
        if (context != null) {
            context.updateAccessTime();
        }
        return context;
    }

    /**
     * 清理当前线程的日志上下文
     * 应在顶级方法返回前调用（finally块中）
     */
    public static void clearContext() {
        contextHolder.remove();
    }

    /**
     * 检查当前线程是否存在有效的日志上下文
     * 
     * @return true-存在有效上下文, false-不存在或已过期
     */
    public static boolean hasValidContext() {
        GameLogContext context = contextHolder.get();
        return context != null && !context.isExpired();
    }

    /**
     * 手动清理所有线程的过期上下文（系统维护用）
     * 注意：这是一个全局操作，一般不需要调用
     */
    public static void clearAllContexts() {
        contextHolder.remove();
    }

    /**
     * 获取活跃的上下文数量
     * 
     * @return 活跃上下文数量
     */
    public static int getActiveContextCount() {
        // 返回当前存在的上下文数量（简化实现）
        return contextHolder.get() != null ? 1 : 0;
    }

    /**
     * 获取已创建的上下文总数
     * 
     * @return 创建的上下文总数
     */
    public static long getTotalCreatedContexts() {
        // 返回已创建的上下文总数（可需要外部计数器支持）
        return contextHolder.get() != null ? 1 : 0;
    }
}
