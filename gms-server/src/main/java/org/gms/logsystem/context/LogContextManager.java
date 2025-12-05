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

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 日志上下文管理器 - 负责日志上下文的创建、存储、获取和清理
 * 使用ThreadLocal + 缓存的双重存储机制
 *
 * @author logs-system
 */
@Slf4j
@Component
public class LogContextManager {
    /**
     * ThreadLocal上下文存储
     */
    private static final ThreadLocal<GameLogContext> CONTEXT_THREAD_LOCAL = new ThreadLocal<>();

    /**
     * 上下文缓存（用于分布式环境下的上下文共享）
     */
    private final Map<String, GameLogContext> contextCache = new ConcurrentHashMap<>();

    /**
     * 上下文索引（按用户ID快速查询）
     */
    private final Map<Integer, Set<String>> userContextIndex = new ConcurrentHashMap<>();

    /**
     * 创建新的上下文
     */
    public synchronized GameLogContext createContext() {
        GameLogContext context = GameLogContext.builder()
                .contextId(UUID.randomUUID().toString())
                .createdTime(System.currentTimeMillis())
                .lastAccessTime(System.currentTimeMillis())
                .build();

        CONTEXT_THREAD_LOCAL.set(context);
        contextCache.put(context.getContextId(), context);

        log.debug("日志上下文已创建: {}", context.getContextId());
        return context;
    }

    /**
     * 从ThreadLocal获取当前上下文
     */
    public GameLogContext getCurrentContext() {
        GameLogContext context = CONTEXT_THREAD_LOCAL.get();
        if (context != null) {
            context.updateAccessTime();
        }
        return context;
    }

    /**
     * 从缓存获取上下文
     */
    public GameLogContext getContext(String contextId) {
        GameLogContext context = contextCache.get(contextId);
        if (context != null && !context.isExpired()) {
            context.updateAccessTime();
            return context;
        } else if (context != null && context.isExpired()) {
            // 清除过期上下文
            removeContext(contextId);
        }
        return null;
    }

    /**
     * 设置当前上下文
     */
    public void setCurrentContext(GameLogContext context) {
        if (context != null) {
            CONTEXT_THREAD_LOCAL.set(context);
            contextCache.put(context.getContextId(), context);
            if (context.getAccountId() > 0) {
                updateUserIndex(context.getAccountId(), context.getContextId());
            }
            log.debug("日志上下文已设置: {}", context.getContextId());
        }
    }

    /**
     * 获取指定用户的所有上下文
     */
    public Collection<GameLogContext> getUserContexts(int accountId) {
        Set<String> contextIds = userContextIndex.get(accountId);
        if (contextIds == null) {
            return Collections.emptyList();
        }

        List<GameLogContext> contexts = new ArrayList<>();
        for (String contextId : contextIds) {
            GameLogContext context = contextCache.get(contextId);
            if (context != null && !context.isExpired()) {
                contexts.add(context);
            } else if (context != null) {
                removeContext(contextId);
            }
        }
        return contexts;
    }

    /**
     * 更新用户索引
     */
    private synchronized void updateUserIndex(int accountId, String contextId) {
        userContextIndex.computeIfAbsent(accountId, k -> ConcurrentHashMap.newKeySet())
                .add(contextId);
    }

    /**
     * 移除上下文
     */
    public synchronized boolean removeContext(String contextId) {
        GameLogContext removed = contextCache.remove(contextId);
        if (removed != null) {
            if (removed.getAccountId() > 0) {
                Set<String> userContexts = userContextIndex.get(removed.getAccountId());
                if (userContexts != null) {
                    userContexts.remove(contextId);
                }
            }
            log.debug("日志上下文已移除: {}", contextId);
            return true;
        }
        return false;
    }

    /**
     * 清除当前线程的上下文
     */
    public void clearCurrentContext() {
        GameLogContext context = CONTEXT_THREAD_LOCAL.get();
        if (context != null) {
            log.debug("当前线程的日志上下文已清除: {}", context.getContextId());
        }
        CONTEXT_THREAD_LOCAL.remove();
    }

    /**
     * 清除过期的上下文
     */
    public synchronized void clearExpiredContexts() {
        List<String> expiredContextIds = new ArrayList<>();
        for (Map.Entry<String, GameLogContext> entry : contextCache.entrySet()) {
            if (entry.getValue().isExpired()) {
                expiredContextIds.add(entry.getKey());
            }
        }

        for (String contextId : expiredContextIds) {
            removeContext(contextId);
        }

        if (!expiredContextIds.isEmpty()) {
            log.info("已清除 {} 个过期的日志上下文", expiredContextIds.size());
        }
    }

    /**
     * 清空所有上下文
     */
    public synchronized void clearAllContexts() {
        CONTEXT_THREAD_LOCAL.remove();
        contextCache.clear();
        userContextIndex.clear();
        log.info("所有日志上下文已清空");
    }

    /**
     * 获取上下文总数
     */
    public int getContextCount() {
        return contextCache.size();
    }

    /**
     * 获取指定用户的上下文数量
     */
    public int getUserContextCount(int accountId) {
        Set<String> contextIds = userContextIndex.get(accountId);
        return contextIds != null ? contextIds.size() : 0;
    }
}
