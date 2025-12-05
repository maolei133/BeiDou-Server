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

package org.gms.logsystem.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 配置变更通知管理器
 * 管理配置变更监听器，并在配置变更时通知所有订阅者
 */
@Slf4j
@Service
public class ConfigChangeNotifier {
    private final List<ConfigChangeListener> listeners = new CopyOnWriteArrayList<>();
    private final Map<String, List<ConfigChangeListener>> typeListeners = new HashMap<>();

    /**
     * 注册全局配置变更监听器
     */
    public void registerListener(ConfigChangeListener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
            log.info("已注册配置变更监听器: {}", listener.getListenerId());
        }
    }

    /**
     * 注册指定配置类型的监听器
     */
    public void registerListener(String configType, ConfigChangeListener listener) {
        if (listener != null) {
            typeListeners.computeIfAbsent(configType, k -> new CopyOnWriteArrayList<>()).add(listener);
            log.info("已注册{}类型配置变更监听器: {}", configType, listener.getListenerId());
        }
    }

    /**
     * 移除监听器
     */
    public void removeListener(ConfigChangeListener listener) {
        if (listener != null) {
            listeners.remove(listener);
            typeListeners.values().forEach(list -> list.remove(listener));
            log.info("已移除配置变更监听器: {}", listener.getListenerId());
        }
    }

    /**
     * 移除指定配置类型的监听器
     */
    public void removeListener(String configType, ConfigChangeListener listener) {
        if (listener != null && typeListeners.containsKey(configType)) {
            typeListeners.get(configType).remove(listener);
            log.info("已移除{}类型配置变更监听器: {}", configType, listener.getListenerId());
        }
    }

    /**
     * 通知所有监听器配置已变更
     */
    public void notifyChange(ConfigChangeEvent event) {
        if (event == null) {
            return;
        }

        try {
            // 通知全局监听器
            for (ConfigChangeListener listener : listeners) {
                try {
                    listener.onConfigChange(event);
                } catch (Exception e) {
                    log.error("配置变更通知失败: {}", listener.getListenerId(), e);
                }
            }

            // 通知类型特定的监听器
            List<ConfigChangeListener> typeSpecificListeners = typeListeners.get(event.getConfigType());
            if (typeSpecificListeners != null) {
                for (ConfigChangeListener listener : typeSpecificListeners) {
                    try {
                        listener.onConfigChange(event);
                    } catch (Exception e) {
                        log.error("配置变更通知失败: {}", listener.getListenerId(), e);
                    }
                }
            }

            log.info("配置变更通知已发送: {} -> {}", event.getConfigKey(), event.getNewValue());
        } catch (Exception e) {
            log.error("配置变更通知发生异常", e);
        }
    }

    /**
     * 获取所有监听器数量
     */
    public int getListenerCount() {
        return listeners.size();
    }

    /**
     * 获取指定配置类型的监听器数量
     */
    public int getListenerCount(String configType) {
        List<ConfigChangeListener> typeSpecificListeners = typeListeners.get(configType);
        return typeSpecificListeners != null ? typeSpecificListeners.size() : 0;
    }

    /**
     * 清空所有监听器
     */
    public void clearAllListeners() {
        listeners.clear();
        typeListeners.clear();
        log.info("已清空所有配置变更监听器");
    }
}
