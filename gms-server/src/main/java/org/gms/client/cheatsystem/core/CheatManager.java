package org.gms.client.cheatsystem.core;

import org.apache.logging.log4j.message.MapMessage;
import org.gms.client.Character;
import org.gms.server.logging.AuditContext;
import org.gms.server.logging.AuditLogger;
import org.gms.server.logging.LogAction;
import org.gms.server.logging.LogModule;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 内置辅助管理器
 * 负责管理所有内置辅助插件的生命周期
 */
public class CheatManager {
    private final Character player;
    private final Map<String, CheatPlugin> plugins = new ConcurrentHashMap<>();
    
    public CheatManager(Character player) {
        this.player = player;
        if (player != null) {
            logCheatSystemEvent("创建辅助管理器实例", "INFO");
        }
    }
    
    /**
     * 注册插件
     * @param plugin 辅助插件
     */
    public void registerPlugin(CheatPlugin plugin) {
        if (player != null) {
            plugin.initialize(player);
            plugins.put(plugin.getName(), plugin);
            logCheatSystemEvent("注册辅助插件: " + plugin.getName(), "INFO");
        }
    }
    
    /**
     * 注销插件
     * @param pluginName 插件名称
     */
    public void unregisterPlugin(String pluginName) {
        if (player != null) {
            CheatPlugin plugin = plugins.remove(pluginName);
            if (plugin != null) {
                plugin.stop();
                logCheatSystemEvent("注销辅助插件: " + pluginName, "INFO");
            }
        }
    }
    
    /**
     * 获取插件
     * @param pluginName 插件名称
     * @return 辅助插件
     */
    @SuppressWarnings("unchecked")
    public <T extends CheatPlugin> T getPlugin(String pluginName) {
        return (T) plugins.get(pluginName);
    }
    
    /**
     * 获取所有插件
     * @return 插件集合
     */
    public Collection<CheatPlugin> getAllPlugins() {
        return plugins.values();
    }
    
    /**
     * 启动所有插件
     */
    public void startAllPlugins() {
        if (player != null) {
            plugins.values().forEach(plugin -> {
                plugin.start();
                logCheatSystemEvent("启动插件: " + plugin.getName(), "INFO");
            });
        }
    }
    
    /**
     * 停止所有插件
     */
    public void stopAllPlugins() {
        if (player != null) {
            plugins.values().forEach(plugin -> {
                plugin.stop();
                logCheatSystemEvent("停止插件: " + plugin.getName(), "INFO");
            });
        }
    }
    
    /**
     * 更新所有插件配置
     */
    public void updateAllConfig() {
        if (player != null) {
            plugins.values().forEach(plugin -> {
                plugin.updateConfig();
                logCheatSystemEvent("更新辅助插件配置: " + plugin.getName(), "INFO");
            });
        }
    }

    private void logCheatSystemEvent(String message, String level) {
        // 确保上下文存在
        boolean contextSet = false;
        if (AuditContext.get().isEmpty() && player != null && player.getClient() != null) {
            AuditContext.set(player.getClient());
            contextSet = true;
        }

        try {
            MapMessage data = new MapMessage()
                .with("msg", message);
            
            if ("WARN".equals(level) || "ERROR".equals(level)) {
                 AuditLogger.error(LogModule.PLUGIN, LogAction.PLUGIN_ERROR, message, null);
            } else {
                 AuditLogger.info(LogModule.PLUGIN, LogAction.PLUGIN_USE, data);
            }
        } finally {
            // 如果是我们临时设置的上下文，使用完后清理，避免污染线程
            if (contextSet) {
                AuditContext.clear();
            }
        }
    }
}
