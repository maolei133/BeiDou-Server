package org.gms.client.cheatsystem.core;

import org.gms.client.Character;
import org.gms.logging.AuditLogger;
import org.gms.logging.LogModule;

import java.util.Collection;
import java.util.HashMap;
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
        Map<String, Object> data = new HashMap<>();
        data.put("chrId", player.getId());
        data.put("chr", player.getName());
        data.put("msg", message);
        
        if ("WARN".equals(level) || "ERROR".equals(level)) {
             AuditLogger.error(LogModule.SYSTEM, "CHEAT_SYSTEM", data, null);
        } else {
             AuditLogger.info(LogModule.SYSTEM, "CHEAT_SYSTEM", data);
        }
    }
}
