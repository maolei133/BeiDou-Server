package org.gms.cheat.core;

import org.gms.client.Character;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 作弊管理器
 * 负责管理所有作弊插件的生命周期
 */
public class CheatManager {
    private final Character player;
    private final Map<String, CheatPlugin> plugins = new ConcurrentHashMap<>();
    
    public CheatManager(Character player) {
        this.player = player;
    }
    
    /**
     * 注册插件
     * @param plugin 作弊插件
     */
    public void registerPlugin(CheatPlugin plugin) {
        plugin.initialize(player);
        plugins.put(plugin.getName(), plugin);
    }
    
    /**
     * 注销插件
     * @param pluginName 插件名称
     */
    public void unregisterPlugin(String pluginName) {
        CheatPlugin plugin = plugins.remove(pluginName);
        if (plugin != null) {
            plugin.stop();
        }
    }
    
    /**
     * 获取插件
     * @param pluginName 插件名称
     * @return 作弊插件
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
        plugins.values().forEach(CheatPlugin::start);
    }
    
    /**
     * 停止所有插件
     */
    public void stopAllPlugins() {
        plugins.values().forEach(CheatPlugin::stop);
    }
    
    /**
     * 更新所有插件配置
     */
    public void updateAllConfig() {
        plugins.values().forEach(CheatPlugin::updateConfig);
    }
}