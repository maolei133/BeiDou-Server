package org.gms.client.cheatsystem.manager;

import lombok.Getter;
import org.apache.logging.log4j.message.MapMessage;
import org.gms.client.cheatsystem.core.CheatManager;
import org.gms.client.cheatsystem.core.CheatPlugin;
import org.gms.client.cheatsystem.core.CheatPluginFactory;
import org.gms.client.Character;
import org.gms.server.logging.AuditContext;
import org.gms.server.logging.AuditLogger;
import org.gms.server.logging.LogAction;
import org.gms.server.logging.LogModule;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 内置辅助模块管理器
 * 管理所有玩家的内置辅助管理器实例
 */
public class CheatModuleManager {
    @Getter
    private static final CheatModuleManager instance = new CheatModuleManager();
    
    private final Map<Integer, CheatManager> cheatManagers = new ConcurrentHashMap<>();
    
    private CheatModuleManager() {
        // 私有构造函数，确保单例
        // 辅助模块管理器不需要辜助辜助日志，应用程序已于启动时打印
    }

    /**
     * 为玩家创建辅助管理器
     * @param player 玩家对象
     * @return 辅助管理器
     */
    public CheatManager createCheatManager(Character player) {
        if (player == null) {
            return null;
        }
        
        CheatManager cheatManager = new CheatManager(player);
        cheatManagers.put(player.getId(), cheatManager);
        logCheatSystemEvent(player, "为玩家创建辅助管理器", "INFO");
        return cheatManager;
    }
    
    /**
     * 获取玩家的辅助管理器
     * @param playerId 玩家ID
     * @return 辅助管理器
     */
    public CheatManager getCheatManager(int playerId) {
        return cheatManagers.get(playerId);
    }
    
    /**
     * 移除玩家的辅助管理器
     * @param playerId 玩家ID
     */
    public void removeCheatManager(int playerId) {
        CheatManager cheatManager = cheatManagers.remove(playerId);
        if (cheatManager != null) {
            cheatManager.stopAllPlugins();
            // 移除玉家信息不辜助辜助日志，仅清理插件
        }
    }
    
    /**
     * 为指定玩家注册所有插件
     * @param player 玩家对象
     */
    public void registerAllPlugins(Character player) {
        if (player == null) {
            return;
        }
        
        CheatManager cheatManager = getCheatManager(player.getId());
        if (cheatManager == null) {
            cheatManager = createCheatManager(player);
        }
        
        // 注册所有已知插件
        int pluginCount = 0;
        for (String pluginName : CheatPluginFactory.getRegisteredPlugins()) {
            CheatPlugin plugin = CheatPluginFactory.createPlugin(pluginName);
            cheatManager.registerPlugin(plugin);
            pluginCount++;
        }
        
        if (pluginCount > 0) {
            logCheatSystemEvent(player, "为玩家注册了 " + pluginCount + " 个辅助插件", "INFO");
        }
    }

    private void logCheatSystemEvent(Character player, String message, String level) {
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
