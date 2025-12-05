package org.gms.client.cheatsystem.manager;

import lombok.Getter;
import org.gms.client.cheatsystem.core.CheatManager;
import org.gms.client.cheatsystem.core.CheatPlugin;
import org.gms.client.cheatsystem.core.CheatPluginFactory;
import org.gms.client.Character;
import org.gms.logsystem.category.DynamicCategoryManager;
import org.gms.logsystem.facade.CheatSystemLoggerFacade;

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
        CheatSystemLoggerFacade.logCheatSystemEventAuto(player, DynamicCategoryManager.Category.MINOR_PLUGIN_SYSTEM, "为玩家创建辅助管理器", "INFO");
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
            CheatSystemLoggerFacade.logCheatSystemEventAuto(player, DynamicCategoryManager.Category.MINOR_PLUGIN_SYSTEM, "为玩家注册了 " + pluginCount + " 个辅助插件", "INFO");
        }
    }
}