package org.gms.cheat.manager;

import lombok.Getter;
import org.gms.cheat.core.CheatManager;
import org.gms.cheat.core.CheatPlugin;
import org.gms.cheat.core.CheatPluginFactory;
import org.gms.client.Character;
import org.gms.log.CheatLogger;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 辅助模块管理器
 * 管理所有玩家的辅助管理器实例
 */
public class CheatModuleManager {
    @Getter
    private static final CheatModuleManager instance = new CheatModuleManager();
    
    private final Map<Integer, CheatManager> cheatManagers = new ConcurrentHashMap<>();
    
    private CheatModuleManager() {
        // 私有构造函数，确保单例
        CheatLogger.logCheatSystem(null, "辅助模块管理器初始化");
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
        CheatLogger.logCheatSystem(player, "为玩家创建辅助管理器");
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
            CheatLogger.logCheatSystem(null, "移除玩家ID为 " + playerId + " 的辅助管理器");
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
        
        CheatLogger.logCheatSystem(player, "为玩家注册了 " + pluginCount + " 个辅助插件");
    }
}