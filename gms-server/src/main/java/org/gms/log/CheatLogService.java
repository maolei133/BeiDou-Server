package org.gms.log;

import org.gms.client.Character;
import org.gms.cheat.core.CheatPlugin;

/**
 * 辅助系统日志服务类
 * 提供便捷的方法供辅助系统各部分调用
 */
public class CheatLogService {
    
    /**
     * 记录插件激活事件
     * 
     * @param player 玩家对象
     * @param plugin 插件对象
     * @param mapName 地图名称
     * @param mapId 地图ID
     * @param result 激活结果
     */
    public static void logPluginActivation(Character player, CheatPlugin plugin, String mapName, int mapId, String result) {
        CheatLogger.logPluginActivation(player, plugin, mapName, mapId, result);
    }
    
    /**
     * 记录插件停用事件
     * 
     * @param player 玩家对象
     * @param plugin 插件对象
     * @param reason 停用原因
     */
    public static void logPluginDeactivation(Character player, CheatPlugin plugin, String reason) {
        CheatLogger.logPluginDeactivation(player, plugin, reason);
    }
    
    /**
     * 记录插件使用事件
     * 
     * @param player 玩家对象
     * @param plugin 插件对象
     * @param action 使用动作
     * @param details 详细信息
     */
    public static void logPluginUsage(Character player, CheatPlugin plugin, String action, String details) {
        CheatLogger.logPluginUsage(player, plugin, action, details);
    }
    
    /**
     * 记录通用辅助系统事件
     * 
     * @param player 玩家对象
     * @param message 日志消息
     */
    public static void logCheatSystem(Character player, String message) {
        CheatLogger.logCheatSystem(player, message);
    }
}