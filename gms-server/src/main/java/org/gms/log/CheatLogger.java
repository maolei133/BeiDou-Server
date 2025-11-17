package org.gms.log;

import org.gms.client.Character;
import org.gms.client.cheatsystem.core.CheatPlugin;

/**
 * 辅助系统日志记录器
 * 专门用于记录辅助插件相关的日志信息
 */
public class CheatLogger {
    
    /**
     * 记录插件激活日志
     * 
     * @param player 玩家对象
     * @param plugin 插件对象
     * @param mapName 地图名称
     * @param mapId 地图ID
     * @param result 激活结果
     */
    public static void logPluginActivation(Character player, CheatPlugin plugin, String mapName, int mapId, String result) {
        String message;
        if (player != null) {
            message = String.format(
                "玩家 %s (ID: %d) 在地图 %s (ID: %d) 开启了插件 %s，结果: %s",
                player.getName(), 
                player.getId(), 
                mapName,
                mapId,
                plugin.getName(),
                result
            );
        } else {
            message = String.format(
                "在地图 %s (ID: %d) 开启了插件 %s，结果: %s",
                mapName,
                mapId,
                plugin.getName(),
                result
            );
        }
        
        LogManager.log(LogCategories.Major.CHEAT, LogCategories.Minor.PLUGIN_ACTIVATION, message);
    }
    
    /**
     * 记录插件停用日志
     * 
     * @param player 玩家对象
     * @param plugin 插件对象
     * @param reason 停用原因
     */
    public static void logPluginDeactivation(Character player, CheatPlugin plugin, String reason) {
        String message;
        if (player != null) {
            message = String.format(
                "玩家 %s (ID: %d) 结束了插件 %s，原因: %s",
                player.getName(),
                player.getId(),
                plugin.getName(),
                reason
            );
        } else {
            message = String.format(
                "结束了插件 %s，原因: %s",
                plugin.getName(),
                reason
            );
        }
        
        LogManager.log(LogCategories.Major.CHEAT, LogCategories.Minor.PLUGIN_DEACTIVATION, message);
    }
    
    /**
     * 记录插件使用日志
     * 
     * @param player 玩家对象
     * @param plugin 插件对象
     * @param action 使用动作
     * @param details 详细信息
     */
    public static void logPluginUsage(Character player, CheatPlugin plugin, String action, String details) {
        String message;
        if (player != null) {
            message = String.format(
                "玩家 %s (ID: %d) 使用插件 %s 执行操作: %s，详情: %s",
                player.getName(),
                player.getId(),
                plugin.getName(),
                action,
                details
            );
        } else {
            message = String.format(
                "使用插件 %s 执行操作: %s，详情: %s",
                plugin.getName(),
                action,
                details
            );
        }
        
        LogManager.log(LogCategories.Major.CHEAT, LogCategories.Minor.PLUGIN_USAGE, message);
    }
    
    /**
     * 记录通用辅助系统日志
     * 
     * @param player 玩家对象
     * @param message 日志消息
     */
    public static void logCheatSystem(Character player, String message) {
        String fullMessage;
        if (player != null && player.getName() != null) {
            fullMessage = String.format(
                "玩家 %s (ID: %d): %s",
                player.getName(),
                player.getId(),
                message
            );
        } else {
            fullMessage = "玩家 null (ID: 0): " + message;
        }
        
        LogManager.log(LogCategories.Major.CHEAT, LogCategories.Minor.PLUGIN_USAGE, fullMessage);
    }
}