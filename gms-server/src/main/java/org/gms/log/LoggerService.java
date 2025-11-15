package org.gms.log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.HashMap;

/**
 * 统一日志记录接口
 * 提供便捷的方法供系统各部分调用
 */
public class LoggerService {
    private static final Logger log = LoggerFactory.getLogger(LoggerService.class);
    
    // 缓存常用的日志记录器实例
    private static final Map<String, GameLogger> loggerCache = new HashMap<>();
    
    /**
     * 获取特定大类和小类的日志记录器
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return GameLogger实例
     */
    public static GameLogger getLogger(String majorCategory, String minorCategory) {
        String key = majorCategory + ":" + minorCategory;
        return loggerCache.computeIfAbsent(key, k -> new GameLogger(majorCategory, minorCategory));
    }
    
    /**
     * 玩家登录日志
     */
    public static void logPlayerLogin(String playerName, String ipAddress) {
        getLogger(LogCategories.Major.PLAYER, LogCategories.Minor.LOGIN)
            .info("玩家 {} 从IP地址 {} 登录游戏", playerName, ipAddress);
    }
    
    /**
     * 玩家登出日志
     */
    public static void logPlayerLogout(String playerName, long playTime) {
        getLogger(LogCategories.Major.PLAYER, LogCategories.Minor.LOGOUT)
            .info("玩家 {} 登出游戏，本次游戏时长 {} 秒", playerName, playTime);
    }
    
    /**
     * 物品获得日志
     */
    public static void logItemObtain(String playerName, String itemName, int quantity, String source) {
        getLogger(LogCategories.Major.ITEM, LogCategories.Minor.OBTAIN)
            .info("玩家 {} 获得物品 {} 数量 {} 来自 {}", playerName, itemName, quantity, source);
    }
    
    /**
     * 聊天日志
     */
    public static void logChat(String playerName, String chatType, String message, String mapName) {
        getLogger(LogCategories.Major.CHAT, chatType)
            .info("[{}]({}) {}: {}", mapName, chatType, playerName, message);
    }
    
    /**
     * 交易日志
     */
    public static void logTrade(String player1, String player2, String item, int quantity, long meso) {
        getLogger(LogCategories.Major.ECONOMY, LogCategories.Minor.TRADE)
            .info("玩家 {} 和玩家 {} 进行交易: 物品 {} 数量 {}, 金币 {}", player1, player2, item, quantity, meso);
    }
    
    /**
     * GM命令日志
     */
    public static void logGMCommand(String gmName, String command, String target) {
        getLogger(LogCategories.Major.GM_COMMAND, LogCategories.Minor.COMMAND_EXECUTION)
            .info("GM {} 对目标 {} 执行命令: {}", gmName, target, command);
    }
    
    /**
     * 异常日志
     */
    public static void logError(String category, String message, Throwable throwable) {
        getLogger(LogCategories.Major.ERROR, category)
            .error(message, throwable);
    }
    
    /**
     * 安全日志
     */
    public static void logSecurity(String securityType, String playerName, String details) {
        getLogger(LogCategories.Major.SECURITY, securityType)
            .warn("安全警告: 玩家 {} 触发 {} 类型检测, 详情: {}", playerName, securityType, details);
    }
}