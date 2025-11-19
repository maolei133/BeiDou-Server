package org.gms.log;

import org.gms.client.Character;

import java.util.Map;

/**
 * 内置辅助系统专用日志记录器
 * 属于CHEAT大类的日志记录器
 */
public class CheatSystemLogger extends ModuleLogger {
    private static final CheatSystemLogger INSTANCE = new CheatSystemLogger();
    
    private CheatSystemLogger() {
        // 注意：这里的构造调用只是满足父类要求，实际使用时会通过具体方法指定正确的子类
        super(LogCategoryDefinition.Major.CHEAT, LogCategoryDefinition.Minor.PLUGIN_SYSTEM);
    }
    
    public static CheatSystemLogger getInstance() {
        return INSTANCE;
    }
    
    /**
     * 记录内置辅助系统日志
     * @param player 玩家对象
     * @param message 日志消息
     */
    public static void logCheatSystem(Character player, String message) {
        Map<String, Object> moduleData = Map.of("message", message);
        new ModuleLogger(LogCategoryDefinition.Major.CHEAT, LogCategoryDefinition.Minor.PLUGIN_SYSTEM)
                .log(player != null ? player.getClient() : null, player, moduleData);
    }
    
    /**
     * 记录带级别的内置辅助系统日志
     * @param player 玩家对象
     * @param level 日志级别
     * @param message 日志消息
     */
    public static void logCheatSystemWithLevel(Character player, String level, String message) {
        Map<String, Object> moduleData = Map.of("message", message);
        new ModuleLogger(LogCategoryDefinition.Major.CHEAT, LogCategoryDefinition.Minor.PLUGIN_SYSTEM)
                .logWithLevel(player != null ? player.getClient() : null, player, level, moduleData);
    }
    
    /**
     * 记录内置辅助插件激活日志
     * @param player 玩家对象
     * @param pluginName 插件名称
     * @param details 详细信息
     */
    public static void logPluginActivation(Character player, String pluginName, String details) {
        Map<String, Object> moduleData = Map.of(
            "pluginName", pluginName,
            "action", "activation",
            "details", details
        );
        new ModuleLogger(LogCategoryDefinition.Major.CHEAT, LogCategoryDefinition.Minor.PLUGIN_ACTIVATION)
                .log(player != null ? player.getClient() : null, player, moduleData);
    }
    
    /**
     * 记录带级别的内置辅助插件激活日志
     * @param player 玩家对象
     * @param level 日志级别
     * @param pluginName 插件名称
     * @param details 详细信息
     */
    public static void logPluginActivationWithLevel(Character player, String level, String pluginName, String details) {
        Map<String, Object> moduleData = Map.of(
            "pluginName", pluginName,
            "action", "activation",
            "details", details
        );
        new ModuleLogger(LogCategoryDefinition.Major.CHEAT, LogCategoryDefinition.Minor.PLUGIN_ACTIVATION)
                .logWithLevel(player != null ? player.getClient() : null, player, level, moduleData);
    }
    
    /**
     * 记录内置辅助插件停用日志
     * @param player 玩家对象
     * @param pluginName 插件名称
     * @param details 详细信息
     */
    public static void logPluginDeactivation(Character player, String pluginName, String details) {
        Map<String, Object> moduleData = Map.of(
            "pluginName", pluginName,
            "action", "deactivation",
            "details", details
        );
        new ModuleLogger(LogCategoryDefinition.Major.CHEAT, LogCategoryDefinition.Minor.PLUGIN_OPERATION)
                .log(player != null ? player.getClient() : null, player, moduleData);
    }
    
    /**
     * 记录带级别的内置辅助插件停用日志
     * @param player 玩家对象
     * @param level 日志级别
     * @param pluginName 插件名称
     * @param details 详细信息
     */
    public static void logPluginDeactivationWithLevel(Character player, String level, String pluginName, String details) {
        Map<String, Object> moduleData = Map.of(
            "pluginName", pluginName,
            "action", "deactivation",
            "details", details
        );
        new ModuleLogger(LogCategoryDefinition.Major.CHEAT, LogCategoryDefinition.Minor.PLUGIN_OPERATION)
                .logWithLevel(player != null ? player.getClient() : null, player, level, moduleData);
    }
    
    /**
     * 记录内置辅助插件使用日志
     * @param player 玩家对象
     * @param pluginName 插件名称
     * @param usageDetails 使用详情
     */
    public static void logPluginUsage(Character player, String pluginName, String usageDetails) {
        Map<String, Object> moduleData = Map.of(
            "pluginName", pluginName,
            "action", "usage",
            "usageDetails", usageDetails
        );
        new ModuleLogger(LogCategoryDefinition.Major.CHEAT, LogCategoryDefinition.Minor.PLUGIN_OPERATION)
                .log(player != null ? player.getClient() : null, player, moduleData);
    }
    
    /**
     * 记录带级别的内置辅助插件使用日志
     * @param player 玩家对象
     * @param level 日志级别
     * @param pluginName 插件名称
     * @param usageDetails 使用详情
     */
    public static void logPluginUsageWithLevel(Character player, String level, String pluginName, String usageDetails) {
        Map<String, Object> moduleData = Map.of(
            "pluginName", pluginName,
            "action", "usage",
            "usageDetails", usageDetails
        );
        new ModuleLogger(LogCategoryDefinition.Major.CHEAT, LogCategoryDefinition.Minor.PLUGIN_OPERATION)
                .logWithLevel(player != null ? player.getClient() : null, player, level, moduleData);
    }
    
    // 便捷方法：DEBUG级别日志
    public static void debug(Character player, String message) {
        logCheatSystemWithLevel(player, ModuleLogger.LEVEL_DEBUG, message);
    }
    
    // 便捷方法：INFO级别日志
    public static void info(Character player, String message) {
        logCheatSystemWithLevel(player, ModuleLogger.LEVEL_INFO, message);
    }
    
    // 便捷方法：WARN级别日志
    public static void warn(Character player, String message) {
        logCheatSystemWithLevel(player, ModuleLogger.LEVEL_WARN, message);
    }
    
    // 便捷方法：ERROR级别日志
    public static void error(Character player, String message) {
        logCheatSystemWithLevel(player, ModuleLogger.LEVEL_ERROR, message);
    }
}