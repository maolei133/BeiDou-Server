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
}