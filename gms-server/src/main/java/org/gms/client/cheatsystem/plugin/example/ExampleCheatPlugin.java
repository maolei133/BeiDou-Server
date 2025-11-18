package org.gms.client.cheatsystem.plugin.example;

import org.gms.client.cheatsystem.core.BaseCheatPlugin;
import org.gms.client.Character;
import org.gms.config.GameConfig;

/**
 * 示例内置辅助插件
 * 演示如何在内置辅助插件中使用日志系统
 */
public class ExampleCheatPlugin extends BaseCheatPlugin {
    private static final String PLUGIN_NAME = "示例辅助插件";
    private int usageCount = 0;
    
    public ExampleCheatPlugin() {
        super();
        // 可以选择是否启用日志记录
        setLoggingEnabled(GameConfig.getServerBoolean("cheat_example_logging_enabled", true));
    }
    
    @Override
    public String getName() {
        return PLUGIN_NAME;
    }
    
    @Override
    public String getDescription() {
        return "示例辅助功能";
    }
    
    @Override
    public void initialize(Character player) {
        super.initialize(player);
        logPluginActivation("内置辅助插件初始化完成");
    }
    
    @Override
    public void updateConfig() {
        // 实现配置更新逻辑
        if (loggingEnabled) {
            logPluginUsage("更新插件配置参数");
        }
    }
    
    /**
     * 示例内置辅助功能：执行某个操作
     */
    public void performAction(String actionDetails) {
        usageCount++;
        if (loggingEnabled) {
            logPluginUsage("执行了操作: " + actionDetails + "，累计使用次数: " + usageCount);
            
            // 当使用次数超过阈值时，记录特殊事件
            if (usageCount >= GameConfig.getServerInt("example_action_threshold", 10)) {
                logPluginUsage("插件使用次数达到阈值: " + usageCount);
            }
        }
    }
    
    /**
     * 重置内置辅助使用计数
     */
    public void resetUsageCount() {
        usageCount = 0;
        if (loggingEnabled) {
            logPluginUsage("使用计数已重置为0");
        }
    }
    
    /**
     * 获取当前使用计数
     * 
     * @return 使用计数
     */
    public int getUsageCount() {
        return usageCount;
    }
}