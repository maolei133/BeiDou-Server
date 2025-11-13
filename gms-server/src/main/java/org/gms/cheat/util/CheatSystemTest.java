package org.gms.cheat.util;

import org.gms.cheat.core.CheatManager;
import org.gms.cheat.core.CheatPlugin;
import org.gms.cheat.core.CheatPluginFactory;
import org.gms.cheat.manager.CheatModuleManager;
import org.gms.cheat.plugin.ItemVacPlugin;
import org.gms.client.Character;

/**
 * 作弊系统测试工具类
 * 用于测试和验证作弊系统框架的功能
 */
public class CheatSystemTest {
    
    /**
     * 测试作弊系统框架的基本功能
     * @param player 测试玩家对象
     */
    public static void testCheatSystem(Character player) {
        System.out.println("=== 作弊系统框架测试 ===");
        
        // 测试作弊管理器创建
        CheatManager cheatManager = CheatModuleManager.getInstance().getCheatManager(player.getId());
        if (cheatManager != null) {
            System.out.println("✓ CheatManager 创建成功");
        } else {
            System.out.println("✗ CheatManager 创建失败");
            return;
        }
        
        // 测试插件注册
        String[] registeredPlugins = CheatPluginFactory.getRegisteredPlugins();
        System.out.println("✓ 已注册插件数量: " + registeredPlugins.length);
        for (String pluginName : registeredPlugins) {
            System.out.println("  - " + pluginName);
        }
        
        // 测试获取特定插件
        ItemVacPlugin itemVacPlugin = cheatManager.getPlugin("ItemVac");
        if (itemVacPlugin != null) {
            System.out.println("✓ ItemVacPlugin 获取成功");
            System.out.println("  插件名称: " + itemVacPlugin.getName());
            System.out.println("  插件描述: " + itemVacPlugin.getDescription());
        } else {
            System.out.println("✗ ItemVacPlugin 获取失败");
        }
        
        // 测试插件生命周期
        if (itemVacPlugin != null) {
            itemVacPlugin.start();
            if (itemVacPlugin.isRunning()) {
                System.out.println("✓ ItemVacPlugin 启动成功");
            } else {
                System.out.println("✗ ItemVacPlugin 启动失败");
            }
            
            itemVacPlugin.stop();
            if (!itemVacPlugin.isRunning()) {
                System.out.println("✓ ItemVacPlugin 停止成功");
            } else {
                System.out.println("✗ ItemVacPlugin 停止失败");
            }
        }
        
        System.out.println("=== 测试完成 ===");
    }
    
    /**
     * 显示所有插件状态
     * @param player 玩家对象
     */
    public static void displayPluginStatus(Character player) {
        CheatManager cheatManager = CheatModuleManager.getInstance().getCheatManager(player.getId());
        if (cheatManager == null) {
            System.out.println("未找到玩家的作弊管理器");
            return;
        }
        
        System.out.println("=== 插件状态 ===");
        for (CheatPlugin plugin : cheatManager.getAllPlugins()) {
            System.out.println("插件: " + plugin.getName() + 
                             " | 状态: " + (plugin.isRunning() ? "运行中" : "已停止"));
        }
    }
}