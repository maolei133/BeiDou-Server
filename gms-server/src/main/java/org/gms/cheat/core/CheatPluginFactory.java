package org.gms.cheat.core;

import org.gms.cheat.plugin.ItemVacPlugin;
import org.gms.cheat.plugin.MobVacPlugin;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * 作弊插件工厂类
 * 负责创建和管理各种作弊插件的实例
 */
public class CheatPluginFactory {
    private static final Map<String, Supplier<CheatPlugin>> pluginRegistry = new HashMap<>();

    static {
        // 注册所有插件
        registerPlugin("ItemVac", ItemVacPlugin::new);
        registerPlugin("MobVac", MobVacPlugin::new);
    }
    
    /**
     * 注册插件
     * @param name 插件名称
     * @param supplier 插件实例提供者
     */
    public static void registerPlugin(String name, Supplier<CheatPlugin> supplier) {
        pluginRegistry.put(name, supplier);
    }
    
    /**
     * 创建插件实例
     * @param name 插件名称
     * @return 插件实例
     */
    public static CheatPlugin createPlugin(String name) {
        Supplier<CheatPlugin> supplier = pluginRegistry.get(name);
        if (supplier != null) {
            return supplier.get();
        }
        throw new IllegalArgumentException("Unknown plugin: " + name);
    }
    
    /**
     * 获取所有已注册的插件名称
     * @return 插件名称数组
     */
    public static String[] getRegisteredPlugins() {
        return pluginRegistry.keySet().toArray(new String[0]);
    }
}