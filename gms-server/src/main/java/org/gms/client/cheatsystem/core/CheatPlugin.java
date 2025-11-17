package org.gms.client.cheatsystem.core;

import org.gms.client.Character;

/**
 * 作弊插件接口
 * 所有作弊功能都需要实现此接口
 */
public interface CheatPlugin {
    /**
     * 获取插件名称
     * @return 插件名称
     */
    String getName();
    
    /**
     * 获取插件描述
     * @return 插件描述
     */
    String getDescription();
    
    /**
     * 初始化插件
     * @param player 玩家对象
     */
    void initialize(Character player);
    
    /**
     * 启动插件
     */
    void start();
    
    /**
     * 停止插件
     */
    void stop();
    
    /**
     * 检查插件是否正在运行
     * @return 是否正在运行
     */
    boolean isRunning();
    
    /**
     * 更新插件配置
     */
    void updateConfig();
}