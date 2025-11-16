package org.gms.cheat.core;

import lombok.Getter;
import lombok.Setter;
import org.gms.client.Character;
import org.gms.dao.entity.ExtendValueDO;
import org.gms.log.CheatLogger;
import org.gms.net.server.Server;
import org.gms.util.ExtendUtil;

/**
 * 辅助插件基类
 * 提供通用功能的默认实现
 */
@Getter
public abstract class BaseCheatPlugin implements CheatPlugin {
    protected Character player;
    
    @Getter
    @Setter
    protected boolean running = false;
    
    /**
     * 是否启用日志记录
     */
    @Setter
    protected boolean loggingEnabled = true;
    
    protected static long currentServerTime() {
        return Server.getInstance().getCurrentTime();
    }
    
    @Override
    public void initialize(Character player) {
        this.player = player;
        if (loggingEnabled && player != null) {
            CheatLogger.logCheatSystem(player, "初始化辅助插件: " + getName());
        }
    }
    
    @Override
    public void start() {
        if (!running) {
            running = true;
            if (loggingEnabled) {
                CheatLogger.logCheatSystem(player, "启动辅助插件: " + getName());
            }
            onStart();
        }
    }
    
    @Override
    public void stop() {
        if (running) {
            running = false;
            if (loggingEnabled) {
                CheatLogger.logCheatSystem(player, "停止辅助插件: " + getName());
            }
            onStop();
        }
    }
    
    /**
     * 从扩展表中获取账号或角色的扩展值
     * 
     * @param extendId 扩展ID（账号ID或角色ID）
     * @param extendType 扩展类型，11-账号，12-账号日清，13-账号周清；21-角色，22-角色日清，23-角色周清
     * @param extendName 扩展字段名称
     * @return 扩展值对象
     */
    protected ExtendValueDO getExtendValue(String extendId, String extendType, String extendName) {
        if (loggingEnabled) {
            CheatLogger.logCheatSystem(player, String.format("读取扩展值: ID=%s, Type=%s, Name=%s", extendId, extendType, extendName));
        }
        return ExtendUtil.getExtendValue(extendId, extendType, extendName);
    }
    
    /**
     * 保存或更新账号或角色的扩展值到数据库
     * 
     * @param extendId 扩展ID（账号ID或角色ID）
     * @param extendType 扩展类型，11-账号，12-账号日清，13-账号周清；21-角色，22-角色日清，23-角色周清
     * @param extendName 扩展字段名称
     * @param extendValue 扩展字段值
     */
    protected void saveOrUpdateExtendValue(String extendId, String extendType, String extendName, String extendValue) {
        if (loggingEnabled) {
            CheatLogger.logCheatSystem(player, String.format("保存扩展值: ID=%s, Type=%s, Name=%s, Value=%s", extendId, extendType, extendName, extendValue));
        }
        ExtendUtil.saveOrUpdateExtendValue(extendId, extendType, extendName, extendValue);
    }
    
    /**
     * 从扩展表中获取账号的扩展值
     * 
     * @param accountId 账号ID
     * @param extendType 扩展类型，11-账号，12-账号日清，13-账号周清
     * @param extendName 扩展字段名称
     * @return 扩展值对象
     */
    protected ExtendValueDO getAccountExtendValue(int accountId, String extendType, String extendName) {
        if (loggingEnabled) {
            CheatLogger.logCheatSystem(player, String.format("读取账号扩展值: AccountID=%d, Type=%s, Name=%s", accountId, extendType, extendName));
        }
        return getExtendValue(String.valueOf(accountId), extendType, extendName);
    }
    
    /**
     * 保存或更新账号的扩展值到数据库
     * 
     * @param accountId 账号ID
     * @param extendType 扩展类型，11-账号，12-账号日清，13-账号周清
     * @param extendName 扩展字段名称
     * @param extendValue 扩展字段值
     */
    protected void saveOrUpdateAccountExtendValue(int accountId, String extendType, String extendName, String extendValue) {
        if (loggingEnabled) {
            CheatLogger.logCheatSystem(player, String.format("保存账号扩展值: AccountID=%d, Type=%s, Name=%s, Value=%s", accountId, extendType, extendName, extendValue));
        }
        saveOrUpdateExtendValue(String.valueOf(accountId), extendType, extendName, extendValue);
    }
    
    /**
     * 从扩展表中获取角色的扩展值
     * 
     * @param characterId 角色ID
     * @param extendType 扩展类型，21-角色，22-角色日清，23-角色周清
     * @param extendName 扩展字段名称
     * @return 扩展值对象
     */
    protected ExtendValueDO getCharacterExtendValue(int characterId, String extendType, String extendName) {
        if (loggingEnabled) {
            CheatLogger.logCheatSystem(player, String.format("读取角色扩展值: CharacterID=%d, Type=%s, Name=%s", characterId, extendType, extendName));
        }
        return getExtendValue(String.valueOf(characterId), extendType, extendName);
    }
    
    /**
     * 保存或更新角色的扩展值到数据库
     * 
     * @param characterId 角色ID
     * @param extendType 扩展类型，21-角色，22-角色日清，23-角色周清
     * @param extendName 扩展字段名称
     * @param extendValue 扩展字段值
     */
    protected void saveOrUpdateCharacterExtendValue(int characterId, String extendType, String extendName, String extendValue) {
        if (loggingEnabled) {
            CheatLogger.logCheatSystem(player, String.format("保存角色扩展值: CharacterID=%d, Type=%s, Name=%s, Value=%s", characterId, extendType, extendName, extendValue));
        }
        saveOrUpdateExtendValue(String.valueOf(characterId), extendType, extendName, extendValue);
    }
    
    /**
     * 子类可以重写此方法以实现启动逻辑
     */
    protected void onStart() {
        // 默认实现为空
    }
    
    /**
     * 子类可以重写此方法以实现停止逻辑
     */
    protected void onStop() {
        // 默认实现为空
    }
    
    /**
     * 记录插件激活日志
     * 
     * @param mapName 地图名称
     * @param mapId 地图ID
     * @param result 激活结果
     */
    protected void logPluginActivation(String mapName, int mapId, String result) {
        if (loggingEnabled) {
            CheatLogger.logPluginActivation(player, this, mapName, mapId, result);
        }
    }
    
    /**
     * 记录插件停用日志
     * 
     * @param reason 停用原因
     */
    protected void logPluginDeactivation(String reason) {
        if (loggingEnabled) {
            CheatLogger.logPluginDeactivation(player, this, reason);
        }
    }
    
    /**
     * 记录插件使用日志
     * 
     * @param action 使用动作
     * @param details 详细信息
     */
    protected void logPluginUsage(String action, String details) {
        if (loggingEnabled) {
            CheatLogger.logPluginUsage(player, this, action, details);
        }
    }
}