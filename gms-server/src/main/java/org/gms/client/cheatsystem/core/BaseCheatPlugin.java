package org.gms.client.cheatsystem.core;

import lombok.Getter;
import lombok.Setter;
import org.gms.client.Character;
import org.gms.dao.entity.ExtendValueDO;
import org.gms.log.CheatSystemLogger;
import org.gms.util.ExtendUtil;

import java.util.Map;

/**
 * 内置辅助插件基类
 * 提供通用功能的默认实现
 */
@Getter
public abstract class BaseCheatPlugin implements CheatPlugin {
    protected Character player;
    
    @Getter
    @Setter
    protected boolean running = false;
    
    /**
     * 记录启动时的频道，用于检测频道切换
     */
    protected int channel = -1;
    
    /**
     * 是否启用日志记录
     */
    @Setter
    protected boolean loggingEnabled = true;
    
    /**
     * 启动参数
     */
    protected Map<String, Object> startParameters;
    
    protected static long currentServerTime() {
        return System.currentTimeMillis();
    }
    
    @Override
    public void initialize(Character player) {
        this.player = player;
        if (loggingEnabled && player != null) {
            CheatSystemLogger.logCheatSystem(player, "初始化辅助插件: " + getName());
        }
    }
    
    @Override
    public void start() {
        if (!running) {
            running = true;
            // 记录当前频道，用于后续判断是否切换频道
            if (player != null && player.getClient() != null) {
                channel = player.getClient().getChannel();
            }
            if (loggingEnabled) {
                CheatSystemLogger.logCheatSystem(player, "启动辅助插件: " + getName());
            }
            onStart();
        }
    }
    
    @Override
    public void start(Map<String, Object> parameters) {
        this.startParameters = parameters;
        start();
    }
    
    @Override
    public void stop() {
        if (running) {
            running = false;
            if (loggingEnabled) {
                CheatSystemLogger.logCheatSystem(player, "停止辅助插件: " + getName());
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
            CheatSystemLogger.logCheatSystem(player, String.format("读取扩展值: ID=%s, Type=%s, Name=%s", extendId, extendType, extendName));
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
            CheatSystemLogger.logCheatSystem(player, String.format("保存扩展值: ID=%s, Type=%s, Name=%s, Value=%s", extendId, extendType, extendName, extendValue));
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
            CheatSystemLogger.logCheatSystem(player, String.format("读取账号扩展值: AccountID=%d, Type=%s, Name=%s", accountId, extendType, extendName));
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
            CheatSystemLogger.logCheatSystem(player, String.format("保存账号扩展值: AccountID=%d, Type=%s, Name=%s, Value=%s", accountId, extendType, extendName, extendValue));
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
            CheatSystemLogger.logCheatSystem(player, String.format("读取角色扩展值: CharacterID=%d, Type=%s, Name=%s", characterId, extendType, extendName));
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
            CheatSystemLogger.logCheatSystem(player, String.format("保存角色扩展值: CharacterID=%d, Type=%s, Name=%s, Value=%s", characterId, extendType, extendName, extendValue));
        }
        saveOrUpdateExtendValue(String.valueOf(characterId), extendType, extendName, extendValue);
    }
    
    /**
     * 子类可以重写此方法以实现启动逻辑
     */
    protected void onStart() {
        // 默认实现为空
        if (loggingEnabled && player != null) {
            logCheatSystem(player, "插件 " + getName() + " 启动完成");
        }
    }
    
    /**
     * 子类可以重写此方法以实现停止逻辑
     */
    protected void onStop() {
        // 默认实现为空
        if (loggingEnabled && player != null) {
            logCheatSystem(player, "插件 " + getName() + " 停止完成");
        }
    }
    
    /**
     * 记录插件激活日志
     * 
     * @param result 激活结果
     */
    protected void logPluginActivation(String result) {
        if (loggingEnabled) {
            CheatSystemLogger.logPluginActivation(player, getName(), result);
        }
    }
    
    /**
     * 记录插件停用日志
     * 
     * @param reason 停用原因
     */
    protected void logPluginDeactivation(String reason) {
        if (loggingEnabled) {
            CheatSystemLogger.logPluginDeactivation(player, getName(), reason);
        }
    }
    
    /**
     * 记录插件使用日志
     * 
     * @param details 详细信息
     */
    protected void logPluginUsage(String details) {
        if (loggingEnabled) {
            CheatSystemLogger.logPluginUsage(player, getName(), details);
        }
    }
    
    /**
     * 记录通用辅助系统日志
     * 
     * @param player 玩家对象
     * @param message 日志消息
     */
    protected void logCheatSystem(Character player, String message) {
        if (loggingEnabled) {
            CheatSystemLogger.logCheatSystem(player, message);
        }
    }
    
    /**
     * 获取启动参数
     * 
     * @return 启动参数映射
     */
    protected Map<String, Object> getStartParameters() {
        return startParameters;
    }
    
    /**
     * 获取指定的启动参数
     * 
     * @param key 参数键
     * @param defaultValue 默认值
     * @return 参数值
     */
    protected Object getStartParameter(String key, Object defaultValue) {
        if (startParameters != null && startParameters.containsKey(key)) {
            return startParameters.get(key);
        }
        return defaultValue;
    }
    
    /**
     * 获取指定的启动参数（字符串类型）
     * 
     * @param key 参数键
     * @param defaultValue 默认值
     * @return 参数值
     */
    protected String getStartParameterAsString(String key, String defaultValue) {
        Object value = getStartParameter(key, defaultValue);
        return value != null ? value.toString() : defaultValue;
    }
    
    /**
     * 获取指定的启动参数（整数类型）
     * 
     * @param key 参数键
     * @param defaultValue 默认值
     * @return 参数值
     */
    protected int getStartParameterAsInt(String key, int defaultValue) {
        Object value = getStartParameter(key, defaultValue);
        if (value instanceof Number) {
            return ((Number) value).intValue();
        } else if (value instanceof String) {
            try {
                return Integer.parseInt((String) value);
            } catch (NumberFormatException e) {
                return defaultValue;
            }
        }
        return defaultValue;
    }
    
    /**
     * 获取指定的启动参数（布尔类型）
     * 
     * @param key 参数键
     * @param defaultValue 默认值
     * @return 参数值
     */
    protected boolean getStartParameterAsBoolean(String key, boolean defaultValue) {
        Object value = getStartParameter(key, defaultValue);
        if (value instanceof Boolean) {
            return (Boolean) value;
        } else if (value instanceof String) {
            return Boolean.parseBoolean((String) value);
        }
        return defaultValue;
    }
}