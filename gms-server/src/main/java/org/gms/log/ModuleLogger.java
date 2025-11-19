package org.gms.log;

import org.gms.client.Client;
import org.gms.client.Character;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 模块化日志记录器
 * 支持不同功能模块的日志记录
 */
public class ModuleLogger {
    // Logger实例缓存，避免重复创建
    private static final Map<String, BaseLogger> loggerCache = new ConcurrentHashMap<>();
    
    private final String majorCategory;
    private final String minorCategory;
    
    // 日志级别常量
    public static final String LEVEL_DEBUG = "DEBUG";
    public static final String LEVEL_INFO = "INFO";
    public static final String LEVEL_WARN = "WARN";
    public static final String LEVEL_ERROR = "ERROR";
    
    public ModuleLogger(String majorCategory, String minorCategory) {
        this.majorCategory = majorCategory;
        this.minorCategory = minorCategory;
    }
    
    /**
     * 获取或创建BaseLogger实例（带缓存）
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return BaseLogger实例
     */
    private static BaseLogger getOrCreateLogger(String majorCategory, String minorCategory) {
        String key = majorCategory + "/" + minorCategory;
        return loggerCache.computeIfAbsent(key, k -> {
            try {
                return new BaseLogger(majorCategory, minorCategory);
            } catch (Exception e) {
                throw new RuntimeException("无法创建BaseLogger实例: " + e.getMessage(), e);
            }
        });
    }
    
    /**
     * 记录模块日志
     * 
     * @param client 客户端对象
     * @param chr 角色对象
     * @param moduleData 模块特定数据
     */
    public void log(Client client, Character chr, Map<String, Object> moduleData) {
        try {
            // 使用缓存的BaseLogger实例
            BaseLogger logger = getOrCreateLogger(majorCategory, minorCategory);
            BaseLogEntry entry = new BaseLogEntry();
            logger.populateBaseInfo(entry, client, chr);
            
            // 设置模块信息
            entry.setMod(majorCategory + "." + minorCategory);
            
            // 添加模块特定数据到日志条目
            if (moduleData != null) {
                for (Map.Entry<String, Object> e : moduleData.entrySet()) {
                    entry.addCustomField(e.getKey(), e.getValue());
                }
            }
            
            logger.log(entry);
        } catch (Exception e) {
            // 使用统一的日志系统记录错误信息，而不是printStackTrace
            ErrorLogger.logException(client, chr, e, "记录日志时发生异常");
        }
    }
    
    /**
     * 记录带级别的模块日志
     * 
     * @param client 客户端对象
     * @param chr 角色对象
     * @param level 日志级别
     * @param moduleData 模块特定数据
     */
    public void logWithLevel(Client client, Character chr, String level, Map<String, Object> moduleData) {
        try {
            BaseLogger logger = getOrCreateLogger(majorCategory, minorCategory);
            BaseLogEntry entry = new BaseLogEntry();
            logger.populateBaseInfo(entry, client, chr);
            
            // 设置日志级别
            entry.setLvl(level);
            
            // 设置模块信息
            entry.setMod(majorCategory + "." + minorCategory);
            
            // 添加模块特定数据到日志条目
            if (moduleData != null) {
                for (Map.Entry<String, Object> e : moduleData.entrySet()) {
                    entry.addCustomField(e.getKey(), e.getValue());
                }
            }
            
            logger.log(entry);
        } catch (Exception e) {
            ErrorLogger.logException(client, chr, e, "记录带级别日志时发生异常");
        }
    }
    
    /**
     * 记录模块日志（便捷方法）
     * 
     * @param client 客户端对象
     * @param chr 角色对象
     */
    public void log(Client client, Character chr) {
        log(client, chr, null);
    }
    
    /**
     * 记录带级别的模块日志（便捷方法）
     * 
     * @param client 客户端对象
     * @param chr 角色对象
     * @param level 日志级别
     */
    public void logWithLevel(Client client, Character chr, String level) {
        logWithLevel(client, chr, level, null);
    }
    
    /**
     * 记录模块日志（带动态字段）
     * 
     * @param client 客户端对象
     * @param chr 角色对象
     * @param key 字段名
     * @param value 字段值
     */
    public void log(Client client, Character chr, String key, Object value) {
        Map<String, Object> moduleData = new HashMap<>();
        moduleData.put(key, value);
        log(client, chr, moduleData);
    }
    
    /**
     * 记录带级别的模块日志（带动态字段）
     * 
     * @param client 客户端对象
     * @param chr 角色对象
     * @param level 日志级别
     * @param key 字段名
     * @param value 字段值
     */
    public void logWithLevel(Client client, Character chr, String level, String key, Object value) {
        Map<String, Object> moduleData = new HashMap<>();
        moduleData.put(key, value);
        logWithLevel(client, chr, level, moduleData);
    }
    
    /**
     * 记录模块日志（带多个动态字段）
     * 
     * @param client 客户端对象
     * @param chr 角色对象
     * @param keys 字段名数组
     * @param values 字段值数组
     */
    public void log(Client client, Character chr, String[] keys, Object[] values) {
        if (keys == null || values == null || keys.length != values.length) {
            log(client, chr);
            return;
        }
        
        Map<String, Object> moduleData = new HashMap<>();
        for (int i = 0; i < keys.length; i++) {
            moduleData.put(keys[i], values[i]);
        }
        log(client, chr, moduleData);
    }
    
    /**
     * 记录带级别的模块日志（带多个动态字段）
     * 
     * @param client 客户端对象
     * @param chr 角色对象
     * @param level 日志级别
     * @param keys 字段名数组
     * @param values 字段值数组
     */
    public void logWithLevel(Client client, Character chr, String level, String[] keys, Object[] values) {
        if (keys == null || values == null || keys.length != values.length) {
            logWithLevel(client, chr, level);
            return;
        }
        
        Map<String, Object> moduleData = new HashMap<>();
        for (int i = 0; i < keys.length; i++) {
            moduleData.put(keys[i], values[i]);
        }
        logWithLevel(client, chr, level, moduleData);
    }
    
    // 便捷方法：玩家登录日志
    public static void logPlayerLogin(Client client, Character chr) {
        new ModuleLogger(LogCategoryDefinition.Major.PLAYER, LogCategoryDefinition.Minor.LOGIN)
                .log(client, chr);
    }
    
    // 便捷方法：玩家登出日志
    public static void logPlayerLogout(Client client, Character chr) {
        new ModuleLogger(LogCategoryDefinition.Major.PLAYER, LogCategoryDefinition.Minor.LOGOUT)
                .log(client, chr);
    }
    
    // 便捷方法：物品获得日志
    public static void logItemObtain(Client client, Character chr, String itemName, int quantity, String source) {
        Map<String, Object> moduleData = new HashMap<>();
        moduleData.put("itemName", itemName);
        moduleData.put("quantity", quantity);
        moduleData.put("source", source);
        new ModuleLogger(LogCategoryDefinition.Major.ITEM, LogCategoryDefinition.Minor.OBTAIN)
                .log(client, chr, moduleData);
    }
    
    // 便捷方法：交易日志
    public static void logTrade(Client client, Character chr, String targetPlayer, String item, int quantity, long meso) {
        Map<String, Object> moduleData = new HashMap<>();
        moduleData.put("targetPlayer", targetPlayer);
        moduleData.put("item", item);
        moduleData.put("quantity", quantity);
        moduleData.put("meso", meso);
        new ModuleLogger(LogCategoryDefinition.Major.ECONOMY, LogCategoryDefinition.Minor.TRADE)
                .log(client, chr, moduleData);
    }
    
    // 便捷方法：技能使用日志
    public static void logSkillUse(Client client, Character chr, String skillName, int skillId, int level) {
        Map<String, Object> moduleData = new HashMap<>();
        moduleData.put("skillName", skillName);
        moduleData.put("skillId", skillId);
        moduleData.put("level", level);
        new ModuleLogger(LogCategoryDefinition.Major.BATTLE, LogCategoryDefinition.Minor.SKILL_USE)
                .log(client, chr, moduleData);
    }
    
    // 便捷方法：怪物击杀日志
    public static void logMonsterKill(Client client, Character chr, String monsterName, int monsterId, int mapId) {
        Map<String, Object> moduleData = new HashMap<>();
        moduleData.put("monsterName", monsterName);
        moduleData.put("monsterId", monsterId);
        moduleData.put("mapId", mapId);
        new ModuleLogger(LogCategoryDefinition.Major.BATTLE, LogCategoryDefinition.Minor.MONSTER_KILL)
                .log(client, chr, moduleData);
    }
    
    // 便捷方法：GM命令日志
    public static void logGMCommand(Client client, Character chr, String command, String[] args) {
        Map<String, Object> moduleData = new HashMap<>();
        moduleData.put("command", command);
        moduleData.put("args", String.join(",", args));
        new ModuleLogger(LogCategoryDefinition.Major.GM_COMMAND, LogCategoryDefinition.Minor.COMMAND_EXECUTION)
                .log(client, chr, moduleData);
    }
    
    // 便捷方法：聊天日志
    public static void logChat(Client client, Character chr, String chatType, String message, int mapId) {
        Map<String, Object> moduleData = new HashMap<>();
        moduleData.put("chatType", chatType);
        moduleData.put("message", message);
        moduleData.put("mapId", mapId);
        new ModuleLogger(LogCategoryDefinition.Major.CHAT, LogCategoryDefinition.Minor.GENERAL_CHAT)
                .log(client, chr, moduleData);
    }
    
    // 便捷方法：带级别的日志记录
    public static void logWithLevel(Client client, Character chr, String major, String minor, String level, String message) {
        Map<String, Object> moduleData = new HashMap<>();
        moduleData.put("message", message);
        new ModuleLogger(major, minor).logWithLevel(client, chr, level, moduleData);
    }
    
    // 便捷方法：DEBUG级别日志
    public static void debug(Client client, Character chr, String major, String minor, String message) {
        logWithLevel(client, chr, major, minor, LEVEL_DEBUG, message);
    }
    
    // 便捷方法：INFO级别日志
    public static void info(Client client, Character chr, String major, String minor, String message) {
        logWithLevel(client, chr, major, minor, LEVEL_INFO, message);
    }
    
    // 便捷方法：WARN级别日志
    public static void warn(Client client, Character chr, String major, String minor, String message) {
        logWithLevel(client, chr, major, minor, LEVEL_WARN, message);
    }
    
    // 便捷方法：ERROR级别日志
    public static void error(Client client, Character chr, String major, String minor, String message) {
        logWithLevel(client, chr, major, minor, LEVEL_ERROR, message);
    }
}