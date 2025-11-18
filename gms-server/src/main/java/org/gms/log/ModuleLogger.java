package org.gms.log;

import org.gms.client.Client;
import org.gms.client.Character;

import java.util.HashMap;
import java.util.Map;

/**
 * 模块化日志记录器
 * 支持不同功能模块的日志记录
 */
public class ModuleLogger {
    private final String majorCategory;
    private final String minorCategory;
    
    public ModuleLogger(String majorCategory, String minorCategory) {
        this.majorCategory = majorCategory;
        this.minorCategory = minorCategory;
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
            // 使用majorCategory和minorCategory作为模块名创建logger实例
            BaseLogger logger = new BaseLogger(majorCategory, minorCategory);
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
            // 忽略日志记录错误，但应该使用统一的日志系统而不是printStackTrace
            System.err.println("日志记录错误: " + e.getMessage());
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
}