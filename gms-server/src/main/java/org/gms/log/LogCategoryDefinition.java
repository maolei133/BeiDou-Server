package org.gms.log;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

/**
 * 日志分类定义类
 * 用于统一定义和管理日志的大类和小类
 */
public class LogCategoryDefinition {
    
    // 存储大类定义
    private static final Map<String, String> MAJOR_CATEGORIES = new HashMap<>();
    
    // 存储小类定义，key为大类，value为该大类下的小类集合
    private static final Map<String, Set<String>> MINOR_CATEGORIES = new HashMap<>();
    
    // 初始化默认分类
    static {
        // 玩家相关
        addMajorCategory(Major.PLAYER, "玩家相关");
        addMinorCategory(Major.PLAYER, Minor.LOGIN, "登录");
        addMinorCategory(Major.PLAYER, Minor.LOGOUT, "登出");
        addMinorCategory(Major.PLAYER, Minor.LEVEL_UP, "升级");
        addMinorCategory(Major.PLAYER, Minor.JOB_CHANGE, "转职");

        // 游戏物品相关
        addMajorCategory(Major.ITEM, "物品相关");
        addMinorCategory(Major.ITEM, Minor.OBTAIN, "获得");
        addMinorCategory(Major.ITEM, Minor.CONSUME, "消耗");
        addMinorCategory(Major.ITEM, Minor.DROP, "丢弃");
        addMinorCategory(Major.ITEM, Minor.PICKUP, "拾取");

        // 游戏经济相关
        addMajorCategory(Major.ECONOMY, "经济相关");
        addMinorCategory(Major.ECONOMY, Minor.TRADE, "交易");
        addMinorCategory(Major.ECONOMY, Minor.AUCTION, "拍卖");
        addMinorCategory(Major.ECONOMY, Minor.MESO_TRANSACTION, "金币交易");

        // 系统相关
        addMajorCategory(Major.SYSTEM, "系统相关");
        addMinorCategory(Major.SYSTEM, Minor.STARTUP, "启动");
        addMinorCategory(Major.SYSTEM, Minor.SHUTDOWN, "关闭");
        addMinorCategory(Major.SYSTEM, Minor.CONFIG_CHANGE, "配置变更");

        // 聊天相关
        addMajorCategory(Major.CHAT, "聊天相关");
        addMinorCategory(Major.CHAT, Minor.GENERAL_CHAT, "一般聊天");
        addMinorCategory(Major.CHAT, Minor.WHISPER, "私聊");
        addMinorCategory(Major.CHAT, Minor.PARTY_CHAT, "组队聊天");
        addMinorCategory(Major.CHAT, Minor.GUILD_CHAT, "公会聊天");

        // 战斗相关
        addMajorCategory(Major.BATTLE, "战斗相关");
        addMinorCategory(Major.BATTLE, Minor.DAMAGE, "伤害");
        addMinorCategory(Major.BATTLE, Minor.SKILL_USE, "技能使用");
        addMinorCategory(Major.BATTLE, Minor.MONSTER_KILL, "击杀怪物");

        // 任务相关
        addMajorCategory(Major.QUEST, "任务相关");
        addMinorCategory(Major.QUEST, Minor.ACCEPT, "接受");
        addMinorCategory(Major.QUEST, Minor.COMPLETE, "完成");
        addMinorCategory(Major.QUEST, Minor.FORFEIT, "放弃");

        // 商城相关
        addMajorCategory(Major.SHOP, "商城相关");
        addMinorCategory(Major.SHOP, Minor.BUY, "购买");
        addMinorCategory(Major.SHOP, Minor.SELL, "出售");
        addMinorCategory(Major.SHOP, Minor.RECHARGE, "充值");

        // 社交相关
        addMajorCategory(Major.SOCIAL, "社交相关");
        addMinorCategory(Major.SOCIAL, Minor.FRIEND, "好友");
        addMinorCategory(Major.SOCIAL, Minor.GUILD, "公会");
        addMinorCategory(Major.SOCIAL, Minor.PARTY, "组队");

        // GM命令相关
        addMajorCategory(Major.GM_COMMAND, "GM命令");
        addMinorCategory(Major.GM_COMMAND, Minor.COMMAND_EXECUTION, "命令执行");
        addMinorCategory(Major.GM_COMMAND, Minor.PLAYER_PUNISHMENT, "玩家惩罚");

        // 错误相关
        addMajorCategory(Major.ERROR, "错误相关");
        addMinorCategory(Major.ERROR, Minor.EXCEPTION, "异常");
        addMinorCategory(Major.ERROR, Minor.WARNING, "警告");

        // 安全相关
        addMajorCategory(Major.SECURITY, "安全相关");
        addMinorCategory(Major.SECURITY, Minor.HACK_DETECTION, "外挂检测");
        addMinorCategory(Major.SECURITY, Minor.ACCOUNT_SECURITY, "账号安全");

        // 辅助系统相关
        addMajorCategory(Major.CHEAT, "辅助系统");
        addMinorCategory(Major.CHEAT, Minor.PLUGIN_ACTIVATION, "插件激活");
        addMinorCategory(Major.CHEAT, Minor.PLUGIN_OPERATION, "插件操作");
        addMinorCategory(Major.CHEAT, Minor.PLUGIN_SYSTEM, "插件系统");
    }

    /**
     * 添加大类定义
     * 
     * @param code 大类代码
     * @param description 大类描述
     */
    public static void addMajorCategory(String code, String description) {
        MAJOR_CATEGORIES.put(code, description);
    }

    /**
     * 添加小类定义
     * 
     * @param major 大类
     * @param code 小类代码
     * @param description 小类描述
     */
    public static void addMinorCategory(String major, String code, String description) {
        MINOR_CATEGORIES.computeIfAbsent(major, k -> new HashSet<>()).add(code);
    }

    /**
     * 获取所有大类
     * 
     * @return 大类映射
     */
    public static Map<String, String> getMajorCategories() {
        return Collections.unmodifiableMap(MAJOR_CATEGORIES);
    }

    /**
     * 获取指定大类下的所有小类
     * 
     * @param major 大类
     * @return 小类集合
     */
    public static Set<String> getMinorCategories(String major) {
        return MINOR_CATEGORIES.getOrDefault(major, Collections.emptySet());
    }

    /**
     * 检查大类是否存在
     * 
     * @param major 大类
     * @return 是否存在
     */
    public static boolean containsMajor(String major) {
        return MAJOR_CATEGORIES.containsKey(major);
    }

    /**
     * 检查小类是否存在
     * 
     * @param major 大类
     * @param minor 小类
     * @return 是否存在
     */
    public static boolean containsMinor(String major, String minor) {
        return MINOR_CATEGORIES.getOrDefault(major, Collections.emptySet()).contains(minor);
    }

    /**
     * 大类常量定义
     */
    public static class Major {
        /** 玩家相关 */
        public static final String PLAYER = "player";
        /** 游戏物品相关 */
        public static final String ITEM = "item";
        /** 游戏经济相关 */
        public static final String ECONOMY = "economy";
        /** 系统相关 */
        public static final String SYSTEM = "system";
        /** 聊天相关 */
        public static final String CHAT = "chat";
        /** 战斗相关 */
        public static final String BATTLE = "battle";
        /** 任务相关 */
        public static final String QUEST = "quest";
        /** 商城相关 */
        public static final String SHOP = "shop";
        /** 社交相关 */
        public static final String SOCIAL = "social";
        /** GM命令相关 */
        public static final String GM_COMMAND = "gm_command";
        /** 错误相关 */
        public static final String ERROR = "error";
        /** 安全相关 */
        public static final String SECURITY = "security";
        /** 辅助系统相关 */
        public static final String CHEAT = "cheat";
    }

    /**
     * 小类常量定义
     */
    public static class Minor {
        // PLAYER大类下的小类
        public static final String LOGIN = "login";
        public static final String LOGOUT = "logout";
        public static final String LEVEL_UP = "level_up";
        public static final String JOB_CHANGE = "job_change";

        // ITEM大类下的小类
        public static final String OBTAIN = "obtain";
        public static final String CONSUME = "consume";
        public static final String DROP = "drop";
        public static final String PICKUP = "pickup";

        // ECONOMY大类下的小类
        public static final String TRADE = "trade";
        public static final String AUCTION = "auction";
        public static final String MESO_TRANSACTION = "meso_transaction";

        // SYSTEM大类下的小类
        public static final String STARTUP = "startup";
        public static final String SHUTDOWN = "shutdown";
        public static final String CONFIG_CHANGE = "config_change";

        // CHAT大类下的小类
        public static final String GENERAL_CHAT = "general";
        public static final String WHISPER = "whisper";
        public static final String PARTY_CHAT = "party";
        public static final String GUILD_CHAT = "guild";

        // BATTLE大类下的小类
        public static final String DAMAGE = "damage";
        public static final String SKILL_USE = "skill_use";
        public static final String MONSTER_KILL = "monster_kill";

        // QUEST大类下的小类
        public static final String ACCEPT = "accept";
        public static final String COMPLETE = "complete";
        public static final String FORFEIT = "forfeit";

        // SHOP大类下的小类
        public static final String BUY = "buy";
        public static final String SELL = "sell";
        public static final String RECHARGE = "recharge";

        // SOCIAL大类下的小类
        public static final String FRIEND = "friend";
        public static final String GUILD = "guild";
        public static final String PARTY = "party";

        // GM_COMMAND大类下的小类
        public static final String COMMAND_EXECUTION = "execution";
        public static final String PLAYER_PUNISHMENT = "punishment";

        // ERROR大类下的小类
        public static final String EXCEPTION = "exception";
        public static final String WARNING = "warning";

        // SECURITY大类下的小类
        public static final String HACK_DETECTION = "hack_detection";
        public static final String ACCOUNT_SECURITY = "account_security";
        
        // CHEAT大类下的小类
        public static final String PLUGIN_ACTIVATION = "plugin_activation";
        public static final String PLUGIN_OPERATION = "plugin_operation";
        public static final String PLUGIN_SYSTEM = "plugin_system";
    }
}