package org.gms.log;

/**
 * 日志类别枚举类
 * 定义系统中常用的大类和小类
 */
public class LogCategories {
    // 大类定义
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
    }

    // 小类定义
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
    }
}