package org.gms.server.logging;

/**
 * 日志模块枚举
 * 用于规范化日志记录的模块名称，便于统计和国际化。
 */
public enum LogModule {
    /** 系统 */ SYSTEM,
    /** 登录/账号 */ LOGIN,
    /** 角色成长 */ CHARACTER,
    /** 物品/背包 */ ITEM,
    /** NPC商店 */ SHOP,
    /** 玩家交易 */ TRADE,
    /** 组队 */ PARTY,
    /** 公会 */ GUILD,
    /** 家族 */ FAMILY,
    /** 任务 */ QUEST,
    /** 地图/打怪 */ FIELD,
    /** 脚本/副本 */ SCRIPT,
    /** 商城 */ CASH_SHOP,
    /** 活动 */ EVENT,
    /** 反作弊 */ AUTOBAN,
    /** 内置辅助插件 */ PLUGIN,
    /** 仓库 */ STORAGE
}
