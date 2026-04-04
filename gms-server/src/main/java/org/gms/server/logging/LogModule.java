package org.gms.server.logging;

import org.gms.util.I18nUtil;

/**
 * 日志模块枚举
 * 用于规范化日志记录的模块名称，便于统计和国际化。
 */
public enum LogModule {
    /** 系统 */ SYSTEM,
    /** 账号 */ ACCOUNT,
    /** 角色 */ CHARACTER,
    /** 物品溯源 */ ITEM_TRACEAB,
    /** 物品找回 */ ITEM_RECOVERY,
    /** NPC商店 */ SHOP,
    /** 玩家交易 */ TRADE,
    /** 组队 */ PARTY,
    /** 公会 */ GUILD,
    /** 家族 */ FAMILY,
    /** 任务 */ QUEST,
    /** 地图/打怪 */ FIELD,
    /** 脚本 */ SCRIPT,
    /** 商城 */ CASH_SHOP,
    /** 事件 */ EVENT,
    /** 反作弊 */ AUTOBAN,
    /** 内置辅助插件 */ PLUGIN,
    /** 仓库 */ STORAGE;

    public String getI18nKey() {
        return "log.module." + this.name();
    }

    public String getI18nVal() {
        return I18nUtil.getLogMessage(getI18nKey());
    }
}
