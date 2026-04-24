package org.gms.server.logging;

import org.gms.util.I18nUtil;

/**
 * 日志动作枚举
 * 用于规范化日志记录的具体行为。
 */
public enum LogAction {
    // --- SYSTEM ---
    /** 服务器启动 */ SERVER_START,
    /** 服务器关闭 */ SERVER_SHUTDOWN,
    /** 系统错误 */ ERROR,

    // --- ACCOUNT ---
    /** 登录成功 */ ACC_LOGIN_SUCCESS,
    /** 登录失败 */ ACC_LOGIN_FAIL,
    // --- CHARACTER ---
    /** 创建角色 */ CHR_CREATE,
    /** 选择角色 */ CHR_SELECT,
    /** 删除角色 */ CHR_DELETE,
    /** 升级 */ CHR_LEVEL_UP,
    /** 转职 */ CHR_JOB_ADVANCE,
    /** 属性变更 */ CHR_STAT_CHANGE,
    /** 死亡 */ CHR_DIE,
    /** 复活 */ CHR_REVIVE,
    /** 技能点分配 */ CHR_SP_DISTRIBUTE,
    /** 属性点分配 */ CHR_AP_DISTRIBUTE,

    // --- ITEM ---
    /** 获得物品 */ ITEM_GAIN,
    /** 失去物品 */ ITEM_LOST,
    /** 使用物品 */ ITEM_USE,
    /** 移动物品 */ ITEM_MOVE,
    /** 丢弃物品 */ ITEM_DROP,
    /** 拾取物品 */ ITEM_PICKUP,

    // --- SHOP ---
    /** 商店购买 */ SHOP_BUY,
    /** 商店出售 */ SHOP_SELL,
    /** 商店充能 */ SHOP_RECHARGE,

    // --- TRADE ---
    /** 交易开始 */ TRADE_START,
    /** 交易完成 */ TRADE_COMPLETE,
    /** 交易取消 */ TRADE_CANCEL,

    // --- CASH_SHOP ---
    /** 商城购买 */ CS_BUY,
    /** 商城赠送 */ CS_GIFT,
    /** 商城充值 */ CS_CHARGE,
    /** 商城取出 */ CS_OUT,
    /** 商城存入 */ CS_IN,

    // --- FIELD ---
    /** 切换地图 */ MAP_CHANGE,
    /** BOSS被击杀 */ BOSS_KILLED,

    // --- AUTOBAN ---
    /** 检测到作弊 */ CHEAT_DETECTED,
    /** 作弊警告 */ CHEAT_WARNING,
    /** 作弊封号 */ CHEAT_BAN,
    /** 作弊断开 */ CHEAT_DISCONNECT,
    /** 作弊处罚 */ CHEAT_PENALTY,
    /** 作弊提醒 */ CHEAT_ALERT,

    // --- PLUGIN ---
    /** 插件启动 */ PLUGIN_START,
    /** 插件停止 */ PLUGIN_STOP,
    /** 插件使用 */ PLUGIN_USE,
    /** 插件错误 */ PLUGIN_ERROR,

    // --- STORAGE ---
    /** 存入仓库 */ STORAGE_IN,
    /** 取出仓库 */ STORAGE_OUT,
    /** 仓库迁移 */ STORAGE_MIGRATE,
    /** 仓库合并 */ STORAGE_MERGE,
    /** 仓库合并失败 */ STORAGE_MERGE_FAIL;

    public String getI18nKey() {
        return "log.action." + this.name();
    }

    public String getI18nVal() {
        return I18nUtil.getLogMessage(getI18nKey());
    }
}
