package org.gms.server.logging;

import lombok.extern.slf4j.Slf4j;
import org.gms.util.I18nUtil;
import org.springframework.context.NoSuchMessageException;

import java.util.ArrayList;
import java.util.List;

/**
 * 日志动作枚举
 * 用于规范化日志记录的具体行为。
 * 需要维护 @src/main/resources/i18n/log 的多语言包以 log.action. 开头的键值映射
 */
@Slf4j
public enum LogAction {
    // --- SYSTEM ---
    /** 服务器启动 */
    SYSTEM_SERVER_START,
    /** 服务器关闭 */
    SYSTEM_SERVER_SHUTDOWN,
    /** 系统错误 */
    SYSTEM_ERROR,

    // --- ACCOUNT ---
    /** 登录成功 */
    ACCOUNT_LOGIN_SUCCESS,
    /** 登录失败 */
    ACCOUNT_LOGIN_FAIL,
    // --- CHARACTER ---
    /** 创建角色 */
    CHARACTER_CREATE,
    /** 选择角色 */
    CHARACTER_SELECT,
    /** 删除角色 */
    CHARACTER_DELETE,
    /** 升级 */
    CHARACTER_LEVEL_UP,
    /** 转职 */
    CHARACTER_JOB_ADVANCE,
    /** 属性变更 */
    CHARACTER_STAT_CHANGE,
    /** 死亡 */
    CHARACTER_DIE,
    /** 复活 */
    CHARACTER_REVIVE,
    /** 技能点分配 */
    CHARACTER_SP_DISTRIBUTE,
    /** 属性点分配 */
    CHARACTER_AP_DISTRIBUTE,
    /** 抓捕服刑 */
    CHARACTER_JAIL,
    /** 释放服刑 */
    CHARACTER_UNJAIL,

    // --- ITEM_TRACEAB ---
    /** 获得物品 */
    ITEM_TRACEAB_GAIN,
    /** 失去物品 */
    ITEM_TRACEAB_LOST,
    /** 使用物品 */
    ITEM_TRACEAB_USE,
    /** 移动物品 */
    ITEM_TRACEAB_MOVE,
    /** 丢弃物品 */
    ITEM_TRACEAB_DROP,
    /** 拾取物品 */
    ITEM_TRACEAB_PICKUP,

    // --- SHOP ---
    /** 商店购买 */
    SHOP_BUY,
    /** 商店出售 */
    SHOP_SELL,
    /** 商店充能 */
    SHOP_RECHARGE,

    // --- TRADE ---
    /** 交易开始 */
    TRADE_START,
    /** 交易完成 */
    TRADE_COMPLETE,
    /** 交易取消 */
    TRADE_CANCEL,

    // --- CASH_SHOP ---
    /** 商城购买 */
    CASH_SHOP_BUY,
    /** 商城赠送 */
    CASH_SHOP_GIFT,
    /** 商城充值 */
    CASH_SHOP_CHARGE,
    /** 商城取出 */
    CASH_SHOP_OUT,
    /** 商城存入 */
    CASH_SHOP_IN,

    // --- FIELD ---
    /** 切换地图 */
    FIELD_MAP_CHANGE,
    /** BOSS被击杀 */
    FIELD_BOSS_KILLED,
    /** 怪物被击杀 */
    FIELD_MONSTER_KILLED,

    // --- AUTOBAN ---
    /** 检测到作弊 */
    AUTOBAN_CHEAT_DETECTED,
    /** 作弊警告 */
    AUTOBAN_CHEAT_WARNING,
    /** 作弊封号 */
    AUTOBAN_CHEAT_BAN,
    /** 作弊断开 */
    AUTOBAN_CHEAT_DISCONNECT,
    /** 作弊处罚 */
    AUTOBAN_CHEAT_PENALTY,
    /** 作弊提醒 */
    AUTOBAN_CHEAT_ALERT,

    // --- PLUGIN ---
    /** 插件启动 */
    PLUGIN_START,
    /** 插件停止 */
    PLUGIN_STOP,
    /** 插件使用 */
    PLUGIN_USE,
    /** 插件错误 */
    PLUGIN_ERROR,

    // --- STORAGE ---
    /** 存入仓库 */
    STORAGE_IN,
    /** 取出仓库 */
    STORAGE_OUT,
    /** 仓库迁移 */
    STORAGE_MIGRATE,
    /** 仓库合并 */
    STORAGE_MERGE,
    /** 仓库合并失败 */
    STORAGE_MERGE_FAIL;

    public String getI18nKey() {
        return "log.action." + this.name();
    }

    public String getI18nVal() {
        return I18nUtil.getLogMessage(getI18nKey());
    }

    /**
     * 检查并列出所有未在i18n属性文件中注册的日志动作键值
     */
    public static boolean checkMissingI18nKeys() {
        List<String> missingKeys = new ArrayList<>();
        for (LogAction action : LogAction.values()) {
            try {
                I18nUtil.logSource.getMessage(action.getI18nKey(), null, I18nUtil.LANGUAGE);
            } catch (NoSuchMessageException e) {
                missingKeys.add(action.getI18nKey());
            }
        }

        if (!missingKeys.isEmpty()) {
            log.warn("检测到以下 i18n 日志动作 键值未注册，请添加到 `log_zh_CN.properties` 和 `log_en_US.properties` 文件中：");
            for (String key : missingKeys) {
                log.warn(" - " + key);
            }
            return false;
        }
        return true;
    }
}
