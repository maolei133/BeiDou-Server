package org.gms.server.logging;

import lombok.extern.slf4j.Slf4j;
import org.gms.util.I18nUtil;
import org.springframework.context.NoSuchMessageException;

import java.util.ArrayList;
import java.util.List;

/**
 * 日志模块枚举
 * 用于规范化日志记录的模块名称，便于统计和国际化。
 * 需要维护 @src/main/resources/i18n/log 的多语言包以 log.module. 开头的键值映射
 */
@Slf4j
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

    /**
     * 检查并列出所有未在i18n属性文件中注册的日志模块键值
     */
    public static boolean checkMissingI18nKeys() {
        List<String> missingKeys = new ArrayList<>();
        for (LogModule module : LogModule.values()) {
            try {
                I18nUtil.logSource.getMessage(module.getI18nKey(), null, I18nUtil.LANGUAGE);
            } catch (NoSuchMessageException e) {
                missingKeys.add(module.getI18nKey());
            }
        }

        if (!missingKeys.isEmpty()) {
            log.warn("检测到以下 i18n 日志模块 键值未注册，请添加到 `log_zh_CN.properties` 和 `log_en_US.properties` 文件中：");
            for (String key : missingKeys) {
                log.warn(" - " + key);
            }
            return false;
        }
        return true;
    }
}
