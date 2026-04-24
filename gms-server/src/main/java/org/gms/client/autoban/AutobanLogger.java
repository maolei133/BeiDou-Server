package org.gms.client.autoban;

import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.message.MapMessage;
import org.gms.client.Character;
import org.gms.server.logging.AuditLogger;
import org.gms.server.logging.LogAction;
import org.gms.server.logging.LogModule;

/**
 * 反作弊日志记录器
 * <p>
 * 这是一个用于集中处理所有反作弊相关日志的工具类。
 * 它提供了一个统一的日志记录出口，确保所有反作弊日志都具有一致的结构和格式。
 * </p>
 */
@Slf4j
public class AutobanLogger {

    /**
     * 记录反作弊日志的核心方法。
     * <p>
     * 此方法会为所有反作弊日志自动注入一组标准的基础字段，
     * 包括玩家坐标、作弊检测类型等，然后再调用底层的 {@link AuditLogger} 进行记录。
     * </p>
     *
     * @param chr       触发日志的玩家角色对象。
     * @param factory   相关的反作弊检测类型 (e.g., DAMAGE_HACK)。
     * @param action    日志的分类，使用 {@link LogAction} 中的 CHEAT_* 枚举 (e.g., CHEAT_BAN, CHEAT_ALERT)。
     * @param reason    触发该日志的具体原因描述。
     * @param extraData 一个包含额外业务数据的 {@link MapMessage}，可以为 null。
     */
    public static void log(Character chr, AutobanFactory factory, LogAction action, String reason, MapMessage extraData) {
        try {
            // 安全检查：如果角色对象为空，或配置中关闭了日志记录，则直接返回。
            if (chr == null || !chr.getAutoBanManager().useAutoBanLog()) {
                return;
            }

            // 创建一个新的 MapMessage，如果传入了 extraData，则基于它创建以保留已有信息。
            MapMessage logMessage = (extraData != null) ? new MapMessage(extraData.getData()) : new MapMessage();

            // 注入统一的基础字段，这是所有反作弊日志都包含的标准信息。
            logMessage.with("x", chr.getPosition().x)
                    .with("y", chr.getPosition().y)
                    .with("type", factory.getName()) // 作弊检测的类型名称
                    .with("msg", reason);           // 详细的原因描述

            // 调用全局的审计日志记录器，将结构化的日志消息写入。
            AuditLogger.info(LogModule.AUTOBAN, action, logMessage);
        } catch (Throwable t) {
            log.error("记录反作弊日志时发生严重错误", t);
        }
    }

    /**
     * 记录反作弊日志的简化重载方法。
     * <p>
     * 当没有额外的业务数据需要记录时，可以调用此方法。
     * </p>
     *
     * @param chr     触发日志的玩家角色对象。
     * @param factory 相关的反作弊检测类型。
     * @param action  日志的分类。
     * @param reason  触发该日志的具体原因描述。
     */
    public static void log(Character chr, AutobanFactory factory, LogAction action, String reason) {
        log(chr, factory, action, reason, null);
    }
}
