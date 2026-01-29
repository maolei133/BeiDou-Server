package org.gms.server.logging;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.MapMessage;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 审计日志工具类
 * 封装 Log4j2，自动注入上下文信息。
 */
public class AuditLogger {
    private static final Logger log = LogManager.getLogger("audit");
    
    // 模块开关配置 (默认全开)
    private static final Map<String, Boolean> moduleConfig = new ConcurrentHashMap<>();

    /**
     * 记录审计日志
     * @param module 模块名 (如: shop, login)
     * @param action 动作名 (如: buy, enter)
     * @param message 描述信息
     */
    public static void info(String module, String action, String message) {
        info(module, action, new MapMessage().with("msg", message));
    }

    /**
     * 记录结构化审计日志
     * @param module 模块名
     * @param action 动作名
     * @param data 数据对象
     */
    public static void info(String module, String action, MapMessage data) {
        // 1. 检查模块开关
        if (!isModuleEnabled(module)) {
            return;
        }

        if (data == null) {
            data = new MapMessage();
        }

        // 2. 注入基础字段
        data.with("mod", module);
        data.with("act", action);

        // 3. 自动注入上下文信息 (chr, chrId, accId, map)
        Map<String, String> contextData = AuditContext.get();
        for (Map.Entry<String, String> entry : contextData.entrySet()) {
            // 如果 data 中没有该字段，则使用上下文中的值
            if (!data.containsKey(entry.getKey())) {
                data.with(entry.getKey(), entry.getValue());
            }
        }

        // 4. 写入日志
        log.info(data);
    }

    /**
     * 记录错误日志 (带堆栈)
     */
    public static void error(String module, String action, String message, Throwable t) {
        MapMessage data = new MapMessage()
                .with("mod", module)
                .with("act", action)
                .with("msg", message)
                .with("err", t.getMessage());
        
        // 注入上下文
        Map<String, String> contextData = AuditContext.get();
        for (Map.Entry<String, String> entry : contextData.entrySet()) {
             data.with(entry.getKey(), entry.getValue());
        }

        log.error(data, t);
    }

    // --- 配置管理 ---

    public static void setModuleEnabled(String module, boolean enabled) {
        moduleConfig.put(module, enabled);
    }

    public static boolean isModuleEnabled(String module) {
        return moduleConfig.getOrDefault(module, true);
    }

    public static Map<String, Boolean> getModuleConfig() {
        return new ConcurrentHashMap<>(moduleConfig); // 返回副本以保证线程安全
    }
}
