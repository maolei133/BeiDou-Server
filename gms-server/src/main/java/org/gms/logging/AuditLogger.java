package org.gms.logging;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ObjectMessage;

import java.util.HashMap;
import java.util.Map;

/**
 * Loki 日志系统集成 - 审计日志工具
 * 
 * @author BeiDou
 */
public class AuditLogger {

    private static final Logger auditLogger = LogManager.getLogger("audit");

    /**
     * 记录业务日志 (INFO)
     *
     * @param module 业务模块 (LogModule)
     * @param action 具体行为
     * @param data   上下文数据 (key-value)
     */
    public static void info(String module, String action, Map<String, Object> data) {
        log(module, action, data, null);
    }

    /**
     * 记录业务异常 (WARN/ERROR)
     * 
     * @param module 业务模块
     * @param action 具体行为
     * @param data   上下文数据
     * @param e      异常堆栈
     */
    public static void error(String module, String action, Map<String, Object> data, Throwable e) {
        log(module, action, data, e);
    }

    private static void log(String module, String action, Map<String, Object> data, Throwable e) {
        if (data == null) {
            data = new HashMap<>();
        }
        data.put("mod", module);
        data.put("act", action);
        
        if (e != null) {
            data.put("err_msg", e.getMessage());
            auditLogger.error(new ObjectMessage(data), e);
        } else {
            auditLogger.info(new ObjectMessage(data));
        }
    }
}
