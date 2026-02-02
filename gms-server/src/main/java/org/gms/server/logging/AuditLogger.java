/**
 * 审计日志工具类
 * 封装 Log4j2，自动注入上下文信息。
 */
package org.gms.server.logging;

import com.alibaba.fastjson2.JSON;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.MapMessage;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class AuditLogger {
    // 获取名为 "audit" 的 Logger，对应 log4j2.xml 中的配置
    private static final Logger log = LogManager.getLogger("audit");
    
    // 模块开关配置 (默认全开)
    private static final Map<String, Boolean> moduleConfig = new ConcurrentHashMap<>();

    static {
        // 预注册所有枚举模块
        for (LogModule mod : LogModule.values()) {
            moduleConfig.put(mod.name(), true);
        }
    }

    /**
     * 记录审计日志 (枚举版 - 推荐)
     */
    public static void info(LogModule module, LogAction action, String message) {
        info(module.name(), action.name(), new MapMessage().with("msg", message));
    }

    public static void info(LogModule module, LogAction action, MapMessage data) {
        info(module.name(), action.name(), data);
    }

    /**
     * 记录审计日志 (字符串版 - 底层实现)
     */
    public static void info(String module, String action, String message) {
        info(module, action, new MapMessage().with("msg", message));
    }

    public static void info(String module, String action, MapMessage data) {
        // 自动注册模块 (防止有未在枚举中定义的动态模块)
        moduleConfig.putIfAbsent(module, true);

        // 1. 检查模块开关
        if (!isModuleEnabled(module)) {
            return;
        }

        if (data == null) {
            data = new MapMessage();
        }

        // 2. 准备最终的日志 Map (使用 LinkedHashMap 保证顺序)
        Map<String, Object> logMap = new LinkedHashMap<>();

        // 3. 基础字段 (按预设顺序)
        logMap.put("ts", System.currentTimeMillis());
        // logMap.put("l", "INFO"); // 移除日志级别
        logMap.put("mod", module);
        logMap.put("act", action);
        
        // 处理 category -> cat
        if (data.containsKey("category")) {
            logMap.put("cat", data.get("category"));
        } else if (data.containsKey("cat")) {
            logMap.put("cat", data.get("cat"));
        }

        // 4. 注入上下文信息 (按预设顺序)
        Map<String, String> contextData = AuditContext.get();
        
        // 客户端字段
        putIfPresent(logMap, contextData, "ip");
        putIfPresent(logMap, contextData, "hwid");
        putIfPresent(logMap, contextData, "macs");
        
        // 角色信息字段
        putIfPresent(logMap, contextData, "aid");
        putIfPresent(logMap, contextData, "acc");
        putIfPresent(logMap, contextData, "cid");
        putIfPresent(logMap, contextData, "chr");
        putIfPresent(logMap, contextData, "lvl");
        putIfPresent(logMap, contextData, "job");
        putIfPresent(logMap, contextData, "jobName"); // 新增
        putIfPresent(logMap, contextData, "map");
        putIfPresent(logMap, contextData, "mapName"); // 新增

        // 5. 注入其他业务字段 (msg 等)
        Map<String, String> rawData = data.getData();
        for (Map.Entry<String, String> entry : rawData.entrySet()) {
            String key = entry.getKey();
            // 跳过已处理的字段
            if (key.equals("mod") || key.equals("act") || key.equals("category") || key.equals("cat")) {
                continue;
            }
            // 如果上下文里已经有了，且业务数据里也有，通常业务数据优先？或者上下文优先？
            // 这里我们假设业务数据可能包含更具体的覆盖值，但通常不应该冲突。
            // 为了保持顺序，我们把剩余的字段放在最后
            if (!logMap.containsKey(key)) {
                logMap.put(key, entry.getValue());
            }
        }
        
        // 确保 msg 存在 (如果 data 里有 msg，上面已经 put 了；如果没有，这里也不强制，但通常会有)
        
        // 6. 序列化为 JSON 字符串并写入日志
        log.info(JSON.toJSONString(logMap));
    }
    
    private static void putIfPresent(Map<String, Object> target, Map<String, String> source, String key) {
        if (source.containsKey(key)) {
            target.put(key, source.get(key));
        }
    }

    /**
     * 记录错误日志
     */
    public static void error(LogModule module, LogAction action, String message, Throwable t) {
        error(module.name(), action.name(), message, t);
    }

    public static void error(String module, String action, String message, Throwable t) {
        moduleConfig.putIfAbsent(module, true);

        Map<String, Object> logMap = new LinkedHashMap<>();
        logMap.put("ts", System.currentTimeMillis());
        // logMap.put("l", "ERROR"); // 移除日志级别
        logMap.put("mod", module);
        logMap.put("act", action);
        
        Map<String, String> contextData = AuditContext.get();
        putIfPresent(logMap, contextData, "ip");
        putIfPresent(logMap, contextData, "hwid");
        putIfPresent(logMap, contextData, "macs");
        putIfPresent(logMap, contextData, "aid");
        putIfPresent(logMap, contextData, "acc");
        putIfPresent(logMap, contextData, "cid");
        putIfPresent(logMap, contextData, "chr");
        putIfPresent(logMap, contextData, "lvl");
        putIfPresent(logMap, contextData, "job");
        putIfPresent(logMap, contextData, "jobName"); // 新增
        putIfPresent(logMap, contextData, "map");
        putIfPresent(logMap, contextData, "mapName"); // 新增
        
        logMap.put("msg", message);
        if (t != null) {
            logMap.put("err", t.getMessage());
        }

        log.error(JSON.toJSONString(logMap), t);
    }

    // --- 配置管理 ---

    public static void setModuleEnabled(String module, boolean enabled) {
        moduleConfig.put(module, enabled);
    }

    public static boolean isModuleEnabled(String module) {
        return moduleConfig.getOrDefault(module, true);
    }

    public static Map<String, Boolean> getModuleConfig() {
        return new ConcurrentHashMap<>(moduleConfig);
    }
}
