package org.gms.log;

import org.gms.client.Character;
import org.gms.client.Client;

import java.util.HashMap;
import java.util.Map;

/**
 * 错误日志记录器
 * 专门用于记录系统异常、错误和警告信息
 */
public class ErrorLogger {
    private static final String ERROR_MAJOR_CATEGORY = LogCategoryDefinition.Major.ERROR;
    
    /**
     * 记录异常信息
     * 
     * @param client 客户端对象
     * @param chr 角色对象
     * @param exception 异常对象
     * @param context 上下文信息
     */
    public static void logException(Client client, Character chr, Exception exception, String context) {
        Map<String, Object> errorData = new HashMap<>();
        errorData.put("type", "exception");
        errorData.put("exceptionType", exception.getClass().getSimpleName());
        errorData.put("exceptionMessage", exception.getMessage());
        errorData.put("context", context);
        
        // 添加上下文信息
        if (chr != null) {
            errorData.put("playerName", chr.getName());
            errorData.put("characterId", chr.getId());
            errorData.put("accountId", chr.getAccountId());
            if (chr.getMap() != null) {
                errorData.put("mapId", chr.getMapId());
                errorData.put("mapName", chr.getMap().getMapName());
            }
        }
        
        if (client != null) {
            errorData.put("ip", client.getRemoteAddress());
            errorData.put("accountId", client.getAccID());
        }
        
        // 添加堆栈跟踪信息
        StackTraceElement[] stackTrace = exception.getStackTrace();
        StringBuilder stackTraceStr = new StringBuilder();
        for (int i = 0; i < Math.min(stackTrace.length, 10); i++) { // 限制堆栈跟踪信息数量
            stackTraceStr.append(stackTrace[i].toString()).append("\n");
        }
        errorData.put("stackTrace", stackTraceStr.toString());
        
        new ModuleLogger(ERROR_MAJOR_CATEGORY, LogCategoryDefinition.Minor.EXCEPTION)
                .logWithLevel(client, chr, BaseLogEntry.LEVEL_ERROR, errorData);
    }
    
    /**
     * 记录警告信息
     * 
     * @param client 客户端对象
     * @param chr 角色对象
     * @param warning 警告信息
     * @param context 上下文信息
     */
    public static void logWarning(Client client, Character chr, String warning, String context) {
        Map<String, Object> warningData = new HashMap<>();
        warningData.put("type", "warning");
        warningData.put("warning", warning);
        warningData.put("context", context);
        
        // 添加上下文信息
        if (chr != null) {
            warningData.put("playerName", chr.getName());
            warningData.put("characterId", chr.getId());
            warningData.put("accountId", chr.getAccountId());
            if (chr.getMap() != null) {
                warningData.put("mapId", chr.getMapId());
                warningData.put("mapName", chr.getMap().getMapName());
            }
        }
        
        if (client != null) {
            warningData.put("ip", client.getRemoteAddress());
            warningData.put("accountId", client.getAccID());
        }
        
        new ModuleLogger(ERROR_MAJOR_CATEGORY, LogCategoryDefinition.Minor.WARNING)
                .logWithLevel(client, chr, BaseLogEntry.LEVEL_WARN, warningData);
    }
    
    /**
     * 记录错误信息
     * 
     * @param client 客户端对象
     * @param chr 角色对象
     * @param error 错误信息
     * @param context 上下文信息
     */
    public static void logError(Client client, Character chr, String error, String context) {
        Map<String, Object> errorData = new HashMap<>();
        errorData.put("type", "error");
        errorData.put("error", error);
        errorData.put("context", context);
        
        // 添加上下文信息
        if (chr != null) {
            errorData.put("playerName", chr.getName());
            errorData.put("characterId", chr.getId());
            errorData.put("accountId", chr.getAccountId());
            if (chr.getMap() != null) {
                errorData.put("mapId", chr.getMapId());
                errorData.put("mapName", chr.getMap().getMapName());
            }
        }
        
        if (client != null) {
            errorData.put("ip", client.getRemoteAddress());
            errorData.put("accountId", client.getAccID());
        }
        
        new ModuleLogger(ERROR_MAJOR_CATEGORY, LogCategoryDefinition.Minor.EXCEPTION)
                .logWithLevel(client, chr, BaseLogEntry.LEVEL_ERROR, errorData);
    }
}