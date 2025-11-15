package org.gms.log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 游戏日志记录器类
 * 用于特定类别日志的记录
 */
public class GameLogger {
    private final Logger logger;
    private final String majorCategory;
    private final String minorCategory;
    
    public GameLogger(String majorCategory, String minorCategory) {
        this.majorCategory = majorCategory;
        this.minorCategory = minorCategory;
        // 使用SLF4J记录器作为备用日志系统
        this.logger = LoggerFactory.getLogger("GameLog." + majorCategory + "." + minorCategory);
    }
    
    /**
     * 记录INFO级别日志
     */
    public void info(String message, Object... params) {
        String formattedMessage = formatMessage(message, params);
        LogManager.log(majorCategory, minorCategory, formattedMessage);
        logger.info("[{}:{}] {}", majorCategory, minorCategory, formattedMessage);
    }
    
    /**
     * 记录WARN级别日志
     */
    public void warn(String message, Object... params) {
        String formattedMessage = formatMessage(message, params);
        LogManager.log(majorCategory, minorCategory, formattedMessage);
        logger.warn("[{}:{}] {}", majorCategory, minorCategory, formattedMessage);
    }
    
    /**
     * 记录ERROR级别日志
     */
    public void error(String message, Object... params) {
        String formattedMessage = formatMessage(message, params);
        LogManager.log(majorCategory, minorCategory, formattedMessage);
        logger.error("[{}:{}] {}", majorCategory, minorCategory, formattedMessage);
    }
    
    /**
     * 记录ERROR级别日志（带异常）
     */
    public void error(String message, Throwable throwable, Object... params) {
        String formattedMessage = formatMessage(message, params);
        LogManager.log(majorCategory, minorCategory, formattedMessage, throwable);
        logger.error("[{}:{}] {}", majorCategory, minorCategory, formattedMessage, throwable);
    }
    
    /**
     * 格式化消息（类似SLF4J的占位符替换）
     */
    private String formatMessage(String message, Object... params) {
        if (params == null || params.length == 0) {
            return message;
        }
        
        String formattedMessage = message;
        for (Object param : params) {
            formattedMessage = formattedMessage.replaceFirst("\\{\\}", String.valueOf(param != null ? param : "null"));
        }
        return formattedMessage;
    }
}