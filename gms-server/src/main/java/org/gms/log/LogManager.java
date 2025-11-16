package org.gms.log;

import org.gms.constants.net.ServerConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * 日志管理器
 * 负责将日志按照指定格式写入文件
 */
public class LogManager {
    private static final Logger log = LoggerFactory.getLogger(LogManager.class);
    
    private static final String LOG_BASE_DIR = "logs/custom";
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private static final SimpleDateFormat FILE_DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd");
    
    /**
     * 记录日志
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @param message 日志消息
     */
    public static void log(String majorCategory, String minorCategory, String message) {
        log(majorCategory, minorCategory, message, null);
    }
    
    /**
     * 记录日志（带异常信息）
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @param message 日志消息
     * @param throwable 异常信息
     */
    public static void log(String majorCategory, String minorCategory, String message, Throwable throwable) {
        try {
            // 确保日志目录存在
            String logDirPath = LOG_BASE_DIR + File.separator + majorCategory + File.separator + minorCategory;
            File logDir = new File(logDirPath);
            if (!logDir.exists()) {
                logDir.mkdirs();
            }
            
            // 构造日志文件路径
            String logFileName = FILE_DATE_FORMAT.format(new Date()) + ".log";
            String logFilePath = logDirPath + File.separator + logFileName;
            
            // 构造日志内容
            StringBuilder logContent = new StringBuilder();
            logContent.append(DATE_FORMAT.format(new Date()));
            logContent.append(" [").append(ServerConstants.BEI_DOU_VERSION).append("] ");
            logContent.append(message);
            
            if (throwable != null) {
                logContent.append(" Exception: ").append(throwable.getMessage());
            }
            
            logContent.append(System.lineSeparator());
            
            // 写入日志文件
            try (FileWriter writer = new FileWriter(logFilePath, true)) {
                writer.write(logContent.toString());
            }
        } catch (IOException e) {
            log.error("写入日志文件时发生错误", e);
        }
    }
}