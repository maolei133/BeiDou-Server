package org.gms.log;

import org.gms.config.GameConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 日志管理系统核心类
 * 支持按大类和小类进行分类存储
 */
public class LogManager {
    private static final Logger log = LoggerFactory.getLogger(LogManager.class);
    
    private static final String LOG_BASE_DIR = "logs/custom";
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd");
    private static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    
    private static final ExecutorService executorService = Executors.newFixedThreadPool(
        Runtime.getRuntime().availableProcessors()
    );
    
    static {
        // 创建基础日志目录
        createDirIfNotExists(LOG_BASE_DIR);
    }
    
    /**
     * 记录日志的核心方法
     *
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @param message 日志内容
     */
    public static void log(String majorCategory, String minorCategory, String message) {
        CompletableFuture.runAsync(() -> {
            try {
                writeToLogFile(majorCategory, minorCategory, message);
            } catch (Exception e) {
                log.error("写入日志文件时发生错误: majorCategory={}, minorCategory={}", majorCategory, minorCategory, e);
            }
        }, executorService);
    }
    
    /**
     * 记录带堆栈信息的日志
     *
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @param message 日志内容
     * @param throwable 异常对象
     */
    public static void log(String majorCategory, String minorCategory, String message, Throwable throwable) {
        CompletableFuture.runAsync(() -> {
            try {
                writeToLogFile(majorCategory, minorCategory, message + "\n" + getStackTrace(throwable));
            } catch (Exception e) {
                log.error("写入日志文件时发生错误: majorCategory={}, minorCategory={}", majorCategory, minorCategory, e);
            }
        }, executorService);
    }
    
    /**
     * 写入日志到指定文件
     *
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @param message 日志内容
     */
    private static void writeToLogFile(String majorCategory, String minorCategory, String message) {
        try {
            // 构建日志目录路径: logs/custom/大类/小类/
            String logDirPath = LOG_BASE_DIR + File.separator + majorCategory + File.separator + minorCategory;
            createDirIfNotExists(logDirPath);
            
            // 构建日志文件路径: logs/custom/大类/小类/yyyy-MM-dd.log
            String logFilePath = logDirPath + File.separator + DATE_FORMAT.format(new Date()) + ".log";
            
            // 格式化日志内容
            String formattedMessage = String.format("[%s] %s%n", TIME_FORMAT.format(new Date()), message);
            
            // 写入日志文件
            Path path = Paths.get(logFilePath);
            Files.write(path, formattedMessage.getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            log.error("写入日志文件失败: ", e);
        }
    }
    
    /**
     * 获取异常堆栈信息
     *
     * @param throwable 异常对象
     * @return 堆栈信息字符串
     */
    private static String getStackTrace(Throwable throwable) {
        StringBuilder sb = new StringBuilder();
        sb.append(throwable.toString()).append("\n");
        for (StackTraceElement element : throwable.getStackTrace()) {
            sb.append("\tat ").append(element.toString()).append("\n");
        }
        return sb.toString();
    }
    
    /**
     * 创建目录（如果不存在）
     *
     * @param dirPath 目录路径
     */
    private static void createDirIfNotExists(String dirPath) {
        File dir = new File(dirPath);
        if (!dir.exists()) {
            dir.mkdirs();
        }
    }
    
    /**
     * 关闭线程池
     */
    public static void shutdown() {
        executorService.shutdown();
    }
}