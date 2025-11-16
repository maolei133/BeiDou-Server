package org.gms.log;

import org.gms.constants.net.ServerConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 增强型日志管理器
 * 支持记录更详细的日志信息，包括IP、MAC、HWID、账号、角色等
 */
public class EnhancedLogManager {
    private static final Logger log = LoggerFactory.getLogger(EnhancedLogManager.class);
    
    private static final String LOG_BASE_DIR = "logs/custom";
    private static final SimpleDateFormat FILE_DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd");
    
    // 用于提取日志中的特定信息的正则表达式
    private static final Pattern IP_PATTERN = Pattern.compile("\\[IP:([^\\]]+)\\]");
    private static final Pattern MAC_PATTERN = Pattern.compile("\\[MAC:([^\\]]+)\\]");
    private static final Pattern HWID_PATTERN = Pattern.compile("\\[HWID:([^\\]]+)\\]");
    private static final Pattern ACCOUNT_PATTERN = Pattern.compile("\\[Account:([^\\]]+)\\]");
    private static final Pattern ACCOUNT_ID_PATTERN = Pattern.compile("\\[AccountId:([^\\]]+)\\]");
    private static final Pattern CHARACTER_PATTERN = Pattern.compile("\\[Character:([^\\]]+)\\]");
    private static final Pattern CHARACTER_ID_PATTERN = Pattern.compile("\\[CharacterId:([^\\]]+)\\]");
    private static final Pattern LEVEL_PATTERN = Pattern.compile("\\[Level:([^\\]]+)\\]");
    
    /**
     * 记录增强型日志
     * 
     * @param entry 增强型日志条目
     */
    public static void log(EnhancedLogEntry entry) {
        try {
            // 确保日志目录存在
            String logDirPath = LOG_BASE_DIR + File.separator + entry.getMajorCategory() + File.separator + entry.getMinorCategory();
            File logDir = new File(logDirPath);
            if (!logDir.exists()) {
                logDir.mkdirs();
            }
            
            // 构造日志文件路径
            String logFileName = FILE_DATE_FORMAT.format(new Date()) + ".log";
            String logFilePath = logDirPath + File.separator + logFileName;
            
            // 构造日志内容
            String logContent = entry.toLogString() + System.lineSeparator();
            
            // 写入日志文件
            try (FileWriter writer = new FileWriter(logFilePath, true)) {
                writer.write(logContent);
            }
        } catch (IOException e) {
            log.error("写入日志文件时发生错误", e);
        }
    }
    
    /**
     * 从日志文件中提取唯一值（如IP、MAC、HWID等）
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @param pattern 正则表达式模式
     * @return 唯一值集合
     */
    public static Set<String> extractUniqueValues(String majorCategory, String minorCategory, Pattern pattern) {
        Set<String> uniqueValues = new HashSet<>();
        
        try {
            String logDirPath = LOG_BASE_DIR + File.separator + majorCategory + File.separator + minorCategory;
            File logDir = new File(logDirPath);
            
            if (!logDir.exists()) {
                return uniqueValues;
            }
            
            File[] logFiles = logDir.listFiles((dir, name) -> name.endsWith(".log"));
            if (logFiles == null) {
                return uniqueValues;
            }
            
            for (File logFile : logFiles) {
                try (java.util.Scanner scanner = new java.util.Scanner(logFile)) {
                    while (scanner.hasNextLine()) {
                        String line = scanner.nextLine();
                        Matcher matcher = pattern.matcher(line);
                        if (matcher.find()) {
                            uniqueValues.add(matcher.group(1));
                        }
                    }
                }
            }
        } catch (IOException e) {
            log.error("读取日志文件时发生错误", e);
        }
        
        return uniqueValues;
    }
    
    /**
     * 获取所有记录过的IP地址
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return IP地址集合
     */
    public static Set<String> getUniqueIPs(String majorCategory, String minorCategory) {
        return extractUniqueValues(majorCategory, minorCategory, IP_PATTERN);
    }
    
    /**
     * 获取所有记录过的MAC地址
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return MAC地址集合
     */
    public static Set<String> getUniqueMACs(String majorCategory, String minorCategory) {
        return extractUniqueValues(majorCategory, minorCategory, MAC_PATTERN);
    }
    
    /**
     * 获取所有记录过的HWID
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return HWID集合
     */
    public static Set<String> getUniqueHWIDs(String majorCategory, String minorCategory) {
        return extractUniqueValues(majorCategory, minorCategory, HWID_PATTERN);
    }
    
    /**
     * 获取所有记录过的账号
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return 账号集合
     */
    public static Set<String> getUniqueAccounts(String majorCategory, String minorCategory) {
        return extractUniqueValues(majorCategory, minorCategory, ACCOUNT_PATTERN);
    }
    
    /**
     * 获取所有记录过的角色ID
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return 角色ID集合
     */
    public static Set<String> getUniqueCharacterIds(String majorCategory, String minorCategory) {
        return extractUniqueValues(majorCategory, minorCategory, CHARACTER_ID_PATTERN);
    }
}