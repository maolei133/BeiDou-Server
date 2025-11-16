package org.gms.log;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.regex.Matcher;

/**
 * 日志查询服务类
 * 为后台管理系统提供日志查询功能
 */
public class LogQueryService {
    
    private static final String LOG_BASE_DIR = "logs/custom";
    
    // 用于提取日志中的特定信息的正则表达式
    private static final Pattern IP_PATTERN = Pattern.compile("\\[IP:([^\\]]+)\\]");
    private static final Pattern MAC_PATTERN = Pattern.compile("\\[MAC:([^\\]]+)\\]");
    private static final Pattern HWID_PATTERN = Pattern.compile("\\[HWID:([^\\]]+)\\]");
    private static final Pattern ACCOUNT_PATTERN = Pattern.compile("\\[Account:([^\\]]+)\\]");
    private static final Pattern CHARACTER_PATTERN = Pattern.compile("\\[Character:([^\\]]+)\\]");
    private static final Pattern CHARACTER_ID_PATTERN = Pattern.compile("\\[CharacterId:([^\\]]+)\\]");
    
    /**
     * 查询指定日期范围内的日志
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @param startDate 开始日期 (格式: yyyy-MM-dd)
     * @param endDate 结束日期 (格式: yyyy-MM-dd)
     * @return 日志内容列表
     */
    public static List<String> queryLogsByDateRange(String majorCategory, String minorCategory, 
                                                    String startDate, String endDate) {
        try {
            // 如果没有提供大类或小类，则返回空列表
            if (majorCategory == null || minorCategory == null || majorCategory.isEmpty() || minorCategory.isEmpty()) {
                return Collections.emptyList();
            }
            
            String logDirPath = LOG_BASE_DIR + File.separator + majorCategory + File.separator + minorCategory;
            File logDir = new File(logDirPath);
            
            if (!logDir.exists()) {
                return Collections.emptyList();
            }
            
            List<String> result = new ArrayList<>();
            
            try (Stream<Path> paths = Files.walk(Paths.get(logDirPath))) {
                List<Path> logFiles = paths
                    .filter(Files::isRegularFile)
                    .filter(path -> {
                        String fileName = path.getFileName().toString();
                        if (!fileName.endsWith(".log")) {
                            return false;
                        }
                        
                        // 如果没有提供日期范围，则返回所有日志文件
                        if (startDate == null && endDate == null) {
                            return true;
                        }
                        
                        // 移除 .log 后缀以进行比较
                        String datePart = fileName.substring(0, fileName.length() - 4);
                        
                        boolean afterStart = startDate == null || datePart.compareTo(startDate) >= 0;
                        boolean beforeEnd = endDate == null || datePart.compareTo(endDate) <= 0;
                        
                        return afterStart && beforeEnd;
                    })
                    .sorted()
                    .toList();
                
                readLogFiles(logFiles, result);
            }
            
            return result;
        } catch (IOException e) {
            LogManager.log("system", "error", "读取日志文件时发生错误: " + e.getMessage(), e);
            return Collections.emptyList();
        }
    }
    
    /**
     * 查询包含特定关键词的日志
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @param keyword 关键词
     * @return 包含关键词的日志行
     */
    public static List<String> queryLogsWithKeyword(String majorCategory, String minorCategory, String keyword) {
        try {
            // 检查必要参数
            if (majorCategory == null || minorCategory == null || keyword == null || 
                majorCategory.isEmpty() || minorCategory.isEmpty() || keyword.isEmpty()) {
                return Collections.emptyList();
            }
            
            String logDirPath = LOG_BASE_DIR + File.separator + majorCategory + File.separator + minorCategory;
            File logDir = new File(logDirPath);
            
            if (!logDir.exists()) {
                return Collections.emptyList();
            }
            
            List<String> result = new ArrayList<>();
            
            try (Stream<Path> paths = Files.walk(Paths.get(logDirPath))) {
                List<Path> logFiles = paths
                    .filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().endsWith(".log"))
                    .toList();
                
                readLogFilesWithKeyword(logFiles, result, keyword);
            }
            
            return result;
        } catch (IOException e) {
            LogManager.log("system", "error", "读取日志文件时发生错误: " + e.getMessage(), e);
            return Collections.emptyList();
        }
    }
    
    /**
     * 根据详细条件查询日志
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @param startDate 开始日期
     * @param endDate 结束日期
     * @param ip IP地址
     * @param mac MAC地址
     * @param hwid 硬件ID
     * @param account 账号
     * @param character 角色名
     * @param keyword 关键词
     * @return 符合条件的日志行
     */
    public static List<String> queryLogsWithDetails(String majorCategory, String minorCategory,
                                                    String startDate, String endDate,
                                                    String ip, String mac, String hwid,
                                                    String account, String character,
                                                    String keyword) {
        try {
            // 检查必要参数
            if (majorCategory == null || minorCategory == null || 
                majorCategory.isEmpty() || minorCategory.isEmpty()) {
                return Collections.emptyList();
            }
            
            String logDirPath = LOG_BASE_DIR + File.separator + majorCategory + File.separator + minorCategory;
            File logDir = new File(logDirPath);
            
            if (!logDir.exists()) {
                return Collections.emptyList();
            }
            
            List<String> result = new ArrayList<>();
            
            try (Stream<Path> paths = Files.walk(Paths.get(logDirPath))) {
                List<Path> logFiles = paths
                    .filter(Files::isRegularFile)
                    .filter(path -> {
                        String fileName = path.getFileName().toString();
                        if (!fileName.endsWith(".log")) {
                            return false;
                        }
                        
                        // 检查日期范围
                        if (startDate != null || endDate != null) {
                            // 移除 .log 后缀以进行比较
                            String datePart = fileName.substring(0, fileName.length() - 4);
                            
                            boolean afterStart = startDate == null || datePart.compareTo(startDate) >= 0;
                            boolean beforeEnd = endDate == null || datePart.compareTo(endDate) <= 0;
                            
                            return afterStart && beforeEnd;
                        }
                        
                        return true;
                    })
                    .sorted()
                    .toList();
                
                readLogFilesWithDetails(logFiles, result, ip, mac, hwid, account, character, keyword);
            }
            
            return result;
        } catch (IOException e) {
            LogManager.log("system", "error", "读取日志文件时发生错误: " + e.getMessage(), e);
            return Collections.emptyList();
        }
    }
    
    // 重构重复代码段：读取日志文件内容
    private static void readLogFiles(List<Path> logFiles, List<String> result) throws IOException {
        for (Path logFile : logFiles) {
            List<String> lines = Files.readAllLines(logFile);
            result.addAll(lines);
        }
    }
    
    // 重构重复代码段：读取带关键词过滤的日志文件内容
    private static void readLogFilesWithKeyword(List<Path> logFiles, List<String> result, String keyword) throws IOException {
        for (Path logFile : logFiles) {
            List<String> lines = Files.readAllLines(logFile);
            for (String line : lines) {
                if (line.contains(keyword)) {
                    result.add(line);
                }
            }
        }
    }
    
    // 读取带详细条件过滤的日志文件内容
    private static void readLogFilesWithDetails(List<Path> logFiles, List<String> result,
                                                String ip, String mac, String hwid,
                                                String account, String character,
                                                String keyword) throws IOException {
        for (Path logFile : logFiles) {
            List<String> lines = Files.readAllLines(logFile);
            for (String line : lines) {
                // 检查IP
                if (ip != null && !extractValue(line, IP_PATTERN).equals(ip)) {
                    continue;
                }
                
                // 检查MAC
                if (mac != null && !extractValue(line, MAC_PATTERN).equals(mac)) {
                    continue;
                }
                
                // 检查HWID
                if (hwid != null && !extractValue(line, HWID_PATTERN).equals(hwid)) {
                    continue;
                }
                
                // 检查账号
                if (account != null && !extractValue(line, ACCOUNT_PATTERN).equals(account)) {
                    continue;
                }
                
                // 检查角色
                if (character != null && !extractValue(line, CHARACTER_PATTERN).equals(character)) {
                    continue;
                }
                
                // 检查关键词
                if (keyword != null && !line.contains(keyword)) {
                    continue;
                }
                
                result.add(line);
            }
        }
    }
    
    // 从日志行中提取特定值
    private static String extractValue(String line, Pattern pattern) {
        Matcher matcher = pattern.matcher(line);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "";
    }
    
    /**
     * 获取所有可用的大类
     * 
     * @return 大类列表
     */
    public static List<String> getAllMajorCategories() {
        File baseDir = new File(LOG_BASE_DIR);
        if (!baseDir.exists()) {
            return Collections.emptyList();
        }
        
        File[] majorDirs = baseDir.listFiles(File::isDirectory);
        if (majorDirs == null) {
            return Collections.emptyList();
        }
        
        List<String> result = new ArrayList<>();
        for (File dir : majorDirs) {
            if (dir != null && dir.getName() != null) {
                result.add(dir.getName());
            }
        }
        return result;
    }
    
    /**
     * 获取指定大类下的所有小类
     * 
     * @param majorCategory 大类
     * @return 小类列表
     */
    public static List<String> getMinorCategoriesByMajor(String majorCategory) {
        // 检查参数
        if (majorCategory == null || majorCategory.isEmpty()) {
            return Collections.emptyList();
        }
        
        File majorDir = new File(LOG_BASE_DIR + File.separator + majorCategory);
        if (!majorDir.exists()) {
            return Collections.emptyList();
        }
        
        File[] minorDirs = majorDir.listFiles(File::isDirectory);
        if (minorDirs == null) {
            return Collections.emptyList();
        }
        
        List<String> result = new ArrayList<>();
        for (File dir : minorDirs) {
            if (dir != null && dir.getName() != null) {
                result.add(dir.getName());
            }
        }
        return result;
    }
    
    /**
     * 获取所有记录过的IP地址
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return IP地址集合
     */
    public static Set<String> getUniqueIPs(String majorCategory, String minorCategory) {
        return EnhancedLogManager.getUniqueIPs(majorCategory, minorCategory);
    }
    
    /**
     * 获取所有记录过的MAC地址
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return MAC地址集合
     */
    public static Set<String> getUniqueMACs(String majorCategory, String minorCategory) {
        return EnhancedLogManager.getUniqueMACs(majorCategory, minorCategory);
    }
    
    /**
     * 获取所有记录过的HWID
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return HWID集合
     */
    public static Set<String> getUniqueHWIDs(String majorCategory, String minorCategory) {
        return EnhancedLogManager.getUniqueHWIDs(majorCategory, minorCategory);
    }
    
    /**
     * 获取所有记录过的账号
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return 账号集合
     */
    public static Set<String> getUniqueAccounts(String majorCategory, String minorCategory) {
        return EnhancedLogManager.getUniqueAccounts(majorCategory, minorCategory);
    }
    
    /**
     * 获取所有记录过的角色ID
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return 角色ID集合
     */
    public static Set<String> getUniqueCharacterIds(String majorCategory, String minorCategory) {
        return EnhancedLogManager.getUniqueCharacterIds(majorCategory, minorCategory);
    }
}