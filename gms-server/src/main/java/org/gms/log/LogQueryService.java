package org.gms.log;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toList;

/**
 * 日志查询服务类
 * 为后台管理系统提供日志查询功能
 */
public class LogQueryService {
    
    private static final String LOG_BASE_DIR = "logs/custom";
    
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
            // 检查必要参数
            if (majorCategory == null || minorCategory == null) {
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
            if (majorCategory == null || minorCategory == null || keyword == null) {
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
}