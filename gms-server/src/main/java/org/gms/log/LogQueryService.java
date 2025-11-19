package org.gms.log;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 日志查询服务类
 * 提供日志文件查询功能
 */
public class LogQueryService {
    
    private static final String LOG_BASE_DIR = "logs/custom";
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    
    /**
     * 根据条件查询日志
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @param startDate 开始日期
     * @param endDate 结束日期
     * @param keyword 关键词
     * @param ip IP地址
     * @param mac MAC地址
     * @param hwid 硬件ID
     * @param account 账号
     * @param character 角色名
     * @return 符合条件的日志行
     */
    public static List<String> queryLogsWithDetails(String majorCategory, String minorCategory,
                                                    String startDate, String endDate,
                                                    String keyword, String ip, String mac, String hwid,
                                                    String account, String character) {
        try {
            // 检查必要参数
            if (majorCategory == null || minorCategory == null || 
                majorCategory.isEmpty() || minorCategory.isEmpty()) {
                return Collections.emptyList();
            }
            
            String logDirPath = LOG_BASE_DIR + File.separator + majorCategory + File.separator + minorCategory;
            File logDir = new File(logDirPath);
            
            if (!logDir.exists()) {
                System.out.println("日志目录不存在: " + logDirPath);
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
                        
//                        System.out.println("检查文件: " + fileName);
                        
                        // 检查日期范围
                        if ((startDate != null && !startDate.isEmpty()) || (endDate != null && !endDate.isEmpty())) {
                            // 移除 .log 后缀以进行比较
                            String datePart = fileName.substring(0, fileName.length() - 4);
//                            System.out.println("比较日期: " + datePart + " 与范围 " + startDate + " - " + endDate);
                            
                            boolean afterStart = startDate == null || startDate.isEmpty() || compareDate(datePart, startDate) >= 0;
                            boolean beforeEnd = endDate == null || endDate.isEmpty() || compareDate(datePart, endDate) <= 0;
                            
//                            System.out.println("afterStart: " + afterStart + ", beforeEnd: " + beforeEnd);
                            return afterStart && beforeEnd;
                        }
                        
                        return true;
                    })
                    .sorted()
                    .toList();
                
//                System.out.println("找到日志文件数量: " + logFiles.size());
                readLogFilesWithDetails(logFiles, result, keyword, ip, mac, hwid, account, character);
            }
            
//            System.out.println("返回结果数量: " + result.size());
            return result;
        } catch (IOException e) {
            ErrorLogger.logException(null, null, e, "查询日志时发生IO异常");
            return Collections.emptyList();
        }
    }
    
    /**
     * 比较日期字符串
     * 
     * @param date1 日期字符串1 (yyyy-MM-dd)
     * @param date2 日期字符串2 (yyyy-MM-dd)
     * @return 比较结果
     */
    private static int compareDate(String date1, String date2) {
        // 处理可能的文件扩展名
        if (date1.endsWith(".log")) {
            date1 = date1.substring(0, date1.length() - 4);
        }
        if (date2.endsWith(".log")) {
            date2 = date2.substring(0, date2.length() - 4);
        }
        return date1.compareTo(date2);
    }
    
    /**
     * 读取带详细条件过滤的日志文件内容
     */
    private static void readLogFilesWithDetails(List<Path> logFiles, List<String> result,
                                                String keyword, String ip, String mac, String hwid,
                                                String account, String character) throws IOException {
        for (Path logFile : logFiles) {
            List<String> lines = Files.readAllLines(logFile);
            for (String line : lines) {
                try {
                    // 解析JSON日志行
                    JsonNode rootNode = objectMapper.readTree(line);
                    JsonNode baseInfoNode = rootNode.get("baseInfo");
                    
                    if (baseInfoNode != null) {
                        // 检查IP
                        if (ip != null && !ip.isEmpty()) {
                            JsonNode ipNode = baseInfoNode.get("ip");
                            if (ipNode == null || !ip.equals(ipNode.asText())) {
                                continue;
                            }
                        }
                        
                        // 检查MAC
                        if (mac != null && !mac.isEmpty()) {
                            JsonNode macNode = baseInfoNode.get("mac");
                            if (macNode == null || !mac.equals(macNode.asText())) {
                                continue;
                            }
                        }
                        
                        // 检查HWID
                        if (hwid != null && !hwid.isEmpty()) {
                            JsonNode hwidNode = baseInfoNode.get("hwid");
                            if (hwidNode == null || !hwid.equals(hwidNode.asText())) {
                                continue;
                            }
                        }
                        
                        // 检查账号
                        if (account != null && !account.isEmpty()) {
                            JsonNode accountNode = baseInfoNode.get("account");
                            if (accountNode == null || !account.equals(accountNode.asText())) {
                                continue;
                            }
                        }
                        
                        // 检查角色
                        if (character != null && !character.isEmpty()) {
                            JsonNode characterNode = baseInfoNode.get("character");
                            if (characterNode == null || !character.equals(characterNode.asText())) {
                                continue;
                            }
                        }
                    }
                    
                    // 检查关键词
                    if (keyword != null && !keyword.isEmpty() && !line.contains(keyword)) {
                        continue;
                    }
                    
                    result.add(line);
                } catch (Exception e) {
                    // 如果解析JSON失败，仍然添加原始行（为了保持向后兼容）
                    if (keyword == null || keyword.isEmpty() || line.contains(keyword)) {
                        result.add(line);
                    }
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