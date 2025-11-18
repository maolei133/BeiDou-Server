package org.gms.controller;

import org.gms.log.BaseLogger;
import org.gms.log.LogCategoryDefinition;
import org.gms.log.LogQueryService;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * 日志控制器
 * 提供日志查询和相关数据获取的REST API接口
 */
@RestController
@RequestMapping("/api/logs")
public class LogController {
    
    /**
     * 查询日志
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
     * @return 日志内容列表
     */
    @GetMapping("/query")
    public Map<String, Object> queryLogs(
            @RequestParam(required = false) String majorCategory,
            @RequestParam(required = false) String minorCategory,
            @RequestParam(required = false) String startDate,
            @RequestParam(required = false) String endDate,
            @RequestParam(required = false) String keyword,
            @RequestParam(required = false) String ip,
            @RequestParam(required = false) String mac,
            @RequestParam(required = false) String hwid,
            @RequestParam(required = false) String account,
            @RequestParam(required = false) String character) {
        
        Map<String, Object> result = new HashMap<>();
        
        try {
            List<String> logs = LogQueryService.queryLogsWithDetails(
                majorCategory, minorCategory, startDate, endDate, keyword,
                ip, mac, hwid, account, character);
            
            result.put("code", 20000);
            result.put("message", "success");
            result.put("data", logs);
        } catch (Exception e) {
            result.put("code", 500);
            result.put("message", "查询日志时发生错误: " + e.getMessage());
            result.put("data", new ArrayList<>());
        }
        
        return result;
    }
    
    /**
     * 获取所有大类
     * 
     * @return 大类列表
     */
    @GetMapping("/categories/major")
    public Map<String, Object> getAllMajorCategories() {
        Map<String, Object> result = new HashMap<>();
        try {
            Map<String, String> majorCategories = LogCategoryDefinition.getMajorCategories();
            result.put("code", 20000);
            result.put("message", "success");
            result.put("data", new ArrayList<>(majorCategories.keySet()));
        } catch (Exception e) {
            result.put("code", 500);
            result.put("message", "获取大类列表时发生错误: " + e.getMessage());
            result.put("data", new ArrayList<>());
        }
        return result;
    }
    
    /**
     * 获取指定大类下的所有小类
     * 
     * @param majorCategory 大类
     * @return 小类列表
     */
    @GetMapping("/categories/minor")
    public Map<String, Object> getMinorCategoriesByMajor(
            @RequestParam String majorCategory) {
        Map<String, Object> result = new HashMap<>();
        try {
            Set<String> minorCategories = LogCategoryDefinition.getMinorCategories(majorCategory);
            result.put("code", 20000);
            result.put("message", "success");
            result.put("data", new ArrayList<>(minorCategories));
        } catch (Exception e) {
            result.put("code", 500);
            result.put("message", "获取小类列表时发生错误: " + e.getMessage());
            result.put("data", new ArrayList<>());
        }
        return result;
    }
    
    /**
     * 获取唯一IP列表
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return IP列表
     */
    @GetMapping("/unique/ips")
    public Map<String, Object> getUniqueIPs(
            @RequestParam String majorCategory,
            @RequestParam String minorCategory) {
        Map<String, Object> result = new HashMap<>();
        try {
            Set<String> ips = BaseLogger.getUserDataCache().get("ips");
            result.put("code", 20000);
            result.put("message", "success");
            result.put("data", ips != null ? new ArrayList<>(ips) : new ArrayList<>());
        } catch (Exception e) {
            result.put("code", 500);
            result.put("message", "获取IP列表时发生错误: " + e.getMessage());
            result.put("data", new ArrayList<>());
        }
        return result;
    }
    
    /**
     * 获取唯一MAC列表
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return MAC列表
     */
    @GetMapping("/unique/macs")
    public Map<String, Object> getUniqueMACs(
            @RequestParam String majorCategory,
            @RequestParam String minorCategory) {
        Map<String, Object> result = new HashMap<>();
        try {
            Set<String> macs = BaseLogger.getUserDataCache().get("macs");
            result.put("code", 20000);
            result.put("message", "success");
            result.put("data", macs != null ? new ArrayList<>(macs) : new ArrayList<>());
        } catch (Exception e) {
            result.put("code", 500);
            result.put("message", "获取MAC列表时发生错误: " + e.getMessage());
            result.put("data", new ArrayList<>());
        }
        return result;
    }
    
    /**
     * 获取唯一HWID列表
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return HWID列表
     */
    @GetMapping("/unique/hwids")
    public Map<String, Object> getUniqueHWIDs(
            @RequestParam String majorCategory,
            @RequestParam String minorCategory) {
        Map<String, Object> result = new HashMap<>();
        try {
            Set<String> hwids = BaseLogger.getUserDataCache().get("hwids");
            result.put("code", 20000);
            result.put("message", "success");
            result.put("data", hwids != null ? new ArrayList<>(hwids) : new ArrayList<>());
        } catch (Exception e) {
            result.put("code", 500);
            result.put("message", "获取HWID列表时发生错误: " + e.getMessage());
            result.put("data", new ArrayList<>());
        }
        return result;
    }
    
    /**
     * 获取唯一账号列表
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return 账号列表
     */
    @GetMapping("/unique/accounts")
    public Map<String, Object> getUniqueAccounts(
            @RequestParam String majorCategory,
            @RequestParam String minorCategory) {
        Map<String, Object> result = new HashMap<>();
        try {
            Set<String> accounts = BaseLogger.getUserDataCache().get("accounts");
            result.put("code", 20000);
            result.put("message", "success");
            result.put("data", accounts != null ? new ArrayList<>(accounts) : new ArrayList<>());
        } catch (Exception e) {
            result.put("code", 500);
            result.put("message", "获取账号列表时发生错误: " + e.getMessage());
            result.put("data", new ArrayList<>());
        }
        return result;
    }
    
    /**
     * 获取唯一角色ID列表
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return 角色ID列表
     */
    @GetMapping("/unique/characterIds")
    public Map<String, Object> getUniqueCharacterIds(
            @RequestParam String majorCategory,
            @RequestParam String minorCategory) {
        Map<String, Object> result = new HashMap<>();
        try {
            Set<String> characterIds = BaseLogger.getUserDataCache().get("characterIds");
            result.put("code", 20000);
            result.put("message", "success");
            result.put("data", characterIds != null ? new ArrayList<>(characterIds) : new ArrayList<>());
        } catch (Exception e) {
            result.put("code", 500);
            result.put("message", "获取角色ID列表时发生错误: " + e.getMessage());
            result.put("data", new ArrayList<>());
        }
        return result;
    }
    
    /**
     * 获取用户数据（供前端筛选使用）
     * 
     * @return 用户数据
     */
    @GetMapping("/userdata")
    public Map<String, Object> getUserData() {
        Map<String, Object> result = new HashMap<>();
        try {
            Map<String, Set<String>> userDataCache = BaseLogger.getUserDataCache();
            Map<String, List<String>> userData = new HashMap<>();
            
            for (Map.Entry<String, Set<String>> entry : userDataCache.entrySet()) {
                userData.put(entry.getKey(), new ArrayList<>(entry.getValue()));
            }
            
            result.put("code", 20000);
            result.put("message", "success");
            result.put("data", userData);
        } catch (Exception e) {
            result.put("code", 500);
            result.put("message", "获取用户数据时发生错误: " + e.getMessage());
            result.put("data", new HashMap<>());
        }
        return result;
    }
}