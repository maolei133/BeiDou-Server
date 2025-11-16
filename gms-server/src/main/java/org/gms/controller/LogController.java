package org.gms.controller;

import org.gms.log.LogQueryService;
import org.gms.model.dto.ResultBody;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Set;

/**
 * 日志管理控制器
 * 提供RESTful API供后台管理系统查询日志
 */
@RestController
@RequestMapping("/api/logs")
public class LogController {
    
    /**
     * 查询指定条件的日志
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
     * @return 日志列表
     */
    @GetMapping("/query")
    public ResultBody<List<String>> queryLogs(
            HttpServletRequest request,
            @RequestParam(value = "majorCategory", required = false) String majorCategory,
            @RequestParam(value = "minorCategory", required = false) String minorCategory,
            @RequestParam(value = "startDate", required = false) String startDate,
            @RequestParam(value = "endDate", required = false) String endDate,
            @RequestParam(value = "keyword", required = false) String keyword,
            @RequestParam(value = "ip", required = false) String ip,
            @RequestParam(value = "mac", required = false) String mac,
            @RequestParam(value = "hwid", required = false) String hwid,
            @RequestParam(value = "account", required = false) String account,
            @RequestParam(value = "character", required = false) String character) {
        
        try {
            List<String> logs;
            // 如果提供了详细筛选条件，则使用详细查询方法
            if (ip != null || mac != null || hwid != null || account != null || character != null) {
                logs = LogQueryService.queryLogsWithDetails(majorCategory, minorCategory, startDate, endDate,
                        ip, mac, hwid, account, character, keyword);
            } else if (keyword != null && !keyword.isEmpty()) {
                logs = LogQueryService.queryLogsWithKeyword(majorCategory, minorCategory, keyword);
            } else {
                logs = LogQueryService.queryLogsByDateRange(majorCategory, minorCategory, startDate, endDate);
            }
            
            return ResultBody.success(logs);
        } catch (Exception e) {
            return ResultBody.error(request, "查询日志时发生错误: " + e.getMessage());
        }
    }
    
    /**
     * 获取所有大类
     * 
     * @return 大类列表
     */
    @GetMapping("/categories/major")
    public ResultBody<List<String>> getAllMajorCategories(HttpServletRequest request) {
        try {
            List<String> categories = LogQueryService.getAllMajorCategories();
            return ResultBody.success(categories);
        } catch (Exception e) {
            return ResultBody.error(request, "获取大类列表时发生错误: " + e.getMessage());
        }
    }
    
    /**
     * 获取指定大类下的所有小类
     * 
     * @param majorCategory 大类
     * @return 小类列表
     */
    @GetMapping("/categories/minor")
    public ResultBody<List<String>> getMinorCategoriesByMajor(
            HttpServletRequest request,
            @RequestParam(value = "majorCategory") String majorCategory) {
        try {
            if (majorCategory == null || majorCategory.isEmpty()) {
                return ResultBody.error(request, "缺少必要参数: 大类不能为空");
            }
            
            List<String> categories = LogQueryService.getMinorCategoriesByMajor(majorCategory);
            return ResultBody.success(categories);
        } catch (Exception e) {
            return ResultBody.error(request, "获取小类列表时发生错误: " + e.getMessage());
        }
    }
    
    /**
     * 获取唯一IP地址列表
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return IP地址列表
     */
    @GetMapping("/unique/ips")
    public ResultBody<Set<String>> getUniqueIPs(
            HttpServletRequest request,
            @RequestParam(value = "majorCategory") String majorCategory,
            @RequestParam(value = "minorCategory") String minorCategory) {
        try {
            if (majorCategory == null || majorCategory.isEmpty() || 
                minorCategory == null || minorCategory.isEmpty()) {
                return ResultBody.error(request, "缺少必要参数: 大类和小类不能为空");
            }
            
            Set<String> ips = LogQueryService.getUniqueIPs(majorCategory, minorCategory);
            return ResultBody.success(ips);
        } catch (Exception e) {
            return ResultBody.error(request, "获取IP地址列表时发生错误: " + e.getMessage());
        }
    }
    
    /**
     * 获取唯一MAC地址列表
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return MAC地址列表
     */
    @GetMapping("/unique/macs")
    public ResultBody<Set<String>> getUniqueMACs(
            HttpServletRequest request,
            @RequestParam(value = "majorCategory") String majorCategory,
            @RequestParam(value = "minorCategory") String minorCategory) {
        try {
            if (majorCategory == null || majorCategory.isEmpty() || 
                minorCategory == null || minorCategory.isEmpty()) {
                return ResultBody.error(request, "缺少必要参数: 大类和小类不能为空");
            }
            
            Set<String> macs = LogQueryService.getUniqueMACs(majorCategory, minorCategory);
            return ResultBody.success(macs);
        } catch (Exception e) {
            return ResultBody.error(request, "获取MAC地址列表时发生错误: " + e.getMessage());
        }
    }
    
    /**
     * 获取唯一HWID列表
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return HWID列表
     */
    @GetMapping("/unique/hwids")
    public ResultBody<Set<String>> getUniqueHWIDs(
            HttpServletRequest request,
            @RequestParam(value = "majorCategory") String majorCategory,
            @RequestParam(value = "minorCategory") String minorCategory) {
        try {
            if (majorCategory == null || majorCategory.isEmpty() || 
                minorCategory == null || minorCategory.isEmpty()) {
                return ResultBody.error(request, "缺少必要参数: 大类和小类不能为空");
            }
            
            Set<String> hwids = LogQueryService.getUniqueHWIDs(majorCategory, minorCategory);
            return ResultBody.success(hwids);
        } catch (Exception e) {
            return ResultBody.error(request, "获取HWID列表时发生错误: " + e.getMessage());
        }
    }
    
    /**
     * 获取唯一账号列表
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return 账号列表
     */
    @GetMapping("/unique/accounts")
    public ResultBody<Set<String>> getUniqueAccounts(
            HttpServletRequest request,
            @RequestParam(value = "majorCategory") String majorCategory,
            @RequestParam(value = "minorCategory") String minorCategory) {
        try {
            if (majorCategory == null || majorCategory.isEmpty() || 
                minorCategory == null || minorCategory.isEmpty()) {
                return ResultBody.error(request, "缺少必要参数: 大类和小类不能为空");
            }
            
            Set<String> accounts = LogQueryService.getUniqueAccounts(majorCategory, minorCategory);
            return ResultBody.success(accounts);
        } catch (Exception e) {
            return ResultBody.error(request, "获取账号列表时发生错误: " + e.getMessage());
        }
    }
    
    /**
     * 获取唯一角色ID列表
     * 
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return 角色ID列表
     */
    @GetMapping("/unique/characterIds")
    public ResultBody<Set<String>> getUniqueCharacterIds(
            HttpServletRequest request,
            @RequestParam(value = "majorCategory") String majorCategory,
            @RequestParam(value = "minorCategory") String minorCategory) {
        try {
            if (majorCategory == null || majorCategory.isEmpty() || 
                minorCategory == null || minorCategory.isEmpty()) {
                return ResultBody.error(request, "缺少必要参数: 大类和小类不能为空");
            }
            
            Set<String> characterIds = LogQueryService.getUniqueCharacterIds(majorCategory, minorCategory);
            return ResultBody.success(characterIds);
        } catch (Exception e) {
            return ResultBody.error(request, "获取角色ID列表时发生错误: " + e.getMessage());
        }
    }
}