package org.gms.controller;

import org.gms.log.LogQueryService;
import org.gms.model.dto.ResultBody;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;

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
     * @return 日志列表
     */
    @GetMapping("/query")
    public ResultBody<List<String>> queryLogs(
            HttpServletRequest request,
            @RequestParam(value = "majorCategory", required = false) String majorCategory,
            @RequestParam(value = "minorCategory", required = false) String minorCategory,
            @RequestParam(value = "startDate", required = false) String startDate,
            @RequestParam(value = "endDate", required = false) String endDate,
            @RequestParam(value = "keyword", required = false) String keyword) {
        
        try {
            List<String> logs;
            if (keyword != null && !keyword.isEmpty()) {
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
}