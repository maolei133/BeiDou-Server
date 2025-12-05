package org.gms.logsystem.rest;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.category.CategoryInfo;
import org.gms.logsystem.category.DynamicCategoryManager;
import org.gms.model.dto.ResultBody;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 分类查询REST API控制器
 * 提供日志分类管理功能
 */
@Slf4j
@RestController("logSystemCategoryController")
@RequestMapping("/logsystem/categories")
public class CategoryQueryController {

    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final DynamicCategoryManager categoryManager;

    public CategoryQueryController(DynamicCategoryManager categoryManager) {
        this.categoryManager = categoryManager;
    }

    /**
     * 获取所有分类
     */
    @GetMapping("/all")
    public ResultBody<Map<String, Object>> getAllCategories() {
        Map<String, Object> result = new LinkedHashMap<>();
        
        Collection<CategoryInfo> categories = categoryManager.getAllCategories();
        List<Map<String, Object>> categoryList = categories.stream()
                .map(this::convertToMap)
                .collect(Collectors.toList());
        
        result.put("categories", categoryList);
        result.put("count", categoryList.size());
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 获取所有大类
     */
    @GetMapping("/major")
    public ResultBody<Map<String, Object>> getMajorCategories() {
        Map<String, Object> result = new LinkedHashMap<>();
        
        Set<String> majorCategories = categoryManager.getAllMajorCategories();
        result.put("majorCategories", majorCategories);
        result.put("count", majorCategories.size());
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 获取指定大类下的所有小类
     */
    @GetMapping("/major/{majorCategory}")
    public ResultBody<Map<String, Object>> getMinorCategories(@PathVariable String majorCategory) {
        Map<String, Object> result = new LinkedHashMap<>();
        
        Collection<CategoryInfo> categories = categoryManager.getCategoriesByMajor(majorCategory);
        List<Map<String, Object>> categoryList = categories.stream()
                .map(this::convertToMap)
                .collect(Collectors.toList());
        
        result.put("majorCategory", majorCategory);
        result.put("minorCategories", categoryList);
        result.put("count", categoryList.size());
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 获取分类详情
     */
    @GetMapping("/{majorCategory}/{minorCategory}")
    public ResultBody<Map<String, Object>> getCategoryDetail(
            @PathVariable String majorCategory,
            @PathVariable String minorCategory) {
        CategoryInfo category = categoryManager.getCategory(majorCategory, minorCategory);
        
        if (category == null) {
            throw new RuntimeException("分类不存在: " + majorCategory + "." + minorCategory);
        }
        
        Map<String, Object> result = convertToMap(category);
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 创建分类
     */
    @PostMapping
    public ResultBody<Map<String, Object>> createCategory(@RequestBody Map<String, Object> categoryData) {
        String majorCategory = (String) categoryData.get("majorCategory");
        String minorCategory = (String) categoryData.get("minorCategory");
        String description = (String) categoryData.getOrDefault("description", "");
        String level = (String) categoryData.getOrDefault("level", "MEDIUM");
        
        if (majorCategory == null || minorCategory == null) {
            throw new RuntimeException("大类和小类名称不能为空");
        }
        
        boolean success = categoryManager.registerCategory(majorCategory, minorCategory, description, level);
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", success);
        result.put("majorCategory", majorCategory);
        result.put("minorCategory", minorCategory);
        result.put("message", success ? "分类创建成功" : "分类已存在");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 更新分类
     */
    @PutMapping("/{majorCategory}/{minorCategory}")
    public ResultBody<Map<String, Object>> updateCategory(
            @PathVariable String majorCategory,
            @PathVariable String minorCategory,
            @RequestBody Map<String, Object> categoryData) {
        
        CategoryInfo category = categoryManager.getCategory(majorCategory, minorCategory);
        if (category == null) {
            throw new RuntimeException("分类不存在: " + majorCategory + "." + minorCategory);
        }
        
        if (categoryData.containsKey("description")) {
            category.setDescription((String) categoryData.get("description"));
        }
        if (categoryData.containsKey("level")) {
            category.setLevel((String) categoryData.get("level"));
        }
        if (categoryData.containsKey("enabled")) {
            category.setEnabled((Boolean) categoryData.get("enabled"));
        }
        if (categoryData.containsKey("consoleOutput")) {
            category.setConsoleOutput((Boolean) categoryData.get("consoleOutput"));
        }
        if (categoryData.containsKey("fileOutput")) {
            category.setFileOutput((Boolean) categoryData.get("fileOutput"));
        }
        
        boolean success = categoryManager.updateCategory(category);
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", success);
        result.put("majorCategory", majorCategory);
        result.put("minorCategory", minorCategory);
        result.put("message", success ? "分类更新成功" : "分类更新失败");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 删除分类
     */
    @DeleteMapping("/{majorCategory}/{minorCategory}")
    public ResultBody<Map<String, Object>> deleteCategory(
            @PathVariable String majorCategory,
            @PathVariable String minorCategory) {
        
        boolean success = categoryManager.unregisterCategory(majorCategory, minorCategory);
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", success);
        result.put("majorCategory", majorCategory);
        result.put("minorCategory", minorCategory);
        result.put("message", success ? "分类删除成功" : "分类不存在或删除失败");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 启用/禁用分类
     */
    @PutMapping("/{majorCategory}/{minorCategory}/enable")
    public ResultBody<Map<String, Object>> setEnabled(
            @PathVariable String majorCategory,
            @PathVariable String minorCategory,
            @RequestParam boolean enabled) {
        
        boolean success = categoryManager.setEnabled(majorCategory, minorCategory, enabled);
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", success);
        result.put("majorCategory", majorCategory);
        result.put("minorCategory", minorCategory);
        result.put("enabled", enabled);
        result.put("message", success ? "状态更新成功" : "分类不存在");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 转换CategoryInfo为Map
     */
    private Map<String, Object> convertToMap(CategoryInfo category) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("majorCategory", category.getMajorCategory());
        map.put("minorCategory", category.getMinorCategory());
        map.put("description", category.getDescription());
        map.put("level", category.getLevel());
        map.put("enabled", category.isEnabled());
        map.put("consoleOutput", category.isConsoleOutput());
        map.put("fileOutput", category.isFileOutput());
        return map;
    }
}
