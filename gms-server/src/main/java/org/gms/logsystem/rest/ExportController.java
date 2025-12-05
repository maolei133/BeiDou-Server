package org.gms.logsystem.rest;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.query.LogQueryRequest;
import org.gms.logsystem.query.LogQueryService;
import org.gms.model.dto.ResultBody;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * 导出管理REST API控制器
 * 提供多种格式的日志导出功能
 */
@Slf4j
@RestController("logSystemExportController")
@RequestMapping("/logsystem/export")
public class ExportController {

    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final DateTimeFormatter fileFormatter = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

    private final LogQueryService logQueryService;

    public ExportController(LogQueryService logQueryService) {
        this.logQueryService = logQueryService;
    }

    /**
     * 获取支持的导出格式
     */
    @GetMapping("/formats")
    public ResultBody<Map<String, Object>> getSupportedFormats() {
        Map<String, Object> result = new LinkedHashMap<>();
        
        List<Map<String, Object>> formats = new ArrayList<>();
        formats.add(createFormat("csv", "CSV", "逗号分隔值文件", true));
        formats.add(createFormat("json", "JSON", "JavaScript对象表示法", true));
        formats.add(createFormat("excel", "Excel", "Microsoft Excel格式", false));
        formats.add(createFormat("pdf", "PDF", "可移植文档格式", false));
        
        result.put("formats", formats);
        result.put("count", formats.size());
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 导出为CSV
     */
    @PostMapping("/csv")
    public ResponseEntity<byte[]> exportCsv(@RequestBody LogQueryRequest request) {
        setupDefaultDates(request);
        
        String csv = logQueryService.exportToCsv(request);
        byte[] csvBytes = csv.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        
        String filename = "logs_" + LocalDateTime.now().format(fileFormatter) + ".csv";
        
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + filename)
                .contentType(MediaType.parseMediaType("text/csv; charset=UTF-8"))
                .body(csvBytes);
    }

    /**
     * 导出为JSON
     */
    @PostMapping("/json")
    public ResponseEntity<byte[]> exportJson(@RequestBody LogQueryRequest request) {
        setupDefaultDates(request);
        
        var queryResult = logQueryService.query(request);
        String json = com.alibaba.fastjson2.JSON.toJSONString(queryResult);
        byte[] jsonBytes = json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        
        String filename = "logs_" + LocalDateTime.now().format(fileFormatter) + ".json";
        
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + filename)
                .contentType(MediaType.APPLICATION_JSON)
                .body(jsonBytes);
    }

    /**
     * 获取导出任务列表（异步导出功能）
     */
    @GetMapping("/jobs")
    public ResultBody<Map<String, Object>> getExportJobs() {
        Map<String, Object> result = new LinkedHashMap<>();
        
        // 返回空列表，实际异步导出功能需要任务队列支持
        result.put("jobs", new ArrayList<>());
        result.put("count", 0);
        result.put("message", "异步导出功能需要任务队列支持");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 创建异步导出任务
     */
    @PostMapping("/async")
    public ResultBody<Map<String, Object>> createAsyncExport(@RequestBody Map<String, Object> request) {
        Map<String, Object> result = new LinkedHashMap<>();
        
        // 返回提示信息
        result.put("success", false);
        result.put("message", "异步导出功能尚未实现");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 设置默认日期范围
     */
    private void setupDefaultDates(LogQueryRequest request) {
        if (request.getStartDate() == null) {
            request.setStartDate(LocalDate.now().minusDays(7));
        }
        if (request.getEndDate() == null) {
            request.setEndDate(LocalDate.now());
        }
        if (request.getPageSize() <= 0) {
            request.setPageSize(10000);
        }
    }

    /**
     * 创建格式描述
     */
    private Map<String, Object> createFormat(String id, String name, String description, boolean available) {
        Map<String, Object> format = new LinkedHashMap<>();
        format.put("id", id);
        format.put("name", name);
        format.put("description", description);
        format.put("available", available);
        return format;
    }
}
