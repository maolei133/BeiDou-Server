package org.gms.logsystem.rest;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.query.LogQueryRequest;
import org.gms.logsystem.query.LogQueryResult;
import org.gms.logsystem.query.LogQueryService;
import org.gms.logsystem.query.LogStatistics;
import org.gms.model.dto.ResultBody;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 日志查询REST API控制器
 * 提供日志查询、导出和统计功能
 */
@Slf4j
@RestController("logSystemLogQueryController")
@RequestMapping("/logsystem/logs")
public class LogQueryController {

    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final LogQueryService logQueryService;

    public LogQueryController(LogQueryService logQueryService) {
        this.logQueryService = logQueryService;
    }

    /**
     * 查询日志
     */
    @PostMapping("/query")
    public ResultBody<LogQueryResult> queryLogs(@RequestBody LogQueryRequest request) {
        // 设置默认日期范围
        if (request.getStartDate() == null) {
            request.setStartDate(LocalDate.now().minusDays(7));
        }
        if (request.getEndDate() == null) {
            request.setEndDate(LocalDate.now());
        }
        if (request.getPageNum() <= 0) {
            request.setPageNum(1);
        }
        if (request.getPageSize() <= 0) {
            request.setPageSize(20);
        }

        LogQueryResult result = logQueryService.query(request);
        if (result.isSuccess()) {
            return ResultBody.success(result);
        } else {
            throw new RuntimeException(result.getMessage());
        }
    }

    /**
     * 获取日志统计信息
     */
    @PostMapping("/statistics")
    public ResultBody<LogStatistics> getStatistics(@RequestBody LogQueryRequest request) {
        // 设置默认日期范围
        if (request.getStartDate() == null) {
            request.setStartDate(LocalDate.now().minusDays(7));
        }
        if (request.getEndDate() == null) {
            request.setEndDate(LocalDate.now());
        }

        LogStatistics stats = logQueryService.getStatistics(request);
        return ResultBody.success(stats);
    }

    /**
     * 导出日志为CSV
     */
    @PostMapping("/export/csv")
    public ResponseEntity<byte[]> exportCsv(@RequestBody LogQueryRequest request) {
        // 设置默认日期范围
        if (request.getStartDate() == null) {
            request.setStartDate(LocalDate.now().minusDays(7));
        }
        if (request.getEndDate() == null) {
            request.setEndDate(LocalDate.now());
        }
        // 导出时获取更多数据
        if (request.getPageSize() <= 0) {
            request.setPageSize(10000);
        }

        String csv = logQueryService.exportToCsv(request);
        byte[] csvBytes = csv.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        String filename = "logs_" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss")) + ".csv";

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + filename)
                .contentType(MediaType.parseMediaType("text/csv; charset=UTF-8"))
                .body(csvBytes);
    }

    /**
     * 获取最近日志（快速查询接口）
     */
    @GetMapping("/recent")
    public ResultBody<LogQueryResult> getRecentLogs(
            @RequestParam(defaultValue = "20") int limit,
            @RequestParam(required = false) String category) {
        LogQueryRequest request = LogQueryRequest.builder()
                .startDate(LocalDate.now())
                .endDate(LocalDate.now())
                .majorCategory(category)
                .pageNum(1)
                .pageSize(limit)
                .sortField("timestamp")
                .sortOrder("desc")
                .build();

        LogQueryResult result = logQueryService.query(request);
        return ResultBody.success(result);
    }

    /**
     * 按关键词搜索日志
     */
    @GetMapping("/search")
    public ResultBody<LogQueryResult> searchLogs(
            @RequestParam String keyword,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int size) {
        LogQueryRequest request = LogQueryRequest.builder()
                .startDate(LocalDate.now().minusDays(7))
                .endDate(LocalDate.now())
                .keyword(keyword)
                .pageNum(page)
                .pageSize(size)
                .build();

        LogQueryResult result = logQueryService.query(request);
        return ResultBody.success(result);
    }

    /**
     * 获取查询状态
     */
    @GetMapping("/status")
    public ResultBody<Map<String, Object>> getQueryStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("available", true);
        status.put("timestamp", LocalDateTime.now().format(formatter));
        return ResultBody.success(status);
    }
}
