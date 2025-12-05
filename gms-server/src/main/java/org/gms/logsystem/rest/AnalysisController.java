package org.gms.logsystem.rest;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.analysis.LogAnalysisService;
import org.gms.logsystem.query.LogQueryRequest;
import org.gms.logsystem.query.LogQueryService;
import org.gms.logsystem.query.LogStatistics;
import org.gms.model.dto.ResultBody;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * 日志分析REST API控制器
 * 提供日志分析和统计功能
 */
@Slf4j
@RestController("logSystemAnalysisController")
@RequestMapping("/logsystem/analysis")
public class AnalysisController {

    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final LogAnalysisService analysisService;
    private final LogQueryService queryService;

    public AnalysisController(LogAnalysisService analysisService, LogQueryService queryService) {
        this.analysisService = analysisService;
        this.queryService = queryService;
    }

    /**
     * 获取日志统计概览
     */
    @GetMapping("/overview")
    public ResultBody<Map<String, Object>> getOverview(
            @RequestParam(defaultValue = "7") int days) {
        Map<String, Object> result = new LinkedHashMap<>();
        
        LogQueryRequest request = LogQueryRequest.builder()
                .startDate(LocalDate.now().minusDays(days))
                .endDate(LocalDate.now())
                .pageNum(1)
                .pageSize(1)
                .build();
        LogStatistics stats = queryService.getStatistics(request);
        
        result.put("totalLogs", stats.getTotalCount());
        result.put("categoryStats", stats.getCategoryStats());
        result.put("accountStats", stats.getAccountStats());
        result.put("days", days);
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 获取分类分析
     */
    @GetMapping("/category")
    public ResultBody<Map<String, Object>> getCategoryAnalysis(
            @RequestParam(defaultValue = "7") int days) {
        Map<String, Object> result = new LinkedHashMap<>();
        
        LogQueryRequest request = LogQueryRequest.builder()
                .startDate(LocalDate.now().minusDays(days))
                .endDate(LocalDate.now())
                .pageNum(1)
                .pageSize(1)
                .build();
        LogStatistics stats = queryService.getStatistics(request);
        
        result.put("categoryStats", stats.getCategoryStats() != null ? 
                stats.getCategoryStats() : new HashMap<>());
        result.put("days", days);
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 获取时间趋势分析
     */
    @GetMapping("/trend")
    public ResultBody<Map<String, Object>> getTrendAnalysis(
            @RequestParam(defaultValue = "7") int days) {
        Map<String, Object> result = new LinkedHashMap<>();
        
        List<Map<String, Object>> trend = new ArrayList<>();
        for (int i = days - 1; i >= 0; i--) {
            LocalDate date = LocalDate.now().minusDays(i);
            LogQueryRequest request = LogQueryRequest.builder()
                    .startDate(date)
                    .endDate(date)
                    .pageNum(1)
                    .pageSize(1)
                    .build();
            LogStatistics stats = queryService.getStatistics(request);
            
            Map<String, Object> point = new LinkedHashMap<>();
            point.put("date", date.toString());
            point.put("count", stats.getTotalCount());
            trend.add(point);
        }
        
        result.put("trend", trend);
        result.put("days", days);
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 获取账号活跃度分析
     */
    @GetMapping("/account-activity")
    public ResultBody<Map<String, Object>> getAccountActivity(
            @RequestParam(defaultValue = "7") int days,
            @RequestParam(defaultValue = "10") int limit) {
        Map<String, Object> result = new LinkedHashMap<>();
        
        LogQueryRequest request = LogQueryRequest.builder()
                .startDate(LocalDate.now().minusDays(days))
                .endDate(LocalDate.now())
                .pageNum(1)
                .pageSize(1)
                .build();
        LogStatistics stats = queryService.getStatistics(request);
        
        // 获取账号统计并排序取Top N
        Map<String, Long> accountStats = stats.getAccountStats() != null ?
                stats.getAccountStats() : new HashMap<>();
        
        List<Map.Entry<String, Long>> sorted = new ArrayList<>(accountStats.entrySet());
        sorted.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));
        
        List<Map<String, Object>> topAccounts = new ArrayList<>();
        for (int i = 0; i < Math.min(limit, sorted.size()); i++) {
            Map.Entry<String, Long> entry = sorted.get(i);
            Map<String, Object> account = new LinkedHashMap<>();
            account.put("account", entry.getKey());
            account.put("logCount", entry.getValue());
            account.put("rank", i + 1);
            topAccounts.add(account);
        }
        
        result.put("topAccounts", topAccounts);
        result.put("days", days);
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }
}
