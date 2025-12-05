package org.gms.logsystem.rest;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.config.LogConfig;
import org.gms.logsystem.monitor.LogMonitor;
import org.gms.logsystem.monitor.PerformanceAnalyzer;
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
 * 仪表板REST API控制器
 * 提供可视化数据和报告功能
 */
@Slf4j
@RestController("logSystemDashboardController")
@RequestMapping("/logsystem/dashboard")
public class DashboardController {

    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final LogQueryService logQueryService;
    private final LogConfig logConfig;
    private final PerformanceAnalyzer performanceAnalyzer;
    private final LogMonitor logMonitor;

    public DashboardController(LogQueryService logQueryService, LogConfig logConfig,
                               PerformanceAnalyzer performanceAnalyzer, LogMonitor logMonitor) {
        this.logQueryService = logQueryService;
        this.logConfig = logConfig;
        this.performanceAnalyzer = performanceAnalyzer;
        this.logMonitor = logMonitor;
    }

    /**
     * 获取仪表板总览数据
     */
    @GetMapping("/overview")
    public ResultBody<Map<String, Object>> getDashboardOverview() {
        Map<String, Object> overview = new LinkedHashMap<>();

        // 获取今日日志统计
        LogQueryRequest todayRequest = LogQueryRequest.builder()
                .startDate(LocalDate.now())
                .endDate(LocalDate.now())
                .pageNum(1)
                .pageSize(1)
                .build();
        LogStatistics todayStats = logQueryService.getStatistics(todayRequest);

        // 获取昨日日志统计
        LogQueryRequest yesterdayRequest = LogQueryRequest.builder()
                .startDate(LocalDate.now().minusDays(1))
                .endDate(LocalDate.now().minusDays(1))
                .pageNum(1)
                .pageSize(1)
                .build();
        LogStatistics yesterdayStats = logQueryService.getStatistics(yesterdayRequest);

        // 获取过去7天日志统计
        LogQueryRequest weekRequest = LogQueryRequest.builder()
                .startDate(LocalDate.now().minusDays(7))
                .endDate(LocalDate.now())
                .pageNum(1)
                .pageSize(1)
                .build();
        LogStatistics weekStats = logQueryService.getStatistics(weekRequest);

        // 获取过去30天日志统计
        LogQueryRequest monthRequest = LogQueryRequest.builder()
                .startDate(LocalDate.now().minusDays(30))
                .endDate(LocalDate.now())
                .pageNum(1)
                .pageSize(1)
                .build();
        LogStatistics monthStats = logQueryService.getStatistics(monthRequest);

        // 关键指标
        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("totalLogs", weekStats.getTotalCount());
        metrics.put("todayLogs", todayStats.getTotalCount());
        metrics.put("yesterdayLogs", yesterdayStats.getTotalCount());
        metrics.put("weekLogs", weekStats.getTotalCount());
        metrics.put("monthLogs", monthStats.getTotalCount());
        metrics.put("averageLogsPerDay", weekStats.getTotalCount() / 7);
        
        // 计算环比增长
        long todayChange = todayStats.getTotalCount() - yesterdayStats.getTotalCount();
        double changeRate = yesterdayStats.getTotalCount() > 0 ? 
                (double) todayChange / yesterdayStats.getTotalCount() * 100 : 0;
        metrics.put("todayChange", todayChange);
        metrics.put("changeRate", String.format("%.2f%%", changeRate));
        
        overview.put("metrics", metrics);

        // 分类统计
        overview.put("categoryStats", todayStats.getCategoryStats() != null ? 
                todayStats.getCategoryStats() : new HashMap<>());

        // 日志级别统计 - 简化版本
        Map<String, Object> levelStats = new LinkedHashMap<>();
        levelStats.put("INFO", 0);
        levelStats.put("WARN", 0);
        levelStats.put("ERROR", 0);
        levelStats.put("DEBUG", 0);
        overview.put("levelStats", levelStats);

        // 最近日志趋势（7天）
        List<Map<String, Object>> trendData = new ArrayList<>();
        for (int i = 6; i >= 0; i--) {
            LocalDate date = LocalDate.now().minusDays(i);
            LogQueryRequest request = LogQueryRequest.builder()
                    .startDate(date)
                    .endDate(date)
                    .pageNum(1)
                    .pageSize(1)
                    .build();
            LogStatistics stats = logQueryService.getStatistics(request);
            
            Map<String, Object> point = new LinkedHashMap<>();
            point.put("date", date.toString());
            point.put("count", stats.getTotalCount());
            trendData.add(point);
        }
        overview.put("todayTrend", trendData);

        // 系统健康状态
        Map<String, Object> health = new LinkedHashMap<>();
        health.put("status", logConfig.isEnabled() ? "HEALTHY" : "DISABLED");
        health.put("loggingEnabled", logConfig.isEnabled());
        health.put("logDir", logConfig.getLogDir());
        health.put("retentionDays", logConfig.getLogRetentionDays());
        health.put("compressionEnabled", logConfig.isCompressionEnabled());
        health.put("asyncThreadPoolSize", logConfig.getAsyncThreadPoolSize());
        
        // 获取磁盘使用情况
        try {
            java.io.File logDir = new java.io.File(logConfig.getLogDir());
            if (logDir.exists()) {
                long usableSpace = logDir.getUsableSpace();
                long totalSpace = logDir.getTotalSpace();
                long usedSpace = totalSpace - usableSpace;
                double usagePercent = totalSpace > 0 ? (double) usedSpace / totalSpace * 100 : 0;
                
                health.put("diskUsage", String.format("%.1f%%", usagePercent));
                health.put("diskUsed", formatSize(usedSpace));
                health.put("diskTotal", formatSize(totalSpace));
                health.put("diskFree", formatSize(usableSpace));
            }
        } catch (Exception e) {
            health.put("diskUsage", "N/A");
        }
        overview.put("systemHealth", health);

        // 内存使用情况
        Map<String, Object> memoryStats = new LinkedHashMap<>();
        Runtime runtime = Runtime.getRuntime();
        long maxMemory = runtime.maxMemory();
        long totalMemory = runtime.totalMemory();
        long freeMemory = runtime.freeMemory();
        long usedMemory = totalMemory - freeMemory;
        double memoryUsage = (double) usedMemory / maxMemory * 100;
        
        memoryStats.put("memoryUsage", String.format("%.1f%%", memoryUsage));
        memoryStats.put("memoryUsed", formatSize(usedMemory));
        memoryStats.put("memoryMax", formatSize(maxMemory));
        memoryStats.put("memoryFree", formatSize(freeMemory));
        health.put("memory", memoryStats);

        // 性能概览
        try {
            overview.put("performance", performanceAnalyzer.getPerformanceOverview());
        } catch (Exception e) {
            overview.put("performance", new HashMap<>());
        }

        // 系统信息
        Map<String, Object> systemInfo = new LinkedHashMap<>();
        systemInfo.put("javaVersion", System.getProperty("java.version"));
        systemInfo.put("osName", System.getProperty("os.name"));
        systemInfo.put("osVersion", System.getProperty("os.version"));
        systemInfo.put("processors", Runtime.getRuntime().availableProcessors());
        overview.put("systemInfo", systemInfo);

        overview.put("timestamp", LocalDateTime.now().format(formatter));

        return ResultBody.success(overview);
    }

    /**
     * 格式化文件大小
     */
    private String formatSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        int exp = (int) (Math.log(bytes) / Math.log(1024));
        char unit = "KMGTPE".charAt(exp - 1);
        return String.format("%.1f %sB", bytes / Math.pow(1024, exp), unit);
    }

    /**
     * 获取仪表板小部件数据
     */
    @GetMapping("/widgets")
    public ResultBody<Map<String, Object>> getWidgetData(
            @RequestParam(defaultValue = "all") String widgetType) {
        Map<String, Object> result = new LinkedHashMap<>();
        List<Map<String, Object>> widgets = new ArrayList<>();

        // 日志趋势小部件
        if ("all".equals(widgetType) || "logs".equals(widgetType)) {
            Map<String, Object> widget = new LinkedHashMap<>();
            widget.put("id", "logs-trend");
            widget.put("title", "日志趋势");
            widget.put("type", "line");
            
            // 获取过去7天的日志统计
            List<Map<String, Object>> trendData = new ArrayList<>();
            for (int i = 6; i >= 0; i--) {
                LocalDate date = LocalDate.now().minusDays(i);
                LogQueryRequest request = LogQueryRequest.builder()
                        .startDate(date)
                        .endDate(date)
                        .pageNum(1)
                        .pageSize(1)
                        .build();
                LogStatistics stats = logQueryService.getStatistics(request);
                
                Map<String, Object> point = new LinkedHashMap<>();
                point.put("date", date.toString());
                point.put("count", stats.getTotalCount());
                trendData.add(point);
            }
            widget.put("data", trendData);
            widgets.add(widget);
        }

        // 性能小部件
        if ("all".equals(widgetType) || "performance".equals(widgetType)) {
            Map<String, Object> widget = new LinkedHashMap<>();
            widget.put("id", "performance");
            widget.put("title", "系统性能");
            widget.put("type", "gauge");
            widget.put("data", performanceAnalyzer.getPerformanceOverview());
            widgets.add(widget);
        }

        result.put("widgets", widgets);
        result.put("count", widgets.size());
        result.put("timestamp", LocalDateTime.now().format(formatter));

        return ResultBody.success(result);
    }

    /**
     * 获取报告列表
     */
    @GetMapping("/reports")
    public ResultBody<Map<String, Object>> getReports() {
        Map<String, Object> result = new LinkedHashMap<>();
        List<Map<String, Object>> reports = new ArrayList<>();
        
        // 返回空列表，实际报告功能需要数据库支持
        result.put("reports", reports);
        result.put("count", 0);
        result.put("timestamp", LocalDateTime.now().format(formatter));

        return ResultBody.success(result);
    }
}
