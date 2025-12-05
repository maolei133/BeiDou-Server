package org.gms.logsystem.rest;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.alert.AlertRuleManager;
import org.gms.logsystem.monitor.LogMonitor;
import org.gms.logsystem.monitor.PerformanceAnalyzer;
import org.gms.logsystem.monitor.PerformanceMetricsCollector;
import org.gms.model.dto.ResultBody;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * 监控REST API控制器
 * 提供性能监控、告警和实时数据
 */
@Slf4j
@RestController("logSystemMonitorController")
@RequestMapping("/logsystem/monitor")
public class MonitorController {

    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final LogMonitor logMonitor;
    private final PerformanceAnalyzer performanceAnalyzer;
    private final PerformanceMetricsCollector metricsCollector;
    private final AlertRuleManager alertRuleManager;

    public MonitorController(LogMonitor logMonitor, PerformanceAnalyzer performanceAnalyzer,
                             PerformanceMetricsCollector metricsCollector, AlertRuleManager alertRuleManager) {
        this.logMonitor = logMonitor;
        this.performanceAnalyzer = performanceAnalyzer;
        this.metricsCollector = metricsCollector;
        this.alertRuleManager = alertRuleManager;
    }

    /**
     * 获取性能概览
     */
    @GetMapping("/performance")
    public ResultBody<Map<String, Object>> getPerformanceOverview() {
        Map<String, Object> overview = performanceAnalyzer.getPerformanceOverview();
        overview.put("timestamp", LocalDateTime.now().format(formatter));
        return ResultBody.success(overview);
    }

    /**
     * 获取性能趋势
     */
    @GetMapping("/performance/trend")
    public ResultBody<Map<String, Object>> getPerformanceTrend(
            @RequestParam(defaultValue = "system") String category,
            @RequestParam(defaultValue = "QPS") String metricType,
            @RequestParam(defaultValue = "24") int hours) {
        PerformanceAnalyzer.PerformanceTrend trend = 
                performanceAnalyzer.getPerformanceTrend(category, metricType, hours);
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("category", trend.getCategory());
        result.put("metricType", trend.getMetricType());
        result.put("values", trend.getValues());
        result.put("timestamps", trend.getTimestamps());
        result.put("trend", trend.getTrend());
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 获取QPS排行
     */
    @GetMapping("/ranking/qps")
    public ResultBody<List<PerformanceAnalyzer.PerformanceRank>> getQPSRanking(
            @RequestParam(defaultValue = "10") int limit) {
        List<PerformanceAnalyzer.PerformanceRank> ranks = performanceAnalyzer.getQPSRanking(limit);
        return ResultBody.success(ranks);
    }

    /**
     * 获取延迟排行
     */
    @GetMapping("/ranking/latency")
    public ResultBody<List<PerformanceAnalyzer.PerformanceRank>> getLatencyRanking(
            @RequestParam(defaultValue = "10") int limit) {
        List<PerformanceAnalyzer.PerformanceRank> ranks = performanceAnalyzer.getLatencyRanking(limit);
        return ResultBody.success(ranks);
    }

    /**
     * 获取成功率排行
     */
    @GetMapping("/ranking/success-rate")
    public ResultBody<List<PerformanceAnalyzer.PerformanceRank>> getSuccessRateRanking(
            @RequestParam(defaultValue = "10") int limit) {
        List<PerformanceAnalyzer.PerformanceRank> ranks = performanceAnalyzer.getSuccessRateRanking(limit);
        return ResultBody.success(ranks);
    }

    /**
     * 获取系统信息
     */
    @GetMapping("/system")
    public ResultBody<Map<String, Object>> getSystemInfo() {
        Map<String, Object> info = metricsCollector.getSystemInfo();
        info.put("timestamp", LocalDateTime.now().format(formatter));
        return ResultBody.success(info);
    }

    /**
     * 获取队列状态
     */
    @GetMapping("/queue")
    public ResultBody<Map<String, Object>> getQueueStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        
        LogMonitor.LogStats systemStats = logMonitor.getSystemStats();
        status.put("pending", 0); // 无队列实现时返回0
        status.put("processed", systemStats.getTotalCount().get());
        status.put("failed", systemStats.getFailureCount().get());
        status.put("qps", logMonitor.getSystemQPS());
        status.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(status);
    }

    /**
     * 获取上下文状态
     */
    @GetMapping("/context")
    public ResultBody<Map<String, Object>> getContextStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("activeContexts", 0); // 返回活跃上下文数
        status.put("totalCreated", 0);
        status.put("timestamp", LocalDateTime.now().format(formatter));
        return ResultBody.success(status);
    }

    /**
     * 获取异常检测数据
     */
    @GetMapping("/anomalies")
    public ResultBody<Map<String, Object>> getAnomalies() {
        Map<String, Object> data = performanceAnalyzer.getAnomalyDetectionData();
        data.put("timestamp", LocalDateTime.now().format(formatter));
        return ResultBody.success(data);
    }

    /**
     * 获取告警列表
     */
    @GetMapping("/alerts")
    public ResultBody<Map<String, Object>> getAlerts(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int size) {
        Map<String, Object> result = new LinkedHashMap<>();
        
        List<Map<String, Object>> alerts = new ArrayList<>();
        // 将异常检测结果转换为告警
        List<String> anomalies = performanceAnalyzer.detectAnomalies();
        for (int i = 0; i < anomalies.size(); i++) {
            Map<String, Object> alert = new LinkedHashMap<>();
            alert.put("id", i + 1);
            alert.put("message", anomalies.get(i));
            alert.put("level", anomalies.get(i).contains("[严重]") ? "critical" : "warning");
            alert.put("time", LocalDateTime.now().format(formatter));
            alerts.add(alert);
        }
        
        result.put("alerts", alerts);
        result.put("total", alerts.size());
        result.put("page", page);
        result.put("size", size);
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 获取告警规则
     */
    @GetMapping("/alert-rules")
    public ResultBody<List<Map<String, Object>>> getAlertRules() {
        List<Map<String, Object>> rules = new ArrayList<>();
        
        alertRuleManager.getAllRules().forEach(rule -> {
            Map<String, Object> ruleMap = new LinkedHashMap<>();
            ruleMap.put("id", rule.getId());
            ruleMap.put("name", rule.getRuleName());
            ruleMap.put("enabled", rule.getEnabled());
            ruleMap.put("condition", rule.getConditionType());
            ruleMap.put("threshold", rule.getThreshold());
            ruleMap.put("actionType", rule.getActionType());
            rules.add(ruleMap);
        });
        
        return ResultBody.success(rules);
    }

    /**
     * 创建告警规则
     */
    @PostMapping("/alert-rules")
    public ResultBody<Map<String, Object>> createAlertRule(@RequestBody Map<String, Object> ruleData) {
        org.gms.logsystem.alert.AlertRule rule = org.gms.logsystem.alert.AlertRule.builder()
                .ruleName((String) ruleData.getOrDefault("name", "未命名规则"))
                .conditionType((String) ruleData.getOrDefault("condition", "FailureRate"))
                .threshold(((Number) ruleData.getOrDefault("threshold", 10)).doubleValue())
                .operator((String) ruleData.getOrDefault("operator", ">"))
                .duration(((Number) ruleData.getOrDefault("duration", 60)).intValue())
                .actionType((String) ruleData.getOrDefault("actionType", "LOG"))
                .enabled(true)
                .build();
        
        org.gms.logsystem.alert.AlertRule createdRule = alertRuleManager.createRule(rule);
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("ruleId", createdRule.getId());
        result.put("message", "告警规则创建成功");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 删除告警规则
     */
    @DeleteMapping("/alert-rules/{ruleId}")
    public ResultBody<Map<String, Object>> deleteAlertRule(@PathVariable Long ruleId) {
        boolean success = alertRuleManager.deleteRule(ruleId);
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", success);
        result.put("ruleId", ruleId);
        result.put("message", success ? "告警规则删除成功" : "规则不存在");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 获取分类统计
     */
    @GetMapping("/categories")
    public ResultBody<List<Map<String, Object>>> getCategoryStats() {
        List<Map<String, Object>> categories = new ArrayList<>();
        
        logMonitor.getAllCategoryStats().forEach(stats -> {
            Map<String, Object> category = new LinkedHashMap<>();
            category.put("id", stats.getCategoryId());
            category.put("totalCount", stats.getTotalCount().get());
            category.put("successCount", stats.getSuccessCount().get());
            category.put("failureCount", stats.getFailureCount().get());
            category.put("qps", stats.getQPS(60000));
            category.put("averageLatency", stats.getAverageLatency());
            categories.add(category);
        });
        
        return ResultBody.success(categories);
    }
}
