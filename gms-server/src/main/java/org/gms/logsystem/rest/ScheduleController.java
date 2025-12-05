package org.gms.logsystem.rest;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.file.LogFileManager;
import org.gms.logsystem.schedule.LogScheduleService;
import org.gms.model.dto.ResultBody;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * 定时任务管理REST API控制器
 * 提供定时任务监控和手动触发功能
 */
@Slf4j
@RestController("logSystemScheduleController")
@RequestMapping("/logsystem/schedule")
public class ScheduleController {

    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final LogScheduleService scheduleService;
    private final LogFileManager logFileManager;

    public ScheduleController(LogScheduleService scheduleService, LogFileManager logFileManager) {
        this.scheduleService = scheduleService;
        this.logFileManager = logFileManager;
    }

    /**
     * 获取定时任务列表
     */
    @GetMapping("/tasks")
    public ResultBody<Map<String, Object>> getTasks() {
        Map<String, Object> result = new LinkedHashMap<>();
        
        List<Map<String, Object>> tasks = new ArrayList<>();
        tasks.add(createTask("cleanup", "日志清理", "0 0 2 * * *", "每天凌晨2点", true));
        tasks.add(createTask("compress", "日志压缩", "0 0 3 * * *", "每天凌晨3点", true));
        tasks.add(createTask("monitor-cleanup", "监控数据清理", "0 0 * * * *", "每小时", true));
        tasks.add(createTask("metrics", "系统指标统计", "0 0 * * * *", "每小时", true));
        tasks.add(createTask("size-check", "目录大小检查", "0 0 */3 * * *", "每3小时", true));
        tasks.add(createTask("backup", "监控数据备份", "0 */30 * * * *", "每30分钟", true));
        
        result.put("tasks", tasks);
        result.put("count", tasks.size());
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 手动触发日志清理
     */
    @PostMapping("/trigger/cleanup")
    public ResultBody<Map<String, Object>> triggerCleanup() {
        long startTime = System.currentTimeMillis();
        scheduleService.cleanupExpiredLogs();
        long duration = System.currentTimeMillis() - startTime;
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("task", "cleanup");
        result.put("duration", duration + "ms");
        result.put("message", "日志清理任务已执行");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 手动触发日志压缩
     */
    @PostMapping("/trigger/compress")
    public ResultBody<Map<String, Object>> triggerCompress() {
        long startTime = System.currentTimeMillis();
        scheduleService.compressYesterdayLogs();
        long duration = System.currentTimeMillis() - startTime;
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("task", "compress");
        result.put("duration", duration + "ms");
        result.put("message", "日志压缩任务已执行");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 手动触发监控数据清理
     */
    @PostMapping("/trigger/monitor-cleanup")
    public ResultBody<Map<String, Object>> triggerMonitorCleanup() {
        long startTime = System.currentTimeMillis();
        scheduleService.cleanupMonitorData();
        long duration = System.currentTimeMillis() - startTime;
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("task", "monitor-cleanup");
        result.put("duration", duration + "ms");
        result.put("message", "监控数据清理任务已执行");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 获取日志目录状态
     */
    @GetMapping("/status")
    public ResultBody<Map<String, Object>> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        
        long logSize = logFileManager.getLogDirectorySize();
        long logSizeMB = logSize / (1024 * 1024);
        
        status.put("logDirectorySize", logSize);
        status.put("logDirectorySizeMB", logSizeMB);
        status.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(status);
    }

    /**
     * 创建任务描述
     */
    private Map<String, Object> createTask(String id, String name, String cron, String schedule, boolean enabled) {
        Map<String, Object> task = new LinkedHashMap<>();
        task.put("id", id);
        task.put("name", name);
        task.put("cron", cron);
        task.put("schedule", schedule);
        task.put("enabled", enabled);
        return task;
    }
}
