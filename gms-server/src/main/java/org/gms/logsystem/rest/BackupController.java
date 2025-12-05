package org.gms.logsystem.rest;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.backup.LogBackupService;
import org.gms.model.dto.ResultBody;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 备份管理REST API控制器
 * 提供日志备份和恢复功能
 */
@Slf4j
@RestController("logSystemBackupController")
@RequestMapping("/logsystem/backup")
public class BackupController {

    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final DateTimeFormatter dateFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd");

    private final LogBackupService backupService;

    public BackupController(LogBackupService backupService) {
        this.backupService = backupService;
    }

    /**
     * 获取备份列表
     */
    @GetMapping("/list")
    public ResultBody<Map<String, Object>> listBackups() {
        Map<String, Object> result = new LinkedHashMap<>();
        
        List<LogBackupService.BackupInfo> backups = backupService.listBackups();
        List<Map<String, Object>> backupList = backups.stream()
                .map(this::convertToMap)
                .collect(Collectors.toList());
        
        result.put("backups", backupList);
        result.put("count", backupList.size());
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 创建备份
     */
    @PostMapping("/create")
    public ResultBody<Map<String, Object>> createBackup(@RequestBody Map<String, Object> request) {
        String startDateStr = (String) request.getOrDefault("startDate", LocalDate.now().minusDays(7).toString());
        String endDateStr = (String) request.getOrDefault("endDate", LocalDate.now().toString());
        
        LocalDate startDate = LocalDate.parse(startDateStr);
        LocalDate endDate = LocalDate.parse(endDateStr);
        
        String backupPath = backupService.createBackup(startDate, endDate);
        
        Map<String, Object> result = new LinkedHashMap<>();
        if (backupPath != null) {
            result.put("success", true);
            result.put("backupPath", backupPath);
            result.put("startDate", startDateStr);
            result.put("endDate", endDateStr);
            result.put("message", "备份创建成功");
        } else {
            result.put("success", false);
            result.put("message", "备份创建失败");
        }
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 恢复备份
     */
    @PostMapping("/restore")
    public ResultBody<Map<String, Object>> restoreBackup(@RequestBody Map<String, Object> request) {
        String backupPath = (String) request.get("backupPath");
        
        if (backupPath == null || backupPath.isEmpty()) {
            throw new RuntimeException("备份路径不能为空");
        }
        
        backupService.restoreBackup(backupPath);
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("backupPath", backupPath);
        result.put("message", "备份恢复请求已提交");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 删除备份
     */
    @DeleteMapping
    public ResultBody<Map<String, Object>> deleteBackup(@RequestParam String backupPath) {
        backupService.deleteBackup(backupPath);
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("backupPath", backupPath);
        result.put("message", "备份删除成功");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(result);
    }

    /**
     * 获取备份状态
     */
    @GetMapping("/status")
    public ResultBody<Map<String, Object>> getBackupStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        
        List<LogBackupService.BackupInfo> backups = backupService.listBackups();
        long totalSize = backups.stream().mapToLong(LogBackupService.BackupInfo::getFileSize).sum();
        
        status.put("backupCount", backups.size());
        status.put("totalSize", totalSize);
        status.put("totalSizeStr", formatSize(totalSize));
        status.put("latestBackup", backups.isEmpty() ? null : convertToMap(backups.get(0)));
        status.put("timestamp", LocalDateTime.now().format(formatter));
        
        return ResultBody.success(status);
    }

    /**
     * 转换BackupInfo为Map
     */
    private Map<String, Object> convertToMap(LogBackupService.BackupInfo backup) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("fileName", backup.getFileName());
        map.put("filePath", backup.getFilePath());
        map.put("fileSize", backup.getFileSize());
        map.put("fileSizeStr", backup.getFileSizeStr());
        map.put("createTime", backup.getCreateTime());
        map.put("createTimeStr", backup.getCreateTimeStr());
        return map;
    }

    /**
     * 格式化文件大小
     */
    private String formatSize(long size) {
        if (size < 1024) return size + " B";
        if (size < 1024 * 1024) return (size / 1024) + " KB";
        if (size < 1024 * 1024 * 1024) return (size / (1024 * 1024)) + " MB";
        return (size / (1024 * 1024 * 1024)) + " GB";
    }
}
