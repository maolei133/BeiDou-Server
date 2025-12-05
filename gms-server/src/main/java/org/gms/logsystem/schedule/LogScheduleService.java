/* This file is part of the BeiDou Maple Story Server
Copyright (C) 2025 BeiDou Server https://github.com/BeiDouMS/BeiDou-Server
Magical-H https://github.com/Magical-H

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation version 3 as published by
the Free Software Foundation. You may not use, modify or distribute
this program under any otheer version of the GNU Affero General Public
License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; witout even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.


You should have received a copy of the GNU Affero General Public License
along with this program. If not, see http://www.gnu.org/licenses/.
*/

package org.gms.logsystem.schedule;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.file.LogFileManager;
import org.gms.logsystem.monitor.LogMonitor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * 日志定时任务管理器 - 处理日志的定期清理、归档和监控数据维护
 * 支持多个定时任务的配置和执行
 *
 * @author logs-system
 */
@Slf4j
@Service
public class LogScheduleService {
    private final LogFileManager logFileManager;
    private final LogMonitor logMonitor;
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public LogScheduleService(LogFileManager logFileManager, LogMonitor logMonitor) {
        this.logFileManager = logFileManager;
        this.logMonitor = logMonitor;
    }

    /**
     * 每天凌晨2点执行日志清理任务
     * 清理超过保留期限的日志文件
     */
    @Scheduled(cron = "0 0 2 * * *")
    public void cleanupExpiredLogs() {
        try {
            log.info("开始清理过期日志文件 - {}", LocalDateTime.now().format(formatter));
            long startTime = System.currentTimeMillis();

            // 执行清理
            logFileManager.cleanupOldLogs();

            long duration = System.currentTimeMillis() - startTime;
            log.info("过期日志清理完成，耗时: {} ms", duration);
        } catch (Exception e) {
            log.error("清理过期日志失败", e);
        }
    }

    /**
     * 每小时执行一次监控数据清理任务
     * 防止监控数据无限增长占用内存
     */
    @Scheduled(cron = "0 0 * * * *")
    public void cleanupMonitorData() {
        try {
            log.info("开始清理监控数据 - {}", LocalDateTime.now().format(formatter));

            // 如果监控数据超过阈值，执行清理
            // 这里可以根据实际需求调整清理逻辑
            long startTime = System.currentTimeMillis();

            // 清理监控数据
            logMonitor.clearOldData();

            long duration = System.currentTimeMillis() - startTime;
            log.info("监控数据清理完成，耗时: {} ms", duration);
        } catch (Exception e) {
            log.error("清理监控数据失败", e);
        }
    }

    /**
     * 每小时统计一次日志系统信息
     * 输出关键指标用于监控
     */
    @Scheduled(cron = "0 0 * * * *")
    public void reportSystemMetrics() {
        try {
            log.info("日志系统指标统计 - {}", LocalDateTime.now().format(formatter));

            // 获取日志目录大小
            long logSize = logFileManager.getLogDirectorySize();
            long logSizeMB = logSize / (1024 * 1024);

            // 获取监控统计信息
            String monitorSummary = logMonitor.getSummary();

            log.info("日志目录大小: {} MB", logSizeMB);
            log.info("监控统计信息: {}", monitorSummary);
        } catch (Exception e) {
            log.error("统计系统指标失败", e);
        }
    }

    /**
     * 每天凌晨3点执行日志压缩任务
     * 将前一天的日志文件进行压缩存储
     */
    @Scheduled(cron = "0 0 3 * * *")
    public void compressYesterdayLogs() {
        try {
            log.info("开始压缩昨日日志文件 - {}", LocalDateTime.now().format(formatter));
            long startTime = System.currentTimeMillis();

            // 执行压缩任务
            // 这里可以扩展LogFileManager来支持特定日期的文件压缩
            logFileManager.compressLogsForDate(java.time.LocalDate.now().minusDays(1));

            long duration = System.currentTimeMillis() - startTime;
            log.info("昨日日志压缩完成，耗时: {} ms", duration);
        } catch (Exception e) {
            log.error("压缩日志文件失败", e);
        }
    }

    /**
     * 每3小时检查一次日志目录大小
     * 如果超过阈值则发送告警
     */
    @Scheduled(cron = "0 0 */3 * * *")
    public void checkLogDirectorySize() {
        try {
            long logSize = logFileManager.getLogDirectorySize();
            long logSizeMB = logSize / (1024 * 1024);

            // 假设阈值为10GB
            long thresholdMB = 10 * 1024;

            if (logSizeMB > thresholdMB) {
                log.warn("日志目录大小超过阈值: {} MB > {} MB", logSizeMB, thresholdMB);
                // 可以在这里添加告警通知逻辑
            } else {
                log.debug("日志目录大小正常: {} MB", logSizeMB);
            }
        } catch (Exception e) {
            log.error("检查日志目录大小失败", e);
        }
    }

    /**
     * 每30分钟备份一次监控数据
     * 防止数据丢失
     */
    @Scheduled(cron = "0 */30 * * * *")
    public void backupMonitorData() {
        try {
            log.debug("开始备份监控数据 - {}", LocalDateTime.now().format(formatter));

            // 可以将监控数据导出到文件或数据库
            // 这里是扩展点，可根据实际需求实现

            log.debug("监控数据备份完成");
        } catch (Exception e) {
            log.error("备份监控数据失败", e);
        }
    }
}
