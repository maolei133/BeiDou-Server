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

package org.gms.logsystem.core;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.config.LogConfig;
import org.gms.logsystem.context.GameLogContext;
import org.gms.logsystem.context.GameLogContextHolder;
import org.gms.logsystem.file.LogFileManager;
import org.gms.logsystem.formatter.GameLogFormatter;
import org.gms.logsystem.alert.LogAlertService;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.*;

/**
 * 高性能日志记录器 - 使用异步处理和队列批处理
 * 支持按性能等级分级处理，提升系统吞吐量
 *
 * @author logs-system
 */
@Slf4j
@Component
public class HighPerformanceLogger {
    private final LogConfig logConfig;
    private final LogFileManager logFileManager;
    private final LogAlertService logAlertService;
    private final ExecutorService executorService;
    private final Map<String, BlockingQueue<GameLogEntry>> levelQueues;

    public HighPerformanceLogger(LogConfig logConfig, LogFileManager logFileManager, 
                                LogAlertService logAlertService) {
        this.logConfig = logConfig;
        this.logFileManager = logFileManager;
        this.logAlertService = logAlertService;
        this.executorService = Executors.newFixedThreadPool(
                logConfig.getAsyncThreadPoolSize(),
                createThreadFactory()
        );
        this.levelQueues = initializeQueues();
        log.info("高性能日志记录器已初始化，日志目录: {}", logConfig.getLogDir());
        initializeProcessors();
    }

    /**
     * 初始化性能等级队列
     */
    private Map<String, BlockingQueue<GameLogEntry>> initializeQueues() {
        Map<String, BlockingQueue<GameLogEntry>> queues = new ConcurrentHashMap<>();
        queues.put("HIGH", new LinkedBlockingQueue<>(logConfig.getHighFreqBufferSize()));
        queues.put("MEDIUM", new LinkedBlockingQueue<>(logConfig.getMediumFreqBufferSize()));
        queues.put("LOW", new LinkedBlockingQueue<>(logConfig.getLowFreqBufferSize()));
        return queues;
    }

    /**
     * 初始化异步处理器
     */
    private void initializeProcessors() {
        // 高频日志处理器
        executorService.submit(() -> processQueue("HIGH", logConfig.getHighFreqFlushInterval()));
        // 中频日志处理器
        executorService.submit(() -> processQueue("MEDIUM", logConfig.getMediumFreqFlushInterval()));
        // 低频日志处理器
        executorService.submit(() -> processQueue("LOW", logConfig.getLowFreqFlushInterval()));
    }

    /**
     * 记录日志（异步）
     */
    public void logAsync(GameLogEntry entry, GameLogContext context) {
        if (!logConfig.isEnabled()) {
            log.debug("[DIAGNOSIS] 日志系统未启用");
            return;
        }

        // 填充上下文信息
        if (context != null) {
            // 封顶级上下文填充logId和timestamp
            if (entry.getLogId() == null || entry.getLogId().isEmpty()) {
                entry.setLogId(context.getContextId());
            }
            if (entry.getTimestamp() <= 0) {
                entry.setTimestamp(context.getCreatedTime());
            }
            
            // 填充玩家信息
            if (entry.getAccountId() <= 0) {
                entry.setAccountId(context.getAccountId());
                entry.setAccountName(context.getAccountName());
            }
            if (entry.getCharacterId() <= 0) {
                entry.setCharacterId(context.getCharacterId());
                entry.setCharacterName(context.getCharacterName());
            }
            if (entry.getIpAddress() == null) {
                entry.setIpAddress(context.getIpAddress());
            }
            if (entry.getMacAddress() == null) {
                entry.setMacAddress(context.getMacAddress());
            }
            if (entry.getHardwareId() == null) {
                entry.setHardwareId(context.getHardwareId());
            }
            if (entry.getMapId() <= 0) {
                entry.setMapId(context.getMapId());
                entry.setMapName(context.getMapName());
            }
            // 保存context到entry中，不然在formatToJson时就拥失了
            entry.setContext(context);
        }

        String level = entry.getPerformanceLevel();
        BlockingQueue<GameLogEntry> queue = levelQueues.get(level);

        if (queue != null) {
            try {
                boolean offered = queue.offer(entry, 100, TimeUnit.MILLISECONDS);
                if (!offered) {
                    log.warn("[DIAGNOSIS] 日志队列已满，丢弃日志条目: {}. {}", entry.getMajorCategory(), entry.getMinorCategory());
                } else {
//                    log.debug("[DIAGNOSIS] 日志已加入队列[{}]: {}.{}", level, entry.getMajorCategory(), entry.getMinorCategory());
                }
            } catch (InterruptedException e) {
                log.warn("[DIAGNOSIS] 日志队列中断: {}. {}", entry.getMajorCategory(), entry.getMinorCategory());
                Thread.currentThread().interrupt();
            }
        } else {
            log.error("[ERROR] 找不到[{}]性能级别的日志队列", level);
        }
    }

    /**
     * 处理队列中的日志
     */
    private void processQueue(String level, int flushInterval) {
        BlockingQueue<GameLogEntry> queue = levelQueues.get(level);
        List<GameLogEntry> batch = new ArrayList<>();

        while (!Thread.currentThread().isInterrupted()) {
            try {
                // 等待消息或超时
                GameLogEntry entry = queue.poll(flushInterval, TimeUnit.MILLISECONDS);

                if (entry != null) {
                    batch.add(entry);
                }

                // 批量处理或超时时处理
                if (!batch.isEmpty() && (entry == null || batch.size() >= getBatchSize(level))) {
                    processBatch(batch, level);
                    batch.clear();
                }
            } catch (InterruptedException e) {
                log.info("{}频日志处理器已停止", level);
                // 处理剩余的日志
                if (!batch.isEmpty()) {
                    processBatch(batch, level);
                }
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    /**
     * 批量处理日志
     */
    private void processBatch(List<GameLogEntry> batch, String level) {
        try {
//            log.debug("[DIAGNOSIS] 开始批量处理日志，数量: {}", batch.size());
            for (GameLogEntry entry : batch) {
                String jsonLog = GameLogFormatter.formatToJson(entry, entry.getContext());
                // 文件输出 - 不允许失败
                try {
                    if (logFileManager != null) {
//                        log.debug("[DIAGNOSIS] 调用logFileManager.writeLog()");
                        logFileManager.writeLog(entry, jsonLog);
//                        log.debug("[DIAGNOSIS] 文件写入完成");
                    } else {
                        log.error("[ERROR] logFileManager 为 null!");
                    }
                } catch (Exception fileError) {
                    log.error("[ERROR] 文件写入失败: {}", fileError.getMessage(), fileError);
                }
                
//                log.debug("[DIAGNOSIS] 日志处理完成: {} - {}.{}", level, entry.getMajorCategory(), entry.getMinorCategory());
            }
        } catch (Exception e) {
            log.error("[ERROR] 批量处理日志出错", e);
        }
    }

    /**
     * 获取批处理大小
     */
    private int getBatchSize(String level) {
        return switch (level) {
            case "HIGH" -> logConfig.getHighFreqBufferSize() / 4;
            case "MEDIUM" -> logConfig.getMediumFreqBufferSize() / 4;
            case "LOW" -> logConfig.getLowFreqBufferSize() / 4;
            default -> 256;
        };
    }

    /**
     * 创建线程工厂
     */
    private ThreadFactory createThreadFactory() {
        return r -> {
            Thread t = new Thread(r);
            t.setName("LogsProcessor-" + System.identityHashCode(t));
            t.setDaemon(false);  // 改为非守护线程，确保日志处理完毕
            return t;
        };
    }

    /**
     * 获取队列大小
     */
    public int getQueueSize(String level) {
        BlockingQueue<GameLogEntry> queue = levelQueues.get(level);
        return queue != null ? queue.size() : 0;
    }

    /**
     * 强制同步写入（用于紧急情形）
     */
    public void logSyncForce(GameLogEntry entry) {
        if (!logConfig.isEnabled() || logFileManager == null) {
            log.warn("强制同步写失败，应未启用或logFileManager不存在");
            return;
        }
        try {
            String jsonLog = GameLogFormatter.formatSimple(entry);
            logFileManager.writeLog(entry, jsonLog);
//            log.info("[SYNC] 日志已强制同步写入: {}.{}", entry.getMajorCategory(), entry.getMinorCategory());
        } catch (Exception e) {
            log.error("[紧急同步写失败] {}.{}", entry.getMajorCategory(), entry.getMinorCategory(), e);
        }
    }

    /**
     * 关闭日志记录器
     */
    public void shutdown() {
        log.info("========== 警告：日志记录器即将关闭");
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(10, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
            log.info("高性能日志记录器已关闭");
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
