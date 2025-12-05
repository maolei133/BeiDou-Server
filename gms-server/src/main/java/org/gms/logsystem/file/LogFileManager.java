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

package org.gms.logsystem.file;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.config.LogConfig;
import org.gms.logsystem.core.GameLogEntry;
import org.springframework.stereotype.Component;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.zip.GZIPOutputStream;

/**
 * 日志文件管理器 - 负责日志的持久化和文件管理
 * 支持按日期分组、文件大小限制、压缩和自动清理
 *
 * @author logs-system
 */
@Slf4j
@Component
public class LogFileManager {
    private final LogConfig logConfig;
    private final Map<String, FileWriter> fileWriters = new ConcurrentHashMap<>();
    private final Map<String, ReentrantReadWriteLock> fileLocks = new ConcurrentHashMap<>();
    private final DateTimeFormatter dateFormatter = DateTimeFormatter.ofPattern("yyyyMMdd");
    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    // 文件大小跟踪
    private final Map<String, Long> fileSizes = new ConcurrentHashMap<>();

    public LogFileManager(LogConfig logConfig) {
        this.logConfig = logConfig;
        initializeLogDirectory();
    }

    /**
     * 初始化日志目录
     */
    private void initializeLogDirectory() {
        try {
            String logDir = logConfig.getLogDir();
            Path basePath = Paths.get(logDir);
            Files.createDirectories(basePath);
            log.info("日志目录已初始化: {}", logDir);
        } catch (IOException e) {
            log.error("初始化日志目录失败", e);
        }
    }

    /**
     * 写入日志到文件
     *
     * @param entry 日志条目
     * @param jsonContent 格式化的JSON内容
     */
    public void writeLog(GameLogEntry entry, String jsonContent) {
        if (!logConfig.isEnabled()) {
//            log.debug("日志系统未启用，跳过写入: {}.{}", entry.getMajorCategory(), entry.getMinorCategory());
            return;
        }

        try {
//            log.debug("开始处理日志条目: {}.{}", entry.getMajorCategory(), entry.getMinorCategory());
//            log.debug("JSON内容长度: {}", jsonContent.length());
            String filePath = getLogFilePath(entry.getMajorCategory(), entry.getMinorCategory());
//            log.debug("文件路径: {}", filePath);
            
            // 直接写入，不使用队列锁
            writeToFile(filePath, jsonContent);
            
            // 更新文件大小
            fileSizes.put(filePath, fileSizes.getOrDefault(filePath, 0L) + jsonContent.getBytes().length);
//            log.debug("文件大小更新完成");
        } catch (Exception e) {
            log.error("写入日志文件失败 - 严重错误: {}.{}", entry.getMajorCategory(), entry.getMinorCategory(), e);
        }
    }

    /**
     * 获取日志文件路径
     */
    private String getLogFilePath(String majorCategory, String minorCategory) {
        String date = LocalDate.now().format(dateFormatter);
        String logDir = logConfig.getLogDir();
        String categoryDir = logDir + File.separator + date + File.separator + majorCategory + File.separator + minorCategory;

        try {
            Path dirPath = Paths.get(categoryDir);
            Files.createDirectories(dirPath);
//            log.info("日志目录已成功创建: {}", categoryDir);
        } catch (IOException e) {
            log.error("严重错误[日志目录创建失败] {}", categoryDir, e);
            throw new RuntimeException("不能创建日志目录: " + categoryDir, e);
        }

        return categoryDir + File.separator + "logs.json";
    }

    /**
     * 检查是否需要轮转文件
     */
    private boolean shouldRotate(String filePath) throws IOException {
        long maxSize = logConfig.getFileSizeMB() * 1024 * 1024;
        long currentSize = fileSizes.getOrDefault(filePath, 0L);

        if (currentSize >= maxSize) {
            return true;
        }

        // 也检查实际文件大小
        Path path = Paths.get(filePath);
        if (Files.exists(path)) {
            return Files.size(path) >= maxSize;
        }

        return false;
    }

    /**
     * 轮转日志文件
     */
    private void rotateLogFile(String filePath) throws IOException {
        Path path = Paths.get(filePath);
        if (!Files.exists(path)) {
            return;
        }

        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        String backupPath = filePath.replace(".json", "_" + timestamp + ".json");

        // 重命名当前文件
        Files.move(path, Paths.get(backupPath), StandardCopyOption.REPLACE_EXISTING);

        // 关闭旧的文件写入器
        FileWriter writer = fileWriters.remove(filePath);
        if (writer != null) {
            try {
                writer.close();
            } catch (IOException e) {
                log.warn("关闭文件写入器失败", e);
            }
        }

        // 重置文件大小
        fileSizes.put(filePath, 0L);

        // 如果启用压缩，则压缩备份文件
        if (logConfig.isCompressionEnabled()) {
            compressFile(backupPath, logConfig.getCompressionFormat());
        }

        log.info("日志文件已轮转: {} -> {}", filePath, backupPath);
    }

    /**
     * 写入内容到文件
     */
    private void writeToFile(String filePath, String content) throws IOException {
        try {
            // 立即写入磁盘，不使用缓冲
            java.io.PrintWriter writer = new java.io.PrintWriter(
                new java.io.FileWriter(filePath, true), 
                true  // autoflush = true
            );
            writer.println(content);
            writer.flush();
            writer.close();
//            log.debug("日志已写入磁盘: {}", filePath);
//            log.debug("写入内容长度: {}", content.length());
        } catch (IOException e) {
            log.error("写入文件失败: {} - {}", filePath, e.getMessage());
            throw e;
        }
    }

    /**
     * 压缩文件
     */
    private void compressFile(String filePath, String format) {
        try {
            Path originalPath = Paths.get(filePath);
            if (!Files.exists(originalPath)) {
                return;
            }

            String compressedPath = filePath + "." + format.toLowerCase();

            if ("GZIP".equalsIgnoreCase(format)) {
                try (FileInputStream fis = new FileInputStream(filePath);
                     FileOutputStream fos = new FileOutputStream(compressedPath);
                     GZIPOutputStream gzos = new GZIPOutputStream(fos)) {
                    byte[] buffer = new byte[4096];
                    int len;
                    while ((len = fis.read(buffer)) > 0) {
                        gzos.write(buffer, 0, len);
                    }
                }
            }
            // 其他压缩格式可在此添加

            // 删除原始文件
            Files.delete(originalPath);
            log.info("日志文件已压缩: {}", compressedPath);
        } catch (IOException e) {
            log.warn("压缩日志文件失败", e);
        }
    }

    /**
     * 清理过期日志文件
     */
    public void cleanupOldLogs() {
        try {
            int retentionDays = logConfig.getRetentionDays();
            LocalDate cutoffDate = LocalDate.now().minusDays(retentionDays);

            Path basePath = Paths.get(logConfig.getLogDir());
            if (!Files.exists(basePath)) {
                return;
            }

            // 递归遍历目录
            Files.walkFileTree(basePath, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    // 检查文件日期
                    String fileName = file.getFileName().toString();
                    String parentDir = file.getParent().getFileName().toString();

                    try {
                        LocalDate fileDate = LocalDate.parse(parentDir, dateFormatter);
                        if (fileDate.isBefore(cutoffDate)) {
                            Files.delete(file);
                            log.info("已删除过期日志文件: {}", file);
                        }
                    } catch (Exception e) {
                        // 忽略无法解析的日期格式
                    }

                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                    // 删除空目录
                    try {
                        DirectoryStream<Path> stream = Files.newDirectoryStream(dir);
                        if (!stream.iterator().hasNext()) {
                            Files.delete(dir);
                        }
                        stream.close();
                    } catch (IOException e) {
                        // 忽略删除失败
                    }
                    return FileVisitResult.CONTINUE;
                }
            });

            log.info("日志清理完成，保留期限: {} 天", retentionDays);
        } catch (IOException e) {
            log.error("清理过期日志失败", e);
        }
    }

    /**
     * 获取日志目录大小
     */
    public long getLogDirectorySize() {
        try {
            Path basePath = Paths.get(logConfig.getLogDir());
            if (!Files.exists(basePath)) {
                return 0;
            }

            long[] size = {0};
            Files.walkFileTree(basePath, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    size[0] += attrs.size();
                    return FileVisitResult.CONTINUE;
                }
            });

            return size[0];
        } catch (IOException e) {
            log.warn("获取日志目录大小失败", e);
            return 0;
        }
    }

    /**
     * 关闭所有文件写入器
     */
    public void shutdown() {
        log.info("正在关闭日志文件管理器...");
        for (FileWriter writer : fileWriters.values()) {
            try {
                writer.close();
            } catch (IOException e) {
                log.warn("关闭文件写入器失败", e);
            }
        }
        fileWriters.clear();
        log.info("日志文件管理器已关闭");
    }

    /**
     * 为特定日期的日志文件执行压缩
     */
    public void compressLogsForDate(java.time.LocalDate date) {
        try {
            String dateStr = date.format(dateFormatter);
            String dateDir = logConfig.getLogDir() + "/" + dateStr;
            Path basePath = Paths.get(dateDir);

            if (!Files.exists(basePath)) {
                log.warn("指定日期的日志目录不存在: {}", dateDir);
                return;
            }

            log.info("开始压缩{}日志文件", dateStr);

            // 遍历所有日志文件
            Files.walkFileTree(basePath, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, java.nio.file.attribute.BasicFileAttributes attrs)
                        throws IOException {
                    String fileName = file.getFileName().toString();
                    if (fileName.endsWith(".json") && !fileName.endsWith(".gz")) {
                        compressFile(file.toString(), logConfig.getCompressionFormat());
                    }
                    return FileVisitResult.CONTINUE;
                }
            });

            log.info("{}日志文件压缩完成", dateStr);
        } catch (IOException e) {
            log.error("压缩指定日期的日志失败", e);
        }
    }
}
