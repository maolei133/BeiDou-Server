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

package org.gms.logsystem.backup;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.config.LogConfig;
import org.gms.logsystem.query.LogQueryRequest;
import org.gms.logsystem.query.LogQueryService;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

@Slf4j
@Service
public class LogBackupService {
    private final LogConfig logConfig;
    private final LogQueryService logQueryService;

    public LogBackupService(LogConfig logConfig, LogQueryService logQueryService) {
        this.logConfig = logConfig;
        this.logQueryService = logQueryService;
    }

    public String createBackup(java.time.LocalDate startDate, java.time.LocalDate endDate) {
        try {
            String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
            String backupFileName = "logs_backup_" + timestamp + ".zip";
            Path backupPath = Paths.get(logConfig.getLogDir()).resolve("backup").resolve(backupFileName);

            Files.createDirectories(backupPath.getParent());

            LogQueryRequest request = LogQueryRequest.builder()
                    .startDate(startDate)
                    .endDate(endDate)
                    .pageSize(10000)
                    .build();

            try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(backupPath))) {
                File logDir = new File(logConfig.getLogDir());
                addDirectoryToZip(logDir, zos, startDate, endDate);
            }

            log.info("日志备份完成: {}", backupPath);
            return backupPath.toString();
        } catch (Exception e) {
            log.error("创建日志备份失败", e);
            return null;
        }
    }

    private void addDirectoryToZip(File dir, ZipOutputStream zos, 
                                  java.time.LocalDate startDate, java.time.LocalDate endDate) throws IOException {
        File[] files = dir.listFiles();
        if (files == null) return;

        for (File file : files) {
            if (file.isDirectory()) {
                addDirectoryToZip(file, zos, startDate, endDate);
            } else {
                String dateStr = file.getParentFile().getName();
                try {
                    java.time.LocalDate fileDate = java.time.LocalDate.parse(dateStr, 
                            java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd"));
                    if (!fileDate.isBefore(startDate) && !fileDate.isAfter(endDate)) {
                        addFileToZip(file, zos);
                    }
                } catch (Exception ignored) {
                }
            }
        }
    }

    private void addFileToZip(File file, ZipOutputStream zos) throws IOException {
        String relativePath = file.getAbsolutePath().replace(logConfig.getLogDir(), "").replaceFirst("^[\\\\/]+", "");
        ZipEntry entry = new ZipEntry(relativePath);
        zos.putNextEntry(entry);

        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = fis.read(buffer)) > 0) {
                zos.write(buffer, 0, len);
            }
        }
        zos.closeEntry();
    }

    public void restoreBackup(String backupFilePath) {
        try {
            Path backupPath = Paths.get(backupFilePath);
            if (!Files.exists(backupPath)) {
                log.error("备份文件不存在: {}", backupFilePath);
                return;
            }

            Path restorePath = Paths.get(logConfig.getLogDir());
            try (ZipInputStream zis = new ZipInputStream(Files.newInputStream(backupPath))) {
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    Path extractPath = restorePath.resolve(entry.getName());
                    if (entry.isDirectory()) {
                        Files.createDirectories(extractPath);
                    } else {
                        Files.createDirectories(extractPath.getParent());
                        try (OutputStream os = Files.newOutputStream(extractPath)) {
                            byte[] buffer = new byte[1024];
                            int len;
                            while ((len = zis.read(buffer)) > 0) {
                                os.write(buffer, 0, len);
                            }
                        }
                    }
                    zis.closeEntry();
                }
            }

            log.info("日志备份恢复完成: {}", backupFilePath);
        } catch (Exception e) {
            log.error("恢复日志备份失败", e);
        }
    }

    public List<BackupInfo> listBackups() {
        List<BackupInfo> backups = new ArrayList<>();
        try {
            Path backupDir = Paths.get(logConfig.getLogDir()).resolve("backup");
            if (!Files.exists(backupDir)) {
                return backups;
            }

            Files.list(backupDir)
                    .filter(path -> path.toString().endsWith(".zip"))
                    .forEach(path -> {
                        try {
                            BackupInfo info = new BackupInfo();
                            info.setFileName(path.getFileName().toString());
                            info.setFilePath(path.toString());
                            info.setFileSize(Files.size(path));
                            info.setCreateTime(Files.getLastModifiedTime(path).toMillis());
                            backups.add(info);
                        } catch (IOException e) {
                            log.warn("获取备份文件信息失败", e);
                        }
                    });

            backups.sort((a, b) -> Long.compare(b.getCreateTime(), a.getCreateTime()));
        } catch (IOException e) {
            log.error("列表备份失败", e);
        }

        return backups;
    }

    public void deleteBackup(String backupFilePath) {
        try {
            Path backupPath = Paths.get(backupFilePath);
            if (Files.deleteIfExists(backupPath)) {
                log.info("备份文件删除成功: {}", backupFilePath);
            }
        } catch (IOException e) {
            log.error("删除备份文件失败", e);
        }
    }

    @Data
    public static class BackupInfo {
        private String fileName;
        private String filePath;
        private long fileSize;
        private long createTime;

        public String getFileSizeStr() {
            long mb = fileSize / (1024 * 1024);
            return mb + " MB";
        }

        public String getCreateTimeStr() {
            return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(createTime));
        }
    }
}
