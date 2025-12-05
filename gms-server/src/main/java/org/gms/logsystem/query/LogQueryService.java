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

package org.gms.logsystem.query;

import com.alibaba.fastjson2.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.config.LogConfig;
import org.gms.logsystem.core.GameLogEntry;
import org.gms.logsystem.formatter.GameLogFormatter;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.*;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 日志查询服务 - 负责从文件中查询和检索日志
 * 支持多条件组合查询、分页、排序等功能
 *
 * @author logs-system
 */
@Slf4j
@Service
public class LogQueryService {
    private final LogConfig logConfig;
    private static final DateTimeFormatter dateFormatter = DateTimeFormatter.ofPattern("yyyyMMdd");

    public LogQueryService(LogConfig logConfig) {
        this.logConfig = logConfig;
    }

    /**
     * 查询日志
     *
     * @param queryRequest 查询条件
     * @return 查询结果
     */
    public LogQueryResult query(LogQueryRequest queryRequest) {
        try {
            List<GameLogEntry> results = new ArrayList<>();

            // 获取查询日期范围的目录
            LocalDate startDate = queryRequest.getStartDate();
            LocalDate endDate = queryRequest.getEndDate();

            for (LocalDate date = startDate; !date.isAfter(endDate); date = date.plusDays(1)) {
                String dateDir = logConfig.getLogDir() + "/" + date.format(dateFormatter);
                Path basePath = Paths.get(dateDir);

                if (Files.exists(basePath)) {
                    // 遍历该日期下的所有日志文件
                    results.addAll(searchInDateDirectory(basePath, queryRequest));
                }
            }

            // 排序
            sortLogs(results, queryRequest);

            // 分页
            LogQueryResult result = new LogQueryResult();
            result.setTotal(results.size());
            result.setPageNum(queryRequest.getPageNum());
            result.setPageSize(queryRequest.getPageSize());

            int start = (queryRequest.getPageNum() - 1) * queryRequest.getPageSize();
            int end = Math.min(start + queryRequest.getPageSize(), results.size());

            if (start < results.size()) {
                result.setLogs(results.subList(start, end));
            } else {
                result.setLogs(new ArrayList<>());
            }

            result.setSuccess(true);
            return result;
        } catch (Exception e) {
            log.error("日志查询失败", e);
            LogQueryResult result = new LogQueryResult();
            result.setSuccess(false);
            result.setMessage("日志查询失败: " + e.getMessage());
            return result;
        }
    }

    /**
     * 在特定日期目录中搜索日志
     */
    private List<GameLogEntry> searchInDateDirectory(Path basePath, LogQueryRequest queryRequest)
            throws IOException {
        List<GameLogEntry> results = new ArrayList<>();

        Files.walkFileTree(basePath, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, java.nio.file.attribute.BasicFileAttributes attrs)
                    throws IOException {
                if (file.getFileName().toString().endsWith(".json")) {
                    try {
                        List<GameLogEntry> entries = readLogsFromFile(file.toFile(), queryRequest);
                        results.addAll(entries);
                    } catch (Exception e) {
                        log.warn("读取日志文件失败: {}", file, e);
                    }
                }
                return FileVisitResult.CONTINUE;
            }
        });

        return results;
    }

    /**
     * 从文件中读取日志并应用过滤条件
     */
    private List<GameLogEntry> readLogsFromFile(File file, LogQueryRequest queryRequest) throws IOException {
        List<GameLogEntry> results = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                try {
                    GameLogEntry entry = GameLogFormatter.parseFromJson(line);

                    // 应用过滤条件
                    if (matchesQuery(entry, queryRequest)) {
                        results.add(entry);
                    }
                } catch (Exception e) {
                    log.warn("解析日志行失败: {}", line, e);
                }
            }
        }

        return results;
    }

    /**
     * 检查日志是否匹配查询条件
     */
    private boolean matchesQuery(GameLogEntry entry, LogQueryRequest queryRequest) {
        // 大类过滤
        if (queryRequest.getMajorCategory() != null
                && !entry.getMajorCategory().equals(queryRequest.getMajorCategory())) {
            return false;
        }

        // 小类过滤
        if (queryRequest.getMinorCategory() != null
                && !entry.getMinorCategory().equals(queryRequest.getMinorCategory())) {
            return false;
        }

        // 账号ID过滤
        if (queryRequest.getAccountId() > 0
                && entry.getAccountId() != queryRequest.getAccountId()) {
            return false;
        }

        // 账号名称过滤
        if (queryRequest.getAccountName() != null
                && !entry.getAccountName().contains(queryRequest.getAccountName())) {
            return false;
        }

        // 角色ID过滤
        if (queryRequest.getCharacterId() > 0
                && entry.getCharacterId() != queryRequest.getCharacterId()) {
            return false;
        }

        // 角色名称过滤
        if (queryRequest.getCharacterName() != null
                && !entry.getCharacterName().contains(queryRequest.getCharacterName())) {
            return false;
        }

        // 地图ID过滤
        if (queryRequest.getMapId() > 0
                && entry.getMapId() != queryRequest.getMapId()) {
            return false;
        }

        // 地图名称过滤
        if (queryRequest.getMapName() != null
                && !entry.getMapName().contains(queryRequest.getMapName())) {
            return false;
        }

        // 关键词过滤
        if (queryRequest.getKeyword() != null) {
            String keyword = queryRequest.getKeyword().toLowerCase();
            String message = entry.getMessage() != null ? entry.getMessage().toLowerCase() : "";
            if (!message.contains(keyword)) {
                return false;
            }
        }

        // IP过滤
        if (queryRequest.getIpAddress() != null
                && !entry.getIpAddress().equals(queryRequest.getIpAddress())) {
            return false;
        }

        // MAC地址过滤
        if (queryRequest.getMacAddress() != null
                && !entry.getMacAddress().contains(queryRequest.getMacAddress())) {
            return false;
        }

        // 硬件ID过滤
        if (queryRequest.getHardwareId() != null
                && !entry.getHardwareId().equals(queryRequest.getHardwareId())) {
            return false;
        }

        return true;
    }

    /**
     * 对日志列表进行排序
     */
    private void sortLogs(List<GameLogEntry> logs, LogQueryRequest queryRequest) {
        String sortField = queryRequest.getSortField();
        boolean isAsc = "asc".equalsIgnoreCase(queryRequest.getSortOrder());

        Comparator<GameLogEntry> comparator = null;

        if ("timestamp".equals(sortField)) {
            comparator = Comparator.comparingLong(GameLogEntry::getTimestamp);
        } else if ("accountName".equals(sortField)) {
            comparator = Comparator.comparing(e -> e.getAccountName() != null ? e.getAccountName() : "");
        } else if ("characterName".equals(sortField)) {
            comparator = Comparator.comparing(e -> e.getCharacterName() != null ? e.getCharacterName() : "");
        } else if ("message".equals(sortField)) {
            comparator = Comparator.comparing(e -> e.getMessage() != null ? e.getMessage() : "");
        } else {
            // 默认按时间戳降序排列
            comparator = Comparator.comparingLong(GameLogEntry::getTimestamp).reversed();
        }

        if (!isAsc) {
            comparator = comparator.reversed();
        }

        logs.sort(comparator);
    }

    /**
     * 导出日志为CSV格式
     */
    public String exportToCsv(LogQueryRequest queryRequest) {
        try {
            LogQueryResult queryResult = query(queryRequest);

            if (!queryResult.isSuccess() || queryResult.getLogs().isEmpty()) {
                return "";
            }

            StringBuilder csv = new StringBuilder();

            // 写入表头
            csv.append("时间,账号,角色,大类,小类,消息,IP地址,硬件ID,地图\n");

            // 写入数据
            for (GameLogEntry entry : queryResult.getLogs()) {
                csv.append(String.format("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
                        new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(entry.getTimestamp())),
                        entry.getAccountName() != null ? entry.getAccountName() : "",
                        entry.getCharacterName() != null ? entry.getCharacterName() : "",
                        entry.getMajorCategory(),
                        entry.getMinorCategory(),
                        entry.getMessage() != null ? entry.getMessage() : "",
                        entry.getIpAddress() != null ? entry.getIpAddress() : "",
                        entry.getHardwareId() != null ? entry.getHardwareId() : "",
                        entry.getMapName() != null ? entry.getMapName() : ""));
            }

            return csv.toString();
        } catch (Exception e) {
            log.error("导出CSV失败", e);
            return "";
        }
    }

    /**
     * 获取日志统计信息
     */
    public LogStatistics getStatistics(LogQueryRequest queryRequest) {
        try {
            LogQueryResult queryResult = query(queryRequest);
            LogStatistics stats = new LogStatistics();

            if (!queryResult.getLogs().isEmpty()) {
                stats.setTotalCount(queryResult.getTotal());

                // 分类统计
                Map<String, Long> categoryStats = queryResult.getLogs().stream()
                        .collect(Collectors.groupingBy(
                                e -> e.getMajorCategory() + "." + e.getMinorCategory(),
                                Collectors.counting()
                        ));
                stats.setCategoryStats(categoryStats);

                // 账号统计
                Map<String, Long> accountStats = queryResult.getLogs().stream()
                        .collect(Collectors.groupingBy(
                                e -> e.getAccountName() != null ? e.getAccountName() : "unknown",
                                Collectors.counting()
                        ));
                stats.setAccountStats(accountStats);

                // 获取时间范围
                List<GameLogEntry> sorted = queryResult.getLogs().stream()
                        .sorted(Comparator.comparingLong(GameLogEntry::getTimestamp))
                        .collect(Collectors.toList());

                if (!sorted.isEmpty()) {
                    stats.setStartTime(sorted.get(0).getTimestamp());
                    stats.setEndTime(sorted.get(sorted.size() - 1).getTimestamp());
                }
            }

            return stats;
        } catch (Exception e) {
            log.error("获取统计信息失败", e);
            return new LogStatistics();
        }
    }
}
