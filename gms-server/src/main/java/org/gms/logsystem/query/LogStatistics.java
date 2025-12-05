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

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * 日志统计信息模型
 *
 * @author logs-system
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LogStatistics {
    private int totalCount;                     // 总日志数
    private long startTime;                     // 开始时间戳
    private long endTime;                       // 结束时间戳
    private Map<String, Long> categoryStats;    // 按分类统计
    private Map<String, Long> accountStats;     // 按账号统计

    /**
     * 获取查询时间跨度（秒）
     */
    public long getTimeSpanSeconds() {
        return (endTime - startTime) / 1000;
    }

    /**
     * 获取平均每秒日志数
     */
    public double getLogsPerSecond() {
        long timeSpan = getTimeSpanSeconds();
        return timeSpan > 0 ? (double) totalCount / timeSpan : 0;
    }

    /**
     * 获取分类数量
     */
    public int getCategoryCount() {
        return categoryStats != null ? categoryStats.size() : 0;
    }

    /**
     * 获取账号数量
     */
    public int getAccountCount() {
        return accountStats != null ? accountStats.size() : 0;
    }
}
