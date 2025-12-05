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

package org.gms.logsystem.rest;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 监控数据查询请求 - 用于查询日志监控数据的请求参数
 *
 * @author logs-system
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MonitorQueryRequest {
    /**
     * 查询类型: SYSTEM(系统级), CATEGORY(分类级), ALL(全部)
     */
    private String queryType;

    /**
     * 大类（分类级查询时可选）
     */
    private String majorCategory;

    /**
     * 小类（分类级查询时可选）
     */
    private String minorCategory;

    /**
     * 时间范围：1H(一小时), 1D(一天), 7D(一周), 30D(一月)
     */
    private String timeRange;

    /**
     * 是否包含趋势数据
     */
    private boolean includeTrend;

    /**
     * 排序字段：QPS, LATENCY, COUNT, SUCCESS_RATE
     */
    private String sortBy;

    /**
     * 排序方向：ASC(升序), DESC(降序)
     */
    private String sortDirection;

    /**
     * 返回的最大记录数
     */
    private int limit;
}
