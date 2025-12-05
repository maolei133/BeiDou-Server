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
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.LocalDate;

/**
 * 日志查询请求模型
 *
 * @author logs-system
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LogQueryRequest {
    // 查询条件
    private String majorCategory;       // 日志大类
    private String minorCategory;       // 日志小类
    private int accountId;              // 账号ID
    private String accountName;         // 账号名称
    private int characterId;            // 角色ID
    private String characterName;       // 角色名称
    private int characterLevel;         // 角色等级
    private int jobId;                  // 职业ID
    private String jobName;             // 职业名称
    private int channelId;              // 频道ID
    private String keyword;             // 关键词
    private String ipAddress;           // IP地址
    private String hardwareId;          // 硬件ID
    private String macAddress;          // MAC地址
    private int mapId;                  // 地图ID
    private String mapName;             // 地图名称
    private String level;               // 日志级别 (INFO/WARN/ERROR)
    private String performanceLevel;    // 性能等级 (HIGH/MEDIUM/LOW)
    private LocalDate startDate;        // 开始日期
    private LocalDate endDate;          // 结束日期

    // 分页参数
    @Builder.Default
    private int pageNum = 1;            // 页码
    @Builder.Default
    private int pageSize = 20;          // 每页条数

    // 排序参数
    @Builder.Default
    private String sortField = "timestamp";  // 排序字段
    @Builder.Default
    private String sortOrder = "desc";       // 排序顺序 (asc/desc)

    /**
     * 验证查询参数
     */
    public boolean validate() {
        // 页码和每页条数验证
        if (pageNum < 1 || pageSize < 1 || pageSize > 1000) {
            return false;
        }

        // 日期范围验证
        if (startDate != null && endDate != null && startDate.isAfter(endDate)) {
            return false;
        }

        return true;
    }
    
    /**
     * 转换为JSON字符串
     */
    public String toJsonString() {
        try {
            ObjectMapper mapper = new ObjectMapper();
            return mapper.writeValueAsString(this);
        } catch (Exception e) {
            return this.toString();
        }
    }
}
