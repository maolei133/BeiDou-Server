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
import org.gms.logsystem.core.GameLogEntry;

import java.util.List;

/**
 * 日志查询结果模型
 *
 * @author logs-system
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LogQueryResult {
    private boolean success;            // 查询是否成功
    private String message;             // 错误信息
    private List<GameLogEntry> logs;    // 日志列表
    private int total;                  // 总数
    private int pageNum;                // 当前页码
    private int pageSize;               // 每页条数

    /**
     * 获取总页数
     */
    public int getTotalPages() {
        return (total + pageSize - 1) / pageSize;
    }

    /**
     * 获取是否有下一页
     */
    public boolean hasNextPage() {
        return pageNum < getTotalPages();
    }

    /**
     * 获取是否有上一页
     */
    public boolean hasPreviousPage() {
        return pageNum > 1;
    }
}
