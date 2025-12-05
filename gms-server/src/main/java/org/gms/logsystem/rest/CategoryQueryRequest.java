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
 * 分类查询请求 - 分类查询API的请求参数模型
 *
 * @author logs-system
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CategoryQueryRequest {
    /**
     * 大类（可选）
     */
    private String majorCategory;

    /**
     * 小类（可选）
     */
    private String minorCategory;

    /**
     * 性能等级过滤（HIGH/MEDIUM/LOW）
     */
    private String level;

    /**
     * 是否已启用过滤
     */
    private Boolean enabled;

    /**
     * 查询模式：ALL(全部), MAJOR(仅大类), DETAIL(详细)
     */
    private String queryMode;
}
