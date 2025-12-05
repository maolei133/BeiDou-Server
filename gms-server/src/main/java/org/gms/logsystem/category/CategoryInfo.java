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

package org.gms.logsystem.category;

import com.alibaba.fastjson2.JSON;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 分类信息实体类 - 存储日志分类的详细信息
 * 包含大类、小类、性能等级等分类相关的元数据
 *
 * @author logs-system
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CategoryInfo {
    /**
     * 分类ID (格式: majorCategory.minorCategory)
     */
    private String categoryId;

    /**
     * 大类名称
     */
    private String majorCategory;

    /**
     * 小类名称
     */
    private String minorCategory;

    /**
     * 分类描述
     */
    private String description;

    /**
     * 性能等级: HIGH(高频), MEDIUM(中频), LOW(低频)
     */
    private String level;

    /**
     * 是否启用
     */
    private boolean enabled;

    /**
     * 是否输出到控制台
     */
    private boolean consoleOutput;

    /**
     * 是否记录到日志文件
     */
    private boolean fileOutput;

    /**
     * 创建时间
     */
    private long createdTime;

    /**
     * 最后修改时间
     */
    private long modifiedTime;

    @Override
    public String toString() {
        return JSON.toJSONString(this);
    }
}
