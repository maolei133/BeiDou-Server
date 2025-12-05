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
 * 日志记录请求 - 日志记录API的请求参数模型
 *
 * @author logs-system
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LogRecordRequest {
    /**
     * 大类
     */
    private String majorCategory;

    /**
     * 小类
     */
    private String minorCategory;

    /**
     * 日志消息
     */
    private String message;

    /**
     * 自定义数据（JSON格式）
     */
    private String customData;

    /**
     * 日志级别
     */
    private String level;

    /**
     * 账号ID
     */
    private int accountId;

    /**
     * 账号名
     */
    private String accountName;

    /**
     * 角色ID
     */
    private int characterId;

    /**
     * 角色名
     */
    private String characterName;

    /**
     * IP地址
     */
    private String ipAddress;

    /**
     * 地图ID
     */
    private int mapId;

    /**
     * 地图名
     */
    private String mapName;
}
