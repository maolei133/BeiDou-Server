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

package org.gms.logsystem.core;

import com.alibaba.fastjson2.JSON;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.gms.logsystem.context.GameLogContext;

/**
 * 游戏日志实体类 - 表示一条完整的游戏日志记录
 * 包含日志的所有基本信息和上下文数据
 *
 * @author logs-system
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class GameLogEntry {
    /**
     * 日志ID（唯一标识）
     */
    private String logId;

    /**
     * 时间戳
     */
    private long timestamp;

    /**
     * 大类
     */
    private String majorCategory;

    /**
     * 小类
     */
    private String minorCategory;

    /**
     * 日志级别
     */
    private String level;

    /**
     * 日志消息
     */
    private String message;

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
     * MAC地址
     */
    private String macAddress;

    /**
     * 硬件ID
     */
    private String hardwareId;

    /**
     * 地图ID
     */
    private int mapId;

    /**
     * 地图名
     */
    private String mapName;

    /**
     * X坐标
     */
    private int posX;

    /**
     * Y坐标
     */
    private int posY;

    /**
     * 性能等级(HIGH/MEDIUM/LOW)
     */
    private String performanceLevel;

    /**
     * 额外数据（JSON格式）
     */
    private String extraData;

    /**
     * 堆栈跟踪
     */
    private String stackTrace;

    /**
     * 执行耗时（毫秒）
     */
    private long executionTime;

    /**
     * 来源类名
     */
    private String sourceClass;

    /**
     * 来源方法名
     */
    private String sourceMethod;

    /**
     * 来源行号
     */
    private int sourceLine;

    /** 是否为异常日志 */
    private boolean exception;

    /** 游戏日志上下文 */
    private GameLogContext context;

    /**
     * 日志内容转换为JSON字符串
     */
    @Override
    public String toString() {
        return JSON.toJSONString(this);
    }
}
