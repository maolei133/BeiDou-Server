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

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 日志事件类 - 表示一个日志事件及其处理状态
 *
 * @author logs-system
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LogEvent {
    /**
     * 事件ID
     */
    private String eventId;

    /**
     * 日志条目
     */
    private GameLogEntry logEntry;

    /**
     * 事件时间戳
     */
    private long eventTime;

    /**
     * 事件类型
     */
    private String eventType;

    /**
     * 事件状态：CREATED(创建), PROCESSED(处理), STORED(已存储), FAILED(失败)
     */
    private String status;

    /**
     * 错误信息（如果发生错误）
     */
    private String errorMessage;

    /**
     * 处理耗时（毫秒）
     */
    private long processingTime;

    /**
     * 来源处理器名称
     */
    private String processorName;

    /**
     * 是否已上报
     */
    private boolean reported;
}
