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

package org.gms.logsystem.api;

import org.gms.logsystem.core.GameLogEntry;
import org.gms.logsystem.context.GameLogContext;

/**
 * 日志API接口 - 定义日志系统的公共接口
 * 供业务层调用的简化接口
 *
 * @author logs-system
 */
public interface IGameLogger {
    /**
     * 简单日志记录
     */
    void log(String majorCategory, String minorCategory, String message);

    /**
     * 带上下文的日志记录
     */
    void logWithContext(String majorCategory, String minorCategory, String message, String customData);

    /**
     * 异常日志记录
     */
    void logException(String majorCategory, String minorCategory, String message, Throwable exception);

    /**
     * 批量日志记录
     */
    void logBatch(GameLogEntry... entries);

    /**
     * 获取当前上下文
     */
    GameLogContext getCurrentContext();

    /**
     * 创建新上下文
     */
    GameLogContext createContext();

    /**
     * 设置当前上下文
     */
    void setCurrentContext(GameLogContext context);

    /**
     * 清除当前上下文
     */
    void clearCurrentContext();

    /**
     * 获取队列统计信息
     */
    String getQueueStats();

    /**
     * 获取上下文统计信息
     */
    String getContextStats();
}
