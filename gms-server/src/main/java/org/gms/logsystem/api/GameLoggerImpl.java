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

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.core.GameLogEntry;
import org.gms.logsystem.core.HybridLogger;
import org.gms.logsystem.context.GameLogContext;
import org.gms.logsystem.context.LogContextManager;
import org.springframework.stereotype.Service;

/**
 * 游戏日志API实现 - 向业务层提供统一的日志接口
 * 内部使用HybridLogger进行实际处理
 *
 * @author logs-system
 */
@Slf4j
@Service
public class GameLoggerImpl implements IGameLogger {
    private final HybridLogger hybridLogger;
    private final LogContextManager contextManager;

    public GameLoggerImpl(HybridLogger hybridLogger, LogContextManager contextManager) {
        this.hybridLogger = hybridLogger;
        this.contextManager = contextManager;
    }

    @Override
    public void log(String majorCategory, String minorCategory, String message) {
        hybridLogger.log(majorCategory, minorCategory, message);
    }

    @Override
    public void logWithContext(String majorCategory, String minorCategory, String message, String customData) {
        hybridLogger.logWithContext(majorCategory, minorCategory, message, customData);
    }

    @Override
    public void logException(String majorCategory, String minorCategory, String message, Throwable exception) {
        hybridLogger.logException(majorCategory, minorCategory, message, exception);
    }

    @Override
    public void logBatch(GameLogEntry... entries) {
        hybridLogger.logBatch(entries);
    }

    @Override
    public GameLogContext getCurrentContext() {
        return contextManager.getCurrentContext();
    }

    @Override
    public GameLogContext createContext() {
        return contextManager.createContext();
    }

    @Override
    public void setCurrentContext(GameLogContext context) {
        contextManager.setCurrentContext(context);
    }

    @Override
    public void clearCurrentContext() {
        contextManager.clearCurrentContext();
    }

    @Override
    public String getQueueStats() {
        return hybridLogger.getQueueStats();
    }

    @Override
    public String getContextStats() {
        return hybridLogger.getContextStats();
    }
}
