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

package org.gms.logsystem.config;

import lombok.Data;
import java.io.File;

/**
 * 日志配置管理类 - 基于GameConfig的动态配置
 * 支持运行时修改和热更新
 *
 * @author logs-system
 */
@Data
public class LogConfig {
    /**
     * 日志保留天数
     */
    private int logRetentionDays = 30;

    /**
     * 最大日志文件大小（bytes）
     */
    private long maxLogFileSize = 104857600; // 100MB

    /**
     * 是否启用压缩
     */
    private boolean compressionEnabled = true;

    /**
     * 压缩格式
     */
    private String compressionFormat = "gzip";

    /**
     * 高频日志缓冲区大小
     */
    private int highFreqBufferSize = 2048;

    /**
     * 高频日志刷新间隔（毫秒）
     */
    private int highFreqFlushInterval = 500;

    /**
     * 中频日志缓冲区大小
     */
    private int mediumFreqBufferSize = 1024;

    /**
     * 中频日志刷新间隔（毫秒）
     */
    private int mediumFreqFlushInterval = 1000;

    /**
     * 低频日志缓冲区大小
     */
    private int lowFreqBufferSize = 512;

    /**
     * 低频日志刷新间隔（毫秒）
     */
    private int lowFreqFlushInterval = 5000;

    /**
     * 异步线程池大小
     */
    private int asyncThreadPoolSize = 4;

    /**
     * 异步队列大小
     */
    private int asyncQueueSize = 10000;

    /**
     * 是否启用日志系统
     */
    private boolean enabled = false;

    /**
     * 日志输出目录
     */
    private String logDir = System.getProperty("user.dir") + File.separator + "logs";

    /**
     * 冷数据保留天数
     */
    private int coldDataDays = 10;

    /**
     * 温数据保留天数
     */
    private int warmDataDays = 7;

    /**
     * 获取高频日志的缓冲区大小
     */
    public int getHighFreqBufferSize() {
        return highFreqBufferSize;
    }

    /**
     * 获取高频日志的刷新间隔
     */
    public int getHighFreqFlushInterval() {
        return highFreqFlushInterval;
    }

    /**
     * 获取中频日志的缓冲区大小
     */
    public int getMediumFreqBufferSize() {
        return mediumFreqBufferSize;
    }

    /**
     * 获取中频日志的刷新间隔
     */
    public int getMediumFreqFlushInterval() {
        return mediumFreqFlushInterval;
    }

    /**
     * 获取低频日志的缓冲区大小
     */
    public int getLowFreqBufferSize() {
        return lowFreqBufferSize;
    }

    /**
     * 获取日志保留天数
     */
    public int getLogRetentionDays() {
        return logRetentionDays;
    }

    /**
     * 设置日志保留天数
     */
    public void setLogRetentionDays(int logRetentionDays) {
        this.logRetentionDays = logRetentionDays;
    }

    /**
     * 获取最大日志文件大小
     */
    public long getMaxLogFileSize() {
        return maxLogFileSize;
    }

    /**
     * 设置最大日志文件大小
     */
    public void setMaxLogFileSize(long maxLogFileSize) {
        this.maxLogFileSize = maxLogFileSize;
    }

    /**
     * 兼容旧的属性需求
     */
    public int getRetentionDays() {
        return logRetentionDays;
    }

    public void setRetentionDays(int retentionDays) {
        this.logRetentionDays = retentionDays;
    }

    public int getFileSizeMB() {
        return (int)(maxLogFileSize / (1024 * 1024));
    }

    public void setFileSizeMB(int fileSizeMB) {
        this.maxLogFileSize = (long) fileSizeMB * 1024 * 1024;
    }
}