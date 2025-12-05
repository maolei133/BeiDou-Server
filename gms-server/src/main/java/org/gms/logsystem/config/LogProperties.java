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
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * 日志配置属性类 - 从application-log.yml读取配置
 * 支持动态配置刷新
 *
 * @author logs-system
 */
@Data
@Component
@ConfigurationProperties(prefix = "logs")
public class LogProperties {
    /**
     * 日志基础配置
     */
    private BaseConfig base = new BaseConfig();

    /**
     * 高频日志配置
     */
    private PerformanceConfig high = new PerformanceConfig();

    /**
     * 中频日志配置
     */
    private PerformanceConfig medium = new PerformanceConfig();

    /**
     * 低频日志配置
     */
    private PerformanceConfig low = new PerformanceConfig();

    /**
     * 基础配置类
     */
    @Data
    public static class BaseConfig {
        /**
         * 日志保留天数
         */
        private int retentionDays = 30;

        /**
         * 单个日志文件大小（MB）
         */
        private int fileSizeMB = 100;

        /**
         * 是否启用压缩
         */
        private boolean compressionEnabled = true;

        /**
         * 压缩格式 (zip, gzip)
         */
        private String compressionFormat = "gzip";

        /**
         * 冷数据保留天数
         */
        private int coldDataDays = 30;

        /**
         * 温数据保留天数
         */
        private int warmDataDays = 7;
    }

    /**
     * 性能配置类
     */
    @Data
    public static class PerformanceConfig {
        /**
         * 缓冲区大小
         */
        private int bufferSize = 1024;

        /**
         * 刷新间隔（毫秒）
         */
        private int flushInterval = 1000;

        /**
         * 线程池大小
         */
        private int threadPoolSize = 4;

        /**
         * 队列大小
         */
        private int queueSize = 10000;
    }
}
