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

package org.gms.logsystem;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.category.DynamicCategoryManager;
import org.gms.logsystem.config.LogConfig;
import org.gms.logsystem.config.PacketLogConfig;
import org.gms.logsystem.context.LogContextManager;
import org.gms.logsystem.core.HighPerformanceLogger;
import org.gms.logsystem.core.HybridLogger;
import org.gms.logsystem.core.SimpleLogger;
import org.gms.logsystem.file.LogFileManager;
import org.gms.logsystem.alert.LogAlertService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Slf4j
@Configuration
@ComponentScan(basePackages = {"org.gms.logsystem.rest", "org.gms.logsystem.query"})
public class LogsAutoConfiguration {
    @Bean
    @ConditionalOnMissingBean
    public DynamicCategoryManager dynamicCategoryManager() {
        log.info("初始化动态分类管理器");
        return new DynamicCategoryManager();
    }

    @Bean
    @ConditionalOnMissingBean
    public LogConfig logConfig() {
        log.info("初始化日志配置");
        return new LogConfig();
    }

    @Bean
    @ConditionalOnMissingBean
    public PacketLogConfig packetLogConfig() {
        log.info("初始化网络封包日志配置");
        return new PacketLogConfig();
    }

    @Bean
    @ConditionalOnMissingBean
    public LogFileManager logFileManager(LogConfig logConfig) {
        log.info("初始化日志文件管理器");
        return new LogFileManager(logConfig);
    }

    @Bean
    @ConditionalOnMissingBean
    public SimpleLogger simpleLogger(DynamicCategoryManager categoryManager) {
        log.info("初始化简化日志记录器");
        return new SimpleLogger(categoryManager);
    }

    @Bean
    @ConditionalOnMissingBean
    public LogContextManager logContextManager() {
        log.info("初始化日志上下文管理器");
        return new LogContextManager();
    }

    @Bean
    @ConditionalOnMissingBean
    public LogAlertService logAlertService() {
        log.info("初始化日志告警服务");
        return new LogAlertService();
    }

    @Bean
    @ConditionalOnMissingBean
    public HighPerformanceLogger highPerformanceLogger(LogConfig logConfig, LogFileManager logFileManager,
                                                      LogAlertService logAlertService) {
        log.info("初始化高性能日志记录器");
        return new HighPerformanceLogger(logConfig, logFileManager, logAlertService);
    }

    @Bean
    @ConditionalOnMissingBean
    public HybridLogger hybridLogger(SimpleLogger simpleLogger, HighPerformanceLogger highPerformanceLogger,
                                     LogContextManager contextManager, DynamicCategoryManager categoryManager) {
        log.info("初始化混合日志记录器");
        return new HybridLogger(simpleLogger, highPerformanceLogger, contextManager, categoryManager);
    }
}
