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

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * 配置持久化存储服务
 * 负责将配置保存到文件系统并从文件系统读取配置
 */
@Slf4j
@Service
public class ConfigPersistenceService {
    private static final String CONFIG_DIR = "config/logsystem";
    private static final String SYSTEM_CONFIG_FILE = "config/logsystem/system.properties";
    private static final String PERFORMANCE_CONFIG_FILE = "config/logsystem/performance.properties";
    private static final String CATEGORY_CONFIG_FILE = "config/logsystem/category.properties";
    private static final String PACKET_CONFIG_FILE = "config/logsystem/packet.properties";

    public ConfigPersistenceService() {
        initializeConfigDirectory();
    }

    /**
     * 初始化配置目录
     */
    private void initializeConfigDirectory() {
        try {
            Path configPath = Paths.get(CONFIG_DIR);
            if (!Files.exists(configPath)) {
                Files.createDirectories(configPath);
                log.info("已创建配置目录: {}", CONFIG_DIR);
            }
        } catch (IOException e) {
            log.error("创建配置目录失败", e);
        }
    }

    /**
     * 保存系统配置
     */
    public boolean saveSystemConfig(Map<String, Object> config) {
        try {
            Properties props = new Properties();
            config.forEach((k, v) -> props.setProperty(k, v != null ? v.toString() : ""));
            
            try (FileWriter writer = new FileWriter(SYSTEM_CONFIG_FILE, StandardCharsets.UTF_8)) {
                props.store(writer, "System Configuration");
                log.info("系统配置已保存");
                return true;
            }
        } catch (IOException e) {
            log.error("保存系统配置失败", e);
            return false;
        }
    }

    /**
     * 加载系统配置
     */
    public Map<String, Object> loadSystemConfig() {
        Map<String, Object> config = new HashMap<>();
        try {
            Properties props = new Properties();
            try (FileReader reader = new FileReader(SYSTEM_CONFIG_FILE, StandardCharsets.UTF_8)) {
                props.load(reader);
                props.forEach((k, v) -> config.put((String) k, v));
                log.info("系统配置已加载");
            }
        } catch (IOException e) {
            log.warn("加载系统配置失败，将使用默认配置: {}", e.getMessage());
        }
        return config;
    }

    /**
     * 保存性能配置
     */
    public boolean savePerformanceConfig(Map<String, Object> config) {
        try {
            Properties props = new Properties();
            config.forEach((k, v) -> props.setProperty(k, v != null ? v.toString() : ""));
            
            try (FileWriter writer = new FileWriter(PERFORMANCE_CONFIG_FILE, StandardCharsets.UTF_8)) {
                props.store(writer, "Performance Configuration");
                log.info("性能配置已保存");
                return true;
            }
        } catch (IOException e) {
            log.error("保存性能配置失败", e);
            return false;
        }
    }

    /**
     * 加载性能配置
     */
    public Map<String, Object> loadPerformanceConfig() {
        Map<String, Object> config = new HashMap<>();
        try {
            Properties props = new Properties();
            try (FileReader reader = new FileReader(PERFORMANCE_CONFIG_FILE, StandardCharsets.UTF_8)) {
                props.load(reader);
                props.forEach((k, v) -> config.put((String) k, v));
                log.info("性能配置已加载");
            }
        } catch (IOException e) {
            log.warn("加载性能配置失败，将使用默认配置: {}", e.getMessage());
        }
        return config;
    }

    /**
     * 保存分类配置
     */
    public boolean saveCategoryConfig(Map<String, Object> config) {
        try {
            Properties props = new Properties();
            config.forEach((k, v) -> props.setProperty(k, v != null ? v.toString() : ""));
            
            try (FileWriter writer = new FileWriter(CATEGORY_CONFIG_FILE, StandardCharsets.UTF_8)) {
                props.store(writer, "Category Configuration");
                log.info("分类配置已保存");
                return true;
            }
        } catch (IOException e) {
            log.error("保存分类配置失败", e);
            return false;
        }
    }

    /**
     * 加载分类配置
     */
    public Map<String, Object> loadCategoryConfig() {
        Map<String, Object> config = new HashMap<>();
        try {
            Properties props = new Properties();
            try (FileReader reader = new FileReader(CATEGORY_CONFIG_FILE, StandardCharsets.UTF_8)) {
                props.load(reader);
                props.forEach((k, v) -> config.put((String) k, v));
                log.info("分类配置已加载");
            }
        } catch (IOException e) {
            log.warn("加载分类配置失败，将使用默认配置: {}", e.getMessage());
        }
        return config;
    }

    /**
     * 保存网络包配置
     */
    public boolean savePacketConfig(Map<String, Object> config) {
        try {
            Properties props = new Properties();
            config.forEach((k, v) -> props.setProperty(k, v != null ? v.toString() : ""));
            
            try (FileWriter writer = new FileWriter(PACKET_CONFIG_FILE, StandardCharsets.UTF_8)) {
                props.store(writer, "Packet Configuration");
                log.info("网络包配置已保存");
                return true;
            }
        } catch (IOException e) {
            log.error("保存网络包配置失败", e);
            return false;
        }
    }

    /**
     * 加载网络包配置
     */
    public Map<String, Object> loadPacketConfig() {
        Map<String, Object> config = new HashMap<>();
        try {
            Properties props = new Properties();
            try (FileReader reader = new FileReader(PACKET_CONFIG_FILE, StandardCharsets.UTF_8)) {
                props.load(reader);
                props.forEach((k, v) -> config.put((String) k, v));
                log.info("网络包配置已加载");
            }
        } catch (IOException e) {
            log.warn("加载网络包配置失败，将使用默认配置: {}", e.getMessage());
        }
        return config;
    }

    /**
     * 备份所有配置文件
     */
    public boolean backupConfigs() {
        try {
            String timestamp = String.valueOf(System.currentTimeMillis());
            String backupDir = CONFIG_DIR + "/backup-" + timestamp;
            Path backupPath = Paths.get(backupDir);
            Files.createDirectories(backupPath);

            Files.copy(Paths.get(SYSTEM_CONFIG_FILE), backupPath.resolve("system.properties"), StandardCopyOption.REPLACE_EXISTING);
            Files.copy(Paths.get(PERFORMANCE_CONFIG_FILE), backupPath.resolve("performance.properties"), StandardCopyOption.REPLACE_EXISTING);
            Files.copy(Paths.get(CATEGORY_CONFIG_FILE), backupPath.resolve("category.properties"), StandardCopyOption.REPLACE_EXISTING);
            Files.copy(Paths.get(PACKET_CONFIG_FILE), backupPath.resolve("packet.properties"), StandardCopyOption.REPLACE_EXISTING);

            log.info("配置文件已备份到: {}", backupDir);
            return true;
        } catch (IOException e) {
            log.error("备份配置文件失败", e);
            return false;
        }
    }

    /**
     * 检查配置文件是否存在
     */
    public boolean configFilesExist() {
        return Files.exists(Paths.get(SYSTEM_CONFIG_FILE)) &&
               Files.exists(Paths.get(PERFORMANCE_CONFIG_FILE)) &&
               Files.exists(Paths.get(CATEGORY_CONFIG_FILE)) &&
               Files.exists(Paths.get(PACKET_CONFIG_FILE));
    }
}
