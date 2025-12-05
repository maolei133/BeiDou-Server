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
import org.gms.logsystem.category.CategoryInfo;
import org.gms.logsystem.category.DynamicCategoryManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 配置管理服务 - 管理日志系统的动态配置
 * 支持系统配置、性能配置、分类配置的统一管理
 *
 * @author logs-system
 */
@Slf4j
@Service
public class ConfigurationManager {
    private final DynamicCategoryManager categoryManager;
    private final LogConfig logConfig;
    private final PacketLogConfig packetLogConfig;
    
    @Autowired(required = false)
    private ConfigChangeNotifier configChangeNotifier;
    
    @Autowired(required = false)
    private ConfigPersistenceService persistenceService;

    /**
     * 配置变更监听器
     */
    private final List<ConfigChangeListener> listeners = Collections.synchronizedList(new ArrayList<>());

    /**
     * 配置版本号
     */
    private volatile long configVersion = 1;

    public ConfigurationManager(DynamicCategoryManager categoryManager, LogConfig logConfig,
                                PacketLogConfig packetLogConfig) {
        this.categoryManager = categoryManager;
        this.logConfig = logConfig;
        this.packetLogConfig = packetLogConfig;
    }

    /**
     * 获取系统配置
     */
    public Map<String, Object> getSystemConfig() {
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("enabled", logConfig.isEnabled());
        config.put("retentionDays", logConfig.getRetentionDays());
        config.put("fileSizeMB", logConfig.getFileSizeMB());
        config.put("compressionEnabled", logConfig.isCompressionEnabled());
        config.put("compressionFormat", logConfig.getCompressionFormat());
        config.put("asyncThreadPoolSize", logConfig.getAsyncThreadPoolSize());
        config.put("asyncQueueSize", logConfig.getAsyncQueueSize());
        config.put("logDir", logConfig.getLogDir());
        config.put("coldDataDays", logConfig.getColdDataDays());
        config.put("warmDataDays", logConfig.getWarmDataDays());
        return config;
    }

    /**
     * 更新系统配置
     */
    public synchronized boolean updateSystemConfig(Map<String, Object> configMap) {
        try {
            if (configMap.containsKey("enabled")) {
                logConfig.setEnabled((Boolean) configMap.get("enabled"));
            }
            if (configMap.containsKey("retentionDays")) {
                logConfig.setRetentionDays((Integer) configMap.get("retentionDays"));
            }
            if (configMap.containsKey("fileSizeMB")) {
                logConfig.setFileSizeMB((Integer) configMap.get("fileSizeMB"));
            }
            if (configMap.containsKey("compressionEnabled")) {
                logConfig.setCompressionEnabled((Boolean) configMap.get("compressionEnabled"));
            }
            if (configMap.containsKey("compressionFormat")) {
                logConfig.setCompressionFormat((String) configMap.get("compressionFormat"));
            }
            if (configMap.containsKey("asyncThreadPoolSize")) {
                logConfig.setAsyncThreadPoolSize((Integer) configMap.get("asyncThreadPoolSize"));
            }
            if (configMap.containsKey("coldDataDays")) {
                logConfig.setColdDataDays((Integer) configMap.get("coldDataDays"));
            }
            if (configMap.containsKey("warmDataDays")) {
                logConfig.setWarmDataDays((Integer) configMap.get("warmDataDays"));
            }

            // 持久化保存配置
            if (persistenceService != null) {
                persistenceService.saveSystemConfig(getSystemConfig());
            }
            
            // 发送配置变更隨嗅员鐯预告
            notifyConfigChange("system", "system.config", null, getSystemConfig());
            
            log.info("系统配置已更新");
            return true;
        } catch (Exception e) {
            log.error("更新系统配置失败", e);
            return false;
        }
    }

    /**
     * 获取性能配置
     */
    public Map<String, Object> getPerformanceConfig() {
        Map<String, Object> config = new LinkedHashMap<>();

        Map<String, Object> high = new LinkedHashMap<>();
        high.put("bufferSize", logConfig.getHighFreqBufferSize());
        high.put("flushInterval", logConfig.getHighFreqFlushInterval());

        Map<String, Object> medium = new LinkedHashMap<>();
        medium.put("bufferSize", logConfig.getMediumFreqBufferSize());
        medium.put("flushInterval", logConfig.getMediumFreqFlushInterval());

        Map<String, Object> low = new LinkedHashMap<>();
        low.put("bufferSize", logConfig.getLowFreqBufferSize());
        low.put("flushInterval", logConfig.getLowFreqFlushInterval());

        config.put("HIGH", high);
        config.put("MEDIUM", medium);
        config.put("LOW", low);

        return config;
    }

    /**
     * 更新性能配置
     */
    public synchronized boolean updatePerformanceConfig(String level, int bufferSize, int flushInterval) {
        try {
            if ("HIGH".equals(level)) {
                logConfig.setHighFreqBufferSize(bufferSize);
                logConfig.setHighFreqFlushInterval(flushInterval);
            } else if ("MEDIUM".equals(level)) {
                logConfig.setMediumFreqBufferSize(bufferSize);
                logConfig.setMediumFreqFlushInterval(flushInterval);
            } else if ("LOW".equals(level)) {
                logConfig.setLowFreqBufferSize(bufferSize);
                logConfig.setLowFreqFlushInterval(flushInterval);
            } else {
                return false;
            }

            notifyConfigChange("性能配置已更新: " + level);
            log.info("{}频日志性能配置已更新", level);
            return true;
        } catch (Exception e) {
            log.error("更新性能配置失败", e);
            return false;
        }
    }

    /**
     * 获取分类配置
     */
    public Map<String, Object> getCategoryConfig(String majorCategory, String minorCategory) {
        CategoryInfo category = categoryManager.getCategory(majorCategory, minorCategory);
        if (category == null) {
            return null;
        }

        Map<String, Object> config = new LinkedHashMap<>();
        config.put("categoryId", category.getCategoryId());
        config.put("majorCategory", category.getMajorCategory());
        config.put("minorCategory", category.getMinorCategory());
        config.put("description", category.getDescription());
        config.put("level", category.getLevel());
        config.put("enabled", category.isEnabled());
        config.put("consoleOutput", category.isConsoleOutput());
        config.put("fileOutput", category.isFileOutput());

        return config;
    }

    /**
     * 获取所有分类配置
     */
    public List<Map<String, Object>> getAllCategoryConfig() {
        List<Map<String, Object>> configs = new ArrayList<>();
        for (CategoryInfo category : categoryManager.getAllCategories()) {
            Map<String, Object> config = new LinkedHashMap<>();
            config.put("categoryId", category.getCategoryId());
            config.put("majorCategory", category.getMajorCategory());
            config.put("minorCategory", category.getMinorCategory());
            config.put("description", category.getDescription());
            config.put("level", category.getLevel());
            config.put("enabled", category.isEnabled());
            config.put("consoleOutput", category.isConsoleOutput());
            config.put("fileOutput", category.isFileOutput());
            configs.add(config);
        }
        return configs;
    }

    /**
     * 更新分类配置
     */
    public synchronized boolean updateCategoryConfig(String majorCategory, String minorCategory,
                                                     boolean enabled, boolean consoleOutput, boolean fileOutput) {
        try {
            boolean success = categoryManager.setEnabled(majorCategory, minorCategory, enabled);
            if (!success) {
                return false;
            }

            success = categoryManager.setOutputOptions(majorCategory, minorCategory, consoleOutput, fileOutput);
            if (!success) {
                return false;
            }

            notifyConfigChange("分类配置已更新: " + majorCategory + "." + minorCategory);
            log.info("分类配置已更新: {}.{}", majorCategory, minorCategory);
            return true;
        } catch (Exception e) {
            log.error("更新分类配置失败", e);
            return false;
        }
    }

    /**
     * 获取网络封包配置
     */
    public Map<String, Object> getPacketConfig() {
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("inPacketLogEnabled", packetLogConfig.isLogIncoming());
        config.put("outPacketLogEnabled", packetLogConfig.isLogOutgoing());
        config.put("monitoredChrLogEnabled", packetLogConfig.isMonitoredChrLogEnabled());
        config.put("inPacketBlocklist", new ArrayList<>(packetLogConfig.getInPacketBlocklist()));
        config.put("outPacketBlocklist", new ArrayList<>(packetLogConfig.getOutPacketBlocklist()));
        config.put("monitoredCharacterIds", new ArrayList<>(packetLogConfig.getMonitoredCharacterIds()));
        config.put("inPacketBufferSize", packetLogConfig.getInPacketBufferSize());
        config.put("outPacketBufferSize", packetLogConfig.getOutPacketBufferSize());
        config.put("packetLogFlushInterval", packetLogConfig.getPacketLogFlushInterval());
        config.put("capturePacketContent", packetLogConfig.isCapturePacketContent());
        config.put("maxPacketContentLength", packetLogConfig.getMaxPacketContentLength());
        return config;
    }

    /**
     * 更新网络封包配置
     */
    public synchronized boolean updatePacketConfig(Map<String, Object> configMap) {
        try {
            if (configMap.containsKey("inPacketLogEnabled")) {
                packetLogConfig.setLogIncoming((Boolean) configMap.get("inPacketLogEnabled"));
            }
            if (configMap.containsKey("outPacketLogEnabled")) {
                packetLogConfig.setLogOutgoing((Boolean) configMap.get("outPacketLogEnabled"));
            }
            if (configMap.containsKey("monitoredChrLogEnabled")) {
                packetLogConfig.setMonitoredChrLogEnabled((Boolean) configMap.get("monitoredChrLogEnabled"));
            }
            if (configMap.containsKey("inPacketBufferSize")) {
                packetLogConfig.setInPacketBufferSize((Integer) configMap.get("inPacketBufferSize"));
            }
            if (configMap.containsKey("outPacketBufferSize")) {
                packetLogConfig.setOutPacketBufferSize((Integer) configMap.get("outPacketBufferSize"));
            }
            if (configMap.containsKey("packetLogFlushInterval")) {
                packetLogConfig.setPacketLogFlushInterval((Integer) configMap.get("packetLogFlushInterval"));
            }
            if (configMap.containsKey("capturePacketContent")) {
                packetLogConfig.setCapturePacketContent((Boolean) configMap.get("capturePacketContent"));
            }
            if (configMap.containsKey("maxPacketContentLength")) {
                packetLogConfig.setMaxPacketContentLength((Integer) configMap.get("maxPacketContentLength"));
            }

            notifyConfigChange("网络封包配置已更新");
            log.info("网络封包配置已更新");
            return true;
        } catch (Exception e) {
            log.error("更新网络封包配置失败", e);
            return false;
        }
    }

    /**
     * 添加入站包屏蔽
     */
    public synchronized void addInPacketBlock(int opcode) {
        packetLogConfig.addInPacketBlock(opcode);
        notifyConfigChange("入站包屏蔽已添加: " + opcode);
        log.info("入站包屏蔽已添加: {}", opcode);
    }

    /**
     * 移除入站包屏蔽
     */
    public synchronized void removeInPacketBlock(int opcode) {
        packetLogConfig.removeInPacketBlock(opcode);
        notifyConfigChange("入站包屏蔽已移除: " + opcode);
        log.info("入站包屏蔽已移除: {}", opcode);
    }

    /**
     * 添加出站包屏蔽
     */
    public synchronized void addOutPacketBlock(int opcode) {
        packetLogConfig.addOutPacketBlock(opcode);
        notifyConfigChange("出站包屏蔽已添加: " + opcode);
        log.info("出站包屏蔽已添加: {}", opcode);
    }

    /**
     * 移除出站包屏蔽
     */
    public synchronized void removeOutPacketBlock(int opcode) {
        packetLogConfig.removeOutPacketBlock(opcode);
        notifyConfigChange("出站包屏蔽已移除: " + opcode);
        log.info("出站包屏蔽已移除: {}", opcode);
    }

    /**
     * 获取配置版本号
     */
    public long getConfigVersion() {
        return configVersion;
    }

    /**
     * 监听配置变更
     */
    public void addConfigChangeListener(ConfigChangeListener listener) {
        listeners.add(listener);
    }

    /**
     * 移除配置变更监听器
     */
    public void removeConfigChangeListener(ConfigChangeListener listener) {
        listeners.remove(listener);
    }

    /**
     * 通知配置变更
     */
    private void notifyConfigChange(String changeMessage) {
        configVersion++;
        for (ConfigChangeListener listener : listeners) {
            try {
                listener.onConfigChanged(changeMessage, configVersion);
            } catch (Exception e) {
                log.error("配置变更通知失败", e);
            }
        }
    }
    
    /**
     * 通知配置变更（新機制）
     */
    private void notifyConfigChange(String configType, String configKey, Object oldValue, Object newValue) {
        configVersion++;
        
        // 通知旧的供管理哥监听器
        notifyConfigChange(configType + "." + configKey);
        
        // 通知新的配置变更通知器
        if (configChangeNotifier != null) {
            ConfigChangeEvent event = new ConfigChangeEvent(configType, configKey, oldValue, newValue, "REST API");
            configChangeNotifier.notifyChange(event);
        }
    }

    /**
     * 配置变更监听器接口
     */
    public interface ConfigChangeListener {
        void onConfigChanged(String changeMessage, long newVersion);
    }
}
