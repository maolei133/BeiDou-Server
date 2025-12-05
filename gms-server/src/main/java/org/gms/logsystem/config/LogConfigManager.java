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

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

@Slf4j
@Service
public class LogConfigManager {
    private final LogConfig logConfig;
    private final List<ConfigChangeListener> listeners = new CopyOnWriteArrayList<>();

    public LogConfigManager(LogConfig logConfig) {
        this.logConfig = logConfig;
    }

    public void updateConfig(Map<String, Object> configMap) {
        try {
            ConfigSnapshot before = captureSnapshot();

            if (configMap.containsKey("enabled")) {
                logConfig.setEnabled((Boolean) configMap.get("enabled"));
            }
            if (configMap.containsKey("asyncThreadPoolSize")) {
                logConfig.setAsyncThreadPoolSize((Integer) configMap.get("asyncThreadPoolSize"));
            }
            if (configMap.containsKey("highFreqBufferSize")) {
                logConfig.setHighFreqBufferSize((Integer) configMap.get("highFreqBufferSize"));
            }
            if (configMap.containsKey("mediumFreqBufferSize")) {
                logConfig.setMediumFreqBufferSize((Integer) configMap.get("mediumFreqBufferSize"));
            }
            if (configMap.containsKey("lowFreqBufferSize")) {
                logConfig.setLowFreqBufferSize((Integer) configMap.get("lowFreqBufferSize"));
            }
            if (configMap.containsKey("highFreqFlushInterval")) {
                logConfig.setHighFreqFlushInterval((Integer) configMap.get("highFreqFlushInterval"));
            }
            if (configMap.containsKey("mediumFreqFlushInterval")) {
                logConfig.setMediumFreqFlushInterval((Integer) configMap.get("mediumFreqFlushInterval"));
            }
            if (configMap.containsKey("lowFreqFlushInterval")) {
                logConfig.setLowFreqFlushInterval((Integer) configMap.get("lowFreqFlushInterval"));
            }
            if (configMap.containsKey("logRetentionDays")) {
                logConfig.setLogRetentionDays((Integer) configMap.get("logRetentionDays"));
            }
            if (configMap.containsKey("maxLogFileSize")) {
                logConfig.setMaxLogFileSize((Long) configMap.get("maxLogFileSize"));
            }
            if (configMap.containsKey("compressionFormat")) {
                logConfig.setCompressionFormat((String) configMap.get("compressionFormat"));
            }
            if (configMap.containsKey("logDir")) {
                logConfig.setLogDir((String) configMap.get("logDir"));
            }

            ConfigSnapshot after = captureSnapshot();
            notifyListeners(new ConfigChangeEvent(before, after));

            log.info("日志配置已更新: {}", configMap);
        } catch (Exception e) {
            log.error("更新日志配置失败", e);
            throw new RuntimeException("更新日志配置失败: " + e.getMessage());
        }
    }

    public Map<String, Object> getConfig() {
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("enabled", logConfig.isEnabled());
        config.put("asyncThreadPoolSize", logConfig.getAsyncThreadPoolSize());
        config.put("highFreqBufferSize", logConfig.getHighFreqBufferSize());
        config.put("mediumFreqBufferSize", logConfig.getMediumFreqBufferSize());
        config.put("lowFreqBufferSize", logConfig.getLowFreqBufferSize());
        config.put("highFreqFlushInterval", logConfig.getHighFreqFlushInterval());
        config.put("mediumFreqFlushInterval", logConfig.getMediumFreqFlushInterval());
        config.put("lowFreqFlushInterval", logConfig.getLowFreqFlushInterval());
        config.put("logRetentionDays", logConfig.getLogRetentionDays());
        config.put("maxLogFileSize", logConfig.getMaxLogFileSize());
        config.put("compressionFormat", logConfig.getCompressionFormat());
        config.put("logDir", logConfig.getLogDir());
        return config;
    }

    public void registerListener(ConfigChangeListener listener) {
        if (listener != null) {
            listeners.add(listener);
            log.info("已注册配置变更监听器");
        }
    }

    public void unregisterListener(ConfigChangeListener listener) {
        if (listeners.remove(listener)) {
            log.info("已注销配置变更监听器");
        }
    }

    private void notifyListeners(ConfigChangeEvent event) {
        for (ConfigChangeListener listener : listeners) {
            try {
                listener.onConfigChange(event);
            } catch (Exception e) {
                log.error("配置变更监听器执行失败", e);
            }
        }
    }

    private ConfigSnapshot captureSnapshot() {
        return new ConfigSnapshot(
                logConfig.isEnabled(),
                logConfig.getAsyncThreadPoolSize(),
                logConfig.getHighFreqBufferSize(),
                logConfig.getMediumFreqBufferSize(),
                logConfig.getLowFreqBufferSize(),
                logConfig.getHighFreqFlushInterval(),
                logConfig.getMediumFreqFlushInterval(),
                logConfig.getLowFreqFlushInterval(),
                logConfig.getLogRetentionDays(),
                logConfig.getMaxLogFileSize(),
                logConfig.getCompressionFormat(),
                logConfig.getLogDir()
        );
    }

    public static class ConfigSnapshot {
        public final boolean enabled;
        public final int asyncThreadPoolSize;
        public final int highFreqBufferSize;
        public final int mediumFreqBufferSize;
        public final int lowFreqBufferSize;
        public final int highFreqFlushInterval;
        public final int mediumFreqFlushInterval;
        public final int lowFreqFlushInterval;
        public final int logRetentionDays;
        public final long maxLogFileSize;
        public final String compressionFormat;
        public final String logDir;

        public ConfigSnapshot(boolean enabled, int asyncThreadPoolSize, int highFreqBufferSize,
                            int mediumFreqBufferSize, int lowFreqBufferSize, int highFreqFlushInterval,
                            int mediumFreqFlushInterval, int lowFreqFlushInterval, int logRetentionDays,
                            long maxLogFileSize, String compressionFormat, String logDir) {
            this.enabled = enabled;
            this.asyncThreadPoolSize = asyncThreadPoolSize;
            this.highFreqBufferSize = highFreqBufferSize;
            this.mediumFreqBufferSize = mediumFreqBufferSize;
            this.lowFreqBufferSize = lowFreqBufferSize;
            this.highFreqFlushInterval = highFreqFlushInterval;
            this.mediumFreqFlushInterval = mediumFreqFlushInterval;
            this.lowFreqFlushInterval = lowFreqFlushInterval;
            this.logRetentionDays = logRetentionDays;
            this.maxLogFileSize = maxLogFileSize;
            this.compressionFormat = compressionFormat;
            this.logDir = logDir;
        }
    }

    public static class ConfigChangeEvent {
        public final ConfigSnapshot before;
        public final ConfigSnapshot after;
        public final long changeTime = System.currentTimeMillis();

        public ConfigChangeEvent(ConfigSnapshot before, ConfigSnapshot after) {
            this.before = before;
            this.after = after;
        }

        public List<String> getChangedFields() {
            List<String> changed = new ArrayList<>();
            if (before.enabled != after.enabled) changed.add("enabled");
            if (before.asyncThreadPoolSize != after.asyncThreadPoolSize) changed.add("asyncThreadPoolSize");
            if (before.highFreqBufferSize != after.highFreqBufferSize) changed.add("highFreqBufferSize");
            if (before.mediumFreqBufferSize != after.mediumFreqBufferSize) changed.add("mediumFreqBufferSize");
            if (before.lowFreqBufferSize != after.lowFreqBufferSize) changed.add("lowFreqBufferSize");
            if (before.highFreqFlushInterval != after.highFreqFlushInterval) changed.add("highFreqFlushInterval");
            if (before.mediumFreqFlushInterval != after.mediumFreqFlushInterval) changed.add("mediumFreqFlushInterval");
            if (before.lowFreqFlushInterval != after.lowFreqFlushInterval) changed.add("lowFreqFlushInterval");
            if (before.logRetentionDays != after.logRetentionDays) changed.add("logRetentionDays");
            if (before.maxLogFileSize != after.maxLogFileSize) changed.add("maxLogFileSize");
            if (!before.compressionFormat.equals(after.compressionFormat)) changed.add("compressionFormat");
            if (!before.logDir.equals(after.logDir)) changed.add("logDir");
            return changed;
        }
    }

    public interface ConfigChangeListener {
        void onConfigChange(ConfigChangeEvent event);
    }
}
