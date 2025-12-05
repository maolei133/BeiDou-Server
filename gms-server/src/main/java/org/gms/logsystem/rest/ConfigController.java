package org.gms.logsystem.rest;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.config.LogConfig;
import org.gms.logsystem.config.PacketLogConfig;
import org.gms.model.dto.ResultBody;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * 配置管理REST API控制器
 * 提供日志系统配置管理功能
 */
@Slf4j
@RestController("logSystemConfigController")
@RequestMapping("/logsystem/config")
public class ConfigController {

    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final LogConfig logConfig;
    private final PacketLogConfig packetLogConfig;

    public ConfigController(LogConfig logConfig, PacketLogConfig packetLogConfig) {
        this.logConfig = logConfig;
        this.packetLogConfig = packetLogConfig;
    }

    /**
     * 获取日志配置
     */
    @GetMapping("/log")
    public ResultBody<Map<String, Object>> getLogConfig() {
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("enabled", logConfig.isEnabled());
        config.put("logDir", logConfig.getLogDir());
        config.put("retentionDays", logConfig.getLogRetentionDays());
        config.put("maxFileSizeMB", logConfig.getFileSizeMB());
        config.put("compressionEnabled", logConfig.isCompressionEnabled());
        config.put("compressionFormat", logConfig.getCompressionFormat());
        config.put("asyncThreadPoolSize", logConfig.getAsyncThreadPoolSize());
        config.put("asyncQueueSize", logConfig.getAsyncQueueSize());
        config.put("timestamp", LocalDateTime.now().format(formatter));
        return ResultBody.success(config);
    }

    /**
     * 更新日志配置
     */
    @PutMapping("/log")
    public ResultBody<Map<String, Object>> updateLogConfig(@RequestBody Map<String, Object> configMap) {
        if (configMap.containsKey("enabled")) {
            logConfig.setEnabled((Boolean) configMap.get("enabled"));
        }
        if (configMap.containsKey("retentionDays")) {
            logConfig.setLogRetentionDays(((Number) configMap.get("retentionDays")).intValue());
        }
        if (configMap.containsKey("maxFileSizeMB")) {
            logConfig.setFileSizeMB(((Number) configMap.get("maxFileSizeMB")).intValue());
        }
        if (configMap.containsKey("compressionEnabled")) {
            logConfig.setCompressionEnabled((Boolean) configMap.get("compressionEnabled"));
        }

        log.info("日志配置已更新");

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("message", "配置已更新");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        return ResultBody.success(result);
    }

    /**
     * 获取网络包配置
     */
    @GetMapping("/packet")
    public ResultBody<Map<String, Object>> getPacketConfig() {
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("enabled", packetLogConfig.isEnabled());
        config.put("logIncoming", packetLogConfig.isLogIncoming());
        config.put("logOutgoing", packetLogConfig.isLogOutgoing());
        config.put("captureContent", packetLogConfig.isCapturePacketContent());
        config.put("maxContentLength", packetLogConfig.getMaxPacketContentLength());
        config.put("inBlockList", packetLogConfig.getInBlockList());
        config.put("outBlockList", packetLogConfig.getOutBlockList());
        config.put("monitoredCharacters", packetLogConfig.getMonitoredCharacterIds());
        config.put("timestamp", LocalDateTime.now().format(formatter));
        return ResultBody.success(config);
    }

    /**
     * 更新网络包配置
     */
    @PutMapping("/packet")
    public ResultBody<Map<String, Object>> updatePacketConfig(@RequestBody Map<String, Object> configMap) {
        if (configMap.containsKey("enabled")) {
            packetLogConfig.setEnabled((Boolean) configMap.get("enabled"));
        }
        if (configMap.containsKey("logIncoming")) {
            packetLogConfig.setLogIncoming((Boolean) configMap.get("logIncoming"));
        }
        if (configMap.containsKey("logOutgoing")) {
            packetLogConfig.setLogOutgoing((Boolean) configMap.get("logOutgoing"));
        }
        if (configMap.containsKey("captureContent")) {
            packetLogConfig.setCapturePacketContent((Boolean) configMap.get("captureContent"));
        }

        log.info("网络包配置已更新");

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("message", "配置已更新");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        return ResultBody.success(result);
    }

    /**
     * 添加入站包屏蔽
     */
    @PostMapping("/packet/in-block/{opcode}")
    public ResultBody<Map<String, Object>> addInBlockOpcode(@PathVariable int opcode) {
        packetLogConfig.addInBlockOpcode(opcode);
        log.info("添加入站包屏蔽: {}", opcode);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("opcode", opcode);
        result.put("inBlockList", packetLogConfig.getInBlockList());
        return ResultBody.success(result);
    }

    /**
     * 移除入站包屏蔽
     */
    @DeleteMapping("/packet/in-block/{opcode}")
    public ResultBody<Map<String, Object>> removeInBlockOpcode(@PathVariable int opcode) {
        packetLogConfig.removeInBlockOpcode(opcode);
        log.info("移除入站包屏蔽: {}", opcode);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("opcode", opcode);
        result.put("inBlockList", packetLogConfig.getInBlockList());
        return ResultBody.success(result);
    }

    /**
     * 添加出站包屏蔽
     */
    @PostMapping("/packet/out-block/{opcode}")
    public ResultBody<Map<String, Object>> addOutBlockOpcode(@PathVariable int opcode) {
        packetLogConfig.addOutBlockOpcode(opcode);
        log.info("添加出站包屏蔽: {}", opcode);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("opcode", opcode);
        result.put("outBlockList", packetLogConfig.getOutBlockList());
        return ResultBody.success(result);
    }

    /**
     * 移除出站包屏蔽
     */
    @DeleteMapping("/packet/out-block/{opcode}")
    public ResultBody<Map<String, Object>> removeOutBlockOpcode(@PathVariable int opcode) {
        packetLogConfig.removeOutBlockOpcode(opcode);
        log.info("移除出站包屏蔽: {}", opcode);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("opcode", opcode);
        result.put("outBlockList", packetLogConfig.getOutBlockList());
        return ResultBody.success(result);
    }

    /**
     * 获取性能配置
     */
    @GetMapping("/performance")
    public ResultBody<Map<String, Object>> getPerformanceConfig() {
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("highFreqBufferSize", logConfig.getHighFreqBufferSize());
        config.put("highFreqFlushInterval", logConfig.getHighFreqFlushInterval());
        config.put("mediumFreqBufferSize", logConfig.getMediumFreqBufferSize());
        config.put("mediumFreqFlushInterval", logConfig.getMediumFreqFlushInterval());
        config.put("lowFreqBufferSize", logConfig.getLowFreqBufferSize());
        config.put("lowFreqFlushInterval", logConfig.getLowFreqFlushInterval());
        config.put("asyncThreadPoolSize", logConfig.getAsyncThreadPoolSize());
        config.put("asyncQueueSize", logConfig.getAsyncQueueSize());
        config.put("timestamp", LocalDateTime.now().format(formatter));
        return ResultBody.success(config);
    }

    /**
     * 更新性能配置
     */
    @PutMapping("/performance")
    public ResultBody<Map<String, Object>> updatePerformanceConfig(@RequestBody Map<String, Object> configMap) {
        if (configMap.containsKey("highFreqBufferSize")) {
            logConfig.setHighFreqBufferSize(((Number) configMap.get("highFreqBufferSize")).intValue());
        }
        if (configMap.containsKey("highFreqFlushInterval")) {
            logConfig.setHighFreqFlushInterval(((Number) configMap.get("highFreqFlushInterval")).intValue());
        }
        if (configMap.containsKey("asyncThreadPoolSize")) {
            logConfig.setAsyncThreadPoolSize(((Number) configMap.get("asyncThreadPoolSize")).intValue());
        }

        log.info("性能配置已更新");

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("message", "性能配置已更新");
        result.put("timestamp", LocalDateTime.now().format(formatter));
        return ResultBody.success(result);
    }

    /**
     * 获取所有配置
     */
    @GetMapping("/all")
    public ResultBody<Map<String, Object>> getAllConfig() {
        Map<String, Object> allConfig = new LinkedHashMap<>();

        // 日志配置
        Map<String, Object> logCfg = new LinkedHashMap<>();
        logCfg.put("enabled", logConfig.isEnabled());
        logCfg.put("logDir", logConfig.getLogDir());
        logCfg.put("retentionDays", logConfig.getLogRetentionDays());
        logCfg.put("maxFileSizeMB", logConfig.getFileSizeMB());
        allConfig.put("log", logCfg);

        // 网络包配置
        Map<String, Object> packetCfg = new LinkedHashMap<>();
        packetCfg.put("enabled", packetLogConfig.isEnabled());
        packetCfg.put("logIncoming", packetLogConfig.isLogIncoming());
        packetCfg.put("logOutgoing", packetLogConfig.isLogOutgoing());
        allConfig.put("packet", packetCfg);

        allConfig.put("timestamp", LocalDateTime.now().format(formatter));

        return ResultBody.success(allConfig);
    }
}
