package org.gms.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;
import org.gms.server.logging.AuditLogger;
import org.springframework.web.bind.annotation.*;
import org.yaml.snakeyaml.Yaml;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;

@Tag(name = "日志系统管理", description = "提供日志系统的进程管理、动态配置和文件配置接口")
@RestController
@RequestMapping("/api/log")
public class LogSystemController {

    // --- 1. 进程管理 ---

    @Operation(summary = "获取日志系统进程状态", description = "检查 Loki, Promtail, Grafana 进程是否在运行")
    @GetMapping("/process/status")
    public Map<String, Object> getProcessStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("loki", checkProcess("loki-windows-amd64.exe"));
        status.put("promtail", checkProcess("promtail-windows-amd64.exe"));
        status.put("grafana", checkProcess("grafana-server.exe"));
        return status;
    }

    @Operation(summary = "启动日志系统", description = "异步执行 start-logging.bat 脚本")
    @PostMapping("/process/start")
    public String startLogSystem() {
        // 假设 LogSystem 在项目根目录下
        File scriptFile = new File("LogSystem/Windows/start-logging.bat");
        if (!scriptFile.exists()) {
            // 尝试在上级目录查找 (兼容 IDEA 调试模式)
            scriptFile = new File("../LogSystem/Windows/start-logging.bat");
        }

        if (!scriptFile.exists()) {
            return "错误: 找不到启动脚本 start-logging.bat";
        }

        try {
            // 使用 cmd /c start 异步启动，避免阻塞
            String cmd = "cmd /c start \"LogSystem\" \"" + scriptFile.getAbsolutePath() + "\"";
            Runtime.getRuntime().exec(cmd);
            return "已触发启动脚本";
        } catch (IOException e) {
            return "启动失败: " + e.getMessage();
        }
    }

    @Operation(summary = "停止日志系统", description = "强制终止相关进程")
    @PostMapping("/process/stop")
    public String stopLogSystem() {
        StringBuilder result = new StringBuilder();
        result.append(killProcess("loki-windows-amd64.exe")).append("; ");
        result.append(killProcess("promtail-windows-amd64.exe")).append("; ");
        result.append(killProcess("grafana-server.exe"));
        return result.toString();
    }

    @Operation(summary = "重启日志系统", description = "先停止再启动")
    @PostMapping("/process/restart")
    public String restartLogSystem() {
        stopLogSystem();
        // 等待几秒确保进程结束
        try { Thread.sleep(2000); } catch (InterruptedException e) {}
        return startLogSystem();
    }

    private boolean checkProcess(String processName) {
        try {
            Process p = Runtime.getRuntime().exec("tasklist /FI \"IMAGENAME eq " + processName + "\"");
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains(processName)) {
                    return true;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    private String killProcess(String processName) {
        try {
            Runtime.getRuntime().exec("taskkill /F /IM " + processName);
            return "已停止 " + processName;
        } catch (IOException e) {
            return "停止 " + processName + " 失败: " + e.getMessage();
        }
    }

    // --- 2. 动态配置管理 ---

    @Operation(summary = "获取模块日志开关", description = "返回当前所有已注册模块的日志开启状态")
    @GetMapping("/config/modules")
    public Map<String, Boolean> getModuleConfig() {
        return AuditLogger.getModuleConfig();
    }

    @Operation(summary = "设置模块日志开关", description = "实时开启或关闭指定模块的日志记录")
    @PostMapping("/config/modules")
    public String setModuleConfig(
            @Parameter(description = "模块名称 (如 shop, login)", required = true) @RequestParam String module,
            @Parameter(description = "是否开启", required = true) @RequestParam boolean enabled) {
        AuditLogger.setModuleEnabled(module, enabled);
        return "模块 [" + module + "] 已" + (enabled ? "开启" : "关闭");
    }

    @Operation(summary = "获取 Logger 级别", description = "返回 Log4j2 中所有 Logger 的当前级别")
    @GetMapping("/config/levels")
    public Map<String, String> getLoggerLevels() {
        Map<String, String> levels = new HashMap<>();
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        ctx.getConfiguration().getLoggers().forEach((name, loggerConfig) -> {
            levels.put(name.isEmpty() ? "root" : name, loggerConfig.getLevel().toString());
        });
        return levels;
    }

    @Operation(summary = "设置 Logger 级别", description = "动态修改指定 Logger 的日志级别")
    @PostMapping("/config/levels")
    public String setLoggerLevel(
            @Parameter(description = "Logger 名称 (root 表示根 Logger)", required = true) @RequestParam String loggerName,
            @Parameter(description = "日志级别 (INFO, DEBUG, WARN, ERROR, OFF)", required = true) @RequestParam String level) {
        try {
            Level newLevel = Level.valueOf(level.toUpperCase());
            if ("root".equalsIgnoreCase(loggerName)) {
                Configurator.setRootLevel(newLevel);
            } else {
                Configurator.setLevel(loggerName, newLevel);
            }
            return "Logger [" + loggerName + "] 级别已设置为 " + newLevel;
        } catch (IllegalArgumentException e) {
            return "无效的日志级别: " + level;
        }
    }

    // --- 3. 静态文件配置管理 ---

    @Operation(summary = "获取配置文件列表", description = "返回可编辑的配置文件名列表")
    @GetMapping("/files")
    public List<String> getConfigFiles() {
        return Arrays.asList("loki-config.yaml", "promtail-config.yaml", "log4j2.xml");
    }

    @Operation(summary = "读取配置文件内容 (文本)", description = "以纯文本格式读取配置文件")
    @GetMapping("/files/{fileName}")
    public String readConfigFile(
            @Parameter(description = "文件名", required = true) @PathVariable String fileName) {
        File file = getConfigFile(fileName);
        if (file == null || !file.exists()) {
            return "文件不存在";
        }
        try {
            return Files.readString(file.toPath(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "读取失败: " + e.getMessage();
        }
    }

    @Operation(summary = "保存配置文件内容 (文本)", description = "以纯文本格式保存配置文件")
    @PostMapping("/files/{fileName}")
    public String saveConfigFile(
            @Parameter(description = "文件名", required = true) @PathVariable String fileName,
            @RequestBody String content) {
        File file = getConfigFile(fileName);
        if (file == null) {
            return "非法的文件名";
        }
        try {
            Files.writeString(file.toPath(), content, StandardCharsets.UTF_8);
            return "文件已保存";
        } catch (IOException e) {
            return "保存失败: " + e.getMessage();
        }
    }

    // --- 4. 结构化配置管理 (YAML/JSON) ---

    @Operation(summary = "读取 YAML 配置 (JSON)", description = "读取 YAML 配置文件并解析为 JSON 对象，方便前端编辑器使用")
    @GetMapping("/config/yaml/{fileName}")
    public Object getConfigYaml(
            @Parameter(description = "文件名 (仅限 .yaml 文件)", required = true) @PathVariable String fileName) {
        if (!fileName.endsWith(".yaml")) {
            return Collections.singletonMap("error", "仅支持 .yaml 文件");
        }
        File file = getConfigFile(fileName);
        if (file == null || !file.exists()) {
            return Collections.singletonMap("error", "文件不存在");
        }
        try {
            String content = Files.readString(file.toPath(), StandardCharsets.UTF_8);
            Yaml yaml = new Yaml();
            return yaml.load(content);
        } catch (Exception e) {
            return Collections.singletonMap("error", "解析失败: " + e.getMessage());
        }
    }

    @Operation(summary = "保存 YAML 配置 (JSON)", description = "接收 JSON 对象，转换为 YAML 格式并保存")
    @PostMapping("/config/yaml/{fileName}")
    public Map<String, String> saveConfigYaml(
            @Parameter(description = "文件名 (仅限 .yaml 文件)", required = true) @PathVariable String fileName,
            @RequestBody Map<String, Object> config) {
        if (!fileName.endsWith(".yaml")) {
            return Collections.singletonMap("error", "仅支持 .yaml 文件");
        }
        File file = getConfigFile(fileName);
        if (file == null) {
            return Collections.singletonMap("error", "非法的文件名");
        }
        try {
            Yaml yaml = new Yaml();
            String content = yaml.dumpAsMap(config);
            Files.writeString(file.toPath(), content, StandardCharsets.UTF_8);
            return Collections.singletonMap("status", "文件已保存");
        } catch (Exception e) {
            return Collections.singletonMap("error", "保存失败: " + e.getMessage());
        }
    }

    private File getConfigFile(String fileName) {
        String basePath = "LogSystem/Windows/config/";
        // 尝试在上级目录查找
        if (!new File(basePath).exists()) {
            basePath = "../LogSystem/Windows/config/";
        }

        switch (fileName) {
            case "loki-config.yaml":
                return new File(basePath + "loki-config.yaml");
            case "promtail-config.yaml":
                return new File(basePath + "promtail-config.yaml");
            case "log4j2.xml":
                // log4j2 通常在 resources 下，或者运行时指定的路径
                // 这里假设在 src/main/resources 下 (开发环境)
                // 或者在运行目录的 config 目录下 (生产环境)
                File prodFile = new File("config/log4j2.xml");
                if (prodFile.exists()) return prodFile;
                return new File("src/main/resources/log4j2.xml");
            default:
                return null;
        }
    }
}
