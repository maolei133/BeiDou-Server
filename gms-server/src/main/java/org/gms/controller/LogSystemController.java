package org.gms.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;
import org.gms.model.dto.ResultBody;
import org.gms.server.logging.AuditLogger;
import org.gms.server.logging.LogAction;
import org.gms.server.logging.LogModule;
import org.gms.service.AccountService;
import org.gms.service.TraceabilityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.*;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Tag(name = "日志系统管理", description = "提供日志系统的进程管理、动态配置和文件配置接口")
@RestController
@RequestMapping("/log")
public class LogSystemController {

    private final ObjectMapper objectMapper;
    private final AccountService accountService;
    private final Environment environment;

    @Autowired
    public LogSystemController(ObjectMapper objectMapper, AccountService accountService, Environment environment) {
        this.objectMapper = objectMapper;
        this.accountService = accountService;
        this.environment = environment;
    }

    // --- 1. 进程管理 ---

    @Operation(summary = "获取日志系统进程状态", description = "检查 Loki, Promtail 进程是否在运行")
    @GetMapping("/process/status")
    public ResultBody<Map<String, Object>> getProcessStatus() {
        Map<String, Object> status = new HashMap<>();
        Map<String, String> config = readRuntimeConfig();

        // 分别获取 Loki 和 Promtail 的状态
        status.put("loki", checkProcessWithCrossPlatformFallback(config.get("LokiPID"), "loki", "gms-loki", getLokiUrl() + "/ready"));
        status.put("promtail", checkProcessWithCrossPlatformFallback(config.get("PromtailPID"), "promtail", "gms-promtail", resolvePromtailUrl() + "/ready"));
        
        return ResultBody.success(status);
    }

    @Operation(summary = "启动日志系统", description = "按当前平台异步执行 Windows bat 或 Linux/Docker sh 启动脚本")
    @PostMapping("/process/start")
    public ResultBody<String> startLogSystem() {
        if (!isWindows()) {
            String dockerResult = startLinuxDockerLogSystem();
            if (dockerResult != null) {
                return ResultBody.success(dockerResult);
            }
        }

        File scriptFile = getScriptFile();

        if (!scriptFile.exists()) {
            throw new RuntimeException("错误: 找不到启动脚本 " + scriptFile.getName() + " (路径: " + scriptFile.getAbsolutePath() + ")");
        }

        try {
            if (isWindows()) {
                // 使用 ProcessBuilder 替代 Runtime.exec
                // 关键修改：直接在 CMD 命令中切换目录，确保环境正确
                // cmd /c "cd /d 目录 && start 标题 脚本"
                String cmd = String.format("cd /d \"%s\" && start \"LogSystem\" \"%s\"",
                    scriptFile.getParentFile().getAbsolutePath(),
                    scriptFile.getName());

                new ProcessBuilder("cmd", "/c", cmd).start();
            } else {
                ProcessBuilder builder = new ProcessBuilder("bash", scriptFile.getAbsolutePath());
                builder.directory(resolveLinuxDockerWorkDir(scriptFile));
                builder.start();
            }

            return ResultBody.success("已触发启动脚本");
        } catch (IOException e) {
            throw new RuntimeException("启动失败: " + e.getMessage());
        }
    }

    @Operation(summary = "停止日志系统", description = "强制终止相关进程和窗口")
    @PostMapping("/process/stop")
    public ResultBody<String> stopLogSystem() {
        if (!isWindows()) {
            return ResultBody.success(stopLinuxDockerLogSystem());
        }

        Map<String, String> config = readRuntimeConfig();
        StringBuilder result = new StringBuilder();

        result.append(killProcess(config.get("LokiPID"), "Loki"));
        result.append("; ");
        result.append(killProcess(config.get("PromtailPID"), "Promtail"));

        // 强制清理可能残留的进程 (Zombie processes)，解决端口占用问题
        try {
            new ProcessBuilder("taskkill", "/F", "/IM", "loki-windows-amd64.exe").start();
            new ProcessBuilder("taskkill", "/F", "/IM", "promtail-windows-amd64.exe").start();
        } catch (IOException e) {
            // ignore
        }

        // 关闭 CMD 窗口 (通过 PID)
        String shellPid = config.get("ShellPID");
        if (shellPid != null && !shellPid.isEmpty()) {
            try {
                new ProcessBuilder("taskkill", "/F", "/PID", shellPid).start();
                result.append("; 已关闭控制窗口 (PID: ").append(shellPid).append(")");
            } catch (Exception e) {
                result.append("; 关闭窗口失败: ").append(e.getMessage());
            }
        } else {
            // 兼容旧模式：尝试通过窗口标题关闭
             try {
                new ProcessBuilder("taskkill", "/F", "/FI", "WINDOWTITLE eq LogSystem").start();
                result.append("; 已关闭控制窗口 (Title)");
            } catch (IOException e) {
                // ignore
            }
        }

        // 清理配置文件，避免下次误读
        File configFile = new File(getBinDir().getParentFile(), "config/runtime.ini");
        if (configFile.exists()) {
            configFile.delete();
        }

        return ResultBody.success(result.toString());
    }

    @Operation(summary = "重启日志系统", description = "先停止再启动")
    @PostMapping("/process/restart")
    public ResultBody<String> restartLogSystem() {
        stopLogSystem();
        // 等待几秒确保进程结束
        try { Thread.sleep(2000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        return startLogSystem();
    }

    @Operation(summary = "重置日志系统 (重新采集)", description = "停止系统，删除 positions 文件，然后启动")
    @PostMapping("/process/reset")
    public ResultBody<String> resetLogSystem() {
        // 1. 停止
        stopLogSystem();
        try { Thread.sleep(2000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }

        if (isWindows()) {
            // 2. 删除 positions 文件
            File positionsFile = new File(getBinDir().getParentFile(), "config/promtail-positions.yaml");
            if (positionsFile.exists()) {
                positionsFile.delete();
            }
        } else {
            resetLinuxDockerPositions();
        }

        // 3. 启动
        return startLogSystem();
    }

    private File getScriptFile() {
        // 优先查找 LogSystem 目录
        String[] candidates = isWindows()
                ? new String[] {
                    "LogSystem/Windows/start-logging.bat",
                    "../LogSystem/Windows/start-logging.bat",
                    "../../LogSystem/Windows/start-logging.bat" // 应对更深层级的部署结构
                }
                : new String[] {
                    "LogSystem/Docker/start-logging.sh",
                    "../LogSystem/Docker/start-logging.sh",
                    "../../LogSystem/Docker/start-logging.sh" // 应对更深层级的部署结构
                };

        for (String path : candidates) {
            File file = new File(path);
            if (file.exists()) {
                return file;
            }
        }
        // 默认返回第一个，即使不存在
        return new File(candidates[0]);
    }

    private File getBinDir() {
        // 优先查找包含核心可执行文件的目录，确保路径正确
        String[] candidates = {"LogSystem/Windows/bin/", "../LogSystem/Windows/bin/", "../../LogSystem/Windows/bin/"};

        for (String path : candidates) {
            File dir = new File(path);
            // 检查目录是否存在，且包含 loki 可执行文件，防止误判空目录
            if (dir.exists() && new File(dir, "loki-windows-amd64.exe").exists()) {
                return dir;
            }
        }

        // 默认返回第一个，即使不存在 (避免空指针，后续逻辑会处理 exists 检查)
        return new File(candidates[0]);
    }

    private Map<String, String> readRuntimeConfig() {
        Map<String, String> config = new HashMap<>();
        if (!isWindows()) {
            return config;
        }
        File configFile = new File(getBinDir().getParentFile(), "config/runtime.ini");
        if (configFile.exists()) {
            try {
                List<String> lines = Files.readAllLines(configFile.toPath(), StandardCharsets.UTF_8);
                for (String line : lines) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("[") || line.startsWith(";")) continue;
                    String[] parts = line.split("=", 2);
                    if (parts.length == 2) {
                        config.put(parts[0].trim(), parts[1].trim());
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return config;
    }

    private Long checkProcess(String pidStr) {
        if (pidStr == null || pidStr.isEmpty()) return null;
        if (!isWindows()) return null;
        try {
            // 验证是否为数字
            Long.parseLong(pidStr);
            Process p = new ProcessBuilder("tasklist", "/FI", "PID eq " + pidStr).start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            boolean isRunning = false;
            while ((line = reader.readLine()) != null) {
                if (line.contains(pidStr)) {
                    isRunning = true;
                    break;
                }
            }

            if (isRunning) {
                // 如果进程在运行，返回 runtime.ini 的最后修改时间作为启动时间
                File configFile = new File(getBinDir().getParentFile(), "config/runtime.ini");
                return configFile.exists() ? configFile.lastModified() : System.currentTimeMillis();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private Long checkProcessWithCrossPlatformFallback(String pidStr, String processName, String dockerContainerName, String healthUrl) {
        Long windowsStartTime = checkProcess(pidStr);
        if (windowsStartTime != null) {
            return windowsStartTime;
        }
        if (isWindows()) {
            return null;
        }
        Long dockerStartTime = checkDockerContainer(dockerContainerName);
        if (dockerStartTime != null) {
            return dockerStartTime;
        }
        Long linuxStartTime = checkLinuxProcess(processName);
        if (linuxStartTime != null) {
            return linuxStartTime;
        }
        Long httpStartTime = checkHttpStartTime(healthUrl.replaceAll("/ready$", "/metrics"));
        if (httpStartTime != null) {
            return httpStartTime;
        }
        return checkHttpHealth(healthUrl);
    }

    private boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    private Long checkDockerContainer(String containerName) {
        try {
            Process p = new ProcessBuilder("docker", "inspect", "-f", "{{.State.Running}} {{.State.StartedAt}}", containerName).start();
            String output = readProcessOutput(p);
            if (!p.waitFor(3, java.util.concurrent.TimeUnit.SECONDS) || p.exitValue() != 0) {
                return null;
            }
            String[] parts = output.trim().split("\\s+", 2);
            if (parts.length == 2 && "true".equalsIgnoreCase(parts[0])) {
                return java.time.Instant.parse(parts[1]).toEpochMilli();
            }
        } catch (Exception ignored) {
            // Docker 不可用或当前部署不是 Docker 模式时，继续尝试 Linux 进程和 HTTP 健康检查。
        }
        return null;
    }

    private Long checkLinuxProcess(String processName) {
        try {
            Process p = new ProcessBuilder("pgrep", "-xo", processName).start();
            String pid = readProcessOutput(p).trim();
            if (!p.waitFor(3, java.util.concurrent.TimeUnit.SECONDS) || p.exitValue() != 0 || pid.isBlank()) {
                return null;
            }
            Process started = new ProcessBuilder("ps", "-o", "lstart=", "-p", pid).start();
            String startedAt = readProcessOutput(started).trim();
            if (!started.waitFor(3, java.util.concurrent.TimeUnit.SECONDS) || started.exitValue() != 0 || startedAt.isBlank()) {
                return null;
            }
            return java.time.ZonedDateTime.parse(startedAt, java.time.format.DateTimeFormatter.ofPattern("EEE MMM d HH:mm:ss yyyy", Locale.ENGLISH).withZone(java.time.ZoneId.systemDefault())).toInstant().toEpochMilli();
        } catch (Exception ignored) {
            // 进程名不可见或 ps 时间格式无法解析时，继续尝试 HTTP 健康检查。
        }
        return null;
    }

    private Long checkHttpHealth(String url) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(3))
                    .GET()
                    .build();
            HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() >= 200 && response.statusCode() < 300 ? System.currentTimeMillis() : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private Long checkHttpStartTime(String url) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(3))
                    .GET()
                    .build();
            HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                return null;
            }
            for (String line : response.body().split("\\R")) {
                if (line.startsWith("process_start_time_seconds ")) {
                    double seconds = Double.parseDouble(line.substring("process_start_time_seconds ".length()).trim());
                    return (long) (seconds * 1000L);
                }
            }
        } catch (Exception ignored) {
            return null;
        }
        return null;
    }

    private String readProcessOutput(Process process) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            return reader.lines().collect(Collectors.joining("\n"));
        }
    }

    private String readProcessError(Process process) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8))) {
            return reader.lines().collect(Collectors.joining("\n"));
        }
    }

    private String resolvePromtailUrl() {
        String configuredUrl = environment.getProperty("gms.log.promtail-url");
        if (configuredUrl == null || configuredUrl.isBlank()) {
            configuredUrl = environment.getProperty("GMS_LOG_PROMTAIL_URL");
        }
        if (configuredUrl == null || configuredUrl.isBlank()) {
            configuredUrl = System.getenv("GMS_LOG_PROMTAIL_URL");
        }
        if (configuredUrl == null || configuredUrl.isBlank()) {
            configuredUrl = "http://127.0.0.1:9080";
        }
        return configuredUrl.trim().replaceAll("/+$", "");
    }

    private String killProcess(String pidStr, String name) {
        if (pidStr == null || pidStr.isEmpty()) {
            return name + " 未运行";
        }
        try {
            new ProcessBuilder("taskkill", "/F", "/PID", pidStr).start();
            return "已停止 " + name + "(PID: " + pidStr + ")";
        } catch (Exception e) {
            return "停止 " + name + " 失败: " + e.getMessage();
        }
    }

    private File resolveLinuxDockerWorkDir(File scriptFile) {
        File composeDir = findComposeDirFrom(new File(System.getProperty("user.dir", ".")));
        if (composeDir != null) {
            return composeDir;
        }
        File scriptDir = scriptFile.getParentFile();
        return scriptDir != null ? scriptDir : new File(System.getProperty("user.dir", "."));
    }

    private File findComposeDirFrom(File startDir) {
        File current = startDir.getAbsoluteFile();
        while (current != null) {
            if (new File(current, "docker-compose.yml").exists() || new File(current, "compose.yml").exists()) {
                return current;
            }
            current = current.getParentFile();
        }
        return null;
    }

    private String startLinuxDockerLogSystem() {
        if (canAccessDockerSocket()) {
            String loki = callDockerContainerAction("gms-loki", "start", "Loki");
            String promtail = callDockerContainerAction("gms-promtail", "start", "Promtail");
            if (!loki.contains("失败") && !promtail.contains("失败")) {
                return loki + "; " + promtail;
            }
            throw new RuntimeException("启动失败: " + loki + "; " + promtail);
        }
        File scriptFile = getScriptFile();
        if (!scriptFile.exists()) {
            return null;
        }
        return null;
    }

    private String stopLinuxDockerLogSystem() {
        if (canAccessDockerSocket()) {
            String loki = callDockerContainerAction("gms-loki", "stop", "Loki");
            String promtail = callDockerContainerAction("gms-promtail", "stop", "Promtail");
            if (!loki.contains("失败") && !promtail.contains("失败")) {
                return loki + "; " + promtail;
            }
            throw new RuntimeException("停止失败: " + loki + "; " + promtail);
        }

        StringBuilder result = new StringBuilder();
        boolean stoppedByCompose = stopDockerComposeServices(result);
        if (!stoppedByCompose) {
            result.append(stopDockerContainer("gms-loki", "Loki"));
            result.append("; ");
            result.append(stopDockerContainer("gms-promtail", "Promtail"));
        }
        if (!stoppedByCompose && result.toString().contains("Docker 不可用")) {
            result.append("; ").append(killLinuxProcessByName("loki", "Loki"));
            result.append("; ").append(killLinuxProcessByName("promtail", "Promtail"));
        }
        if (result.toString().contains("Docker 不可用") && result.toString().contains("未运行")) {
            throw new RuntimeException("停止失败: 当前容器没有 Docker 控制能力。请挂载 /var/run/docker.sock，或在宿主机执行 LogSystem/Docker/start-logging.sh patch compose 后重建 gms-server。");
        }
        return result.toString();
    }

    private boolean canAccessDockerSocket() {
        return new File("/var/run/docker.sock").exists();
    }

    private String callDockerContainerAction(String containerName, String action, String name) {
        try {
            Process p = new ProcessBuilder(
                    "curl", "-sS", "--unix-socket", "/var/run/docker.sock",
                    "-X", "POST",
                    "-o", "-",
                    "-w", "\n%{http_code}",
                    "http://localhost/containers/" + containerName + "/" + action)
                    .start();
            String output = readProcessOutput(p);
            String error = readProcessError(p);
            if (!p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)) {
                return name + " " + action + " 失败: Docker API 超时";
            }
            int exitCode = p.exitValue();
            if (exitCode != 0) {
                return name + " " + action + " 失败: " + (error.isBlank() ? output : error);
            }
            String[] lines = output.strip().split("\\R");
            String httpCode = lines.length == 0 ? "000" : lines[lines.length - 1].trim();
            if ("204".equals(httpCode)) {
                return "已" + ("start".equals(action) ? "启动" : "停止") + " " + name + " 容器(" + containerName + ")";
            }
            if ("304".equals(httpCode)) {
                return name + " 容器(" + containerName + ")" + ("start".equals(action) ? "已在运行" : "已停止");
            }
            return name + " " + action + " 失败: Docker API HTTP " + httpCode;
        } catch (Exception e) {
            return name + " " + action + " 失败: " + e.getMessage();
        }
    }

    private boolean stopDockerComposeServices(StringBuilder result) {
        File composeDir = findComposeDirFrom(new File(System.getProperty("user.dir", ".")));
        if (composeDir == null) {
            return false;
        }
        try {
            Process p = new ProcessBuilder("docker", "compose", "stop", "loki", "promtail")
                    .directory(composeDir)
                    .start();
            String output = readProcessOutput(p);
            String error = readProcessError(p);
            if (p.waitFor(30, java.util.concurrent.TimeUnit.SECONDS) && p.exitValue() == 0) {
                result.append("已停止 Docker Compose 日志服务");
                if (!output.isBlank()) {
                    result.append(": ").append(output.replaceAll("\\s+", " ").trim());
                }
                return true;
            }
            if (!error.isBlank()) {
                result.append("Docker Compose 停止失败: ").append(error.replaceAll("\\s+", " ").trim());
            }
        } catch (Exception ignored) {
            // Docker Compose 不可用时，继续尝试固定容器名或 Linux 进程方式。
        }
        return false;
    }

    private String stopDockerContainer(String containerName, String name) {
        try {
            Process p = new ProcessBuilder("docker", "stop", containerName).start();
            String output = readProcessOutput(p);
            String error = readProcessError(p);
            if (p.waitFor(15, java.util.concurrent.TimeUnit.SECONDS) && p.exitValue() == 0) {
                return "已停止 " + name + " 容器(" + containerName + ")";
            }
            return name + " 容器停止失败: " + (error.isBlank() ? output : error);
        } catch (Exception e) {
            return "Docker 不可用，无法停止 " + name + " 容器: " + e.getMessage();
        }
    }

    private String killLinuxProcessByName(String processName, String name) {
        try {
            Process find = new ProcessBuilder("pgrep", "-xo", processName).start();
            String pid = readProcessOutput(find).trim();
            if (!find.waitFor(3, java.util.concurrent.TimeUnit.SECONDS) || find.exitValue() != 0 || pid.isBlank()) {
                return name + " 未运行";
            }
            Optional<ProcessHandle> handle = ProcessHandle.of(Long.parseLong(pid));
            if (handle.isPresent()) {
                handle.get().destroy();
                return "已停止 " + name + "(PID: " + pid + ")";
            }
        } catch (Exception e) {
            return "停止 " + name + " 失败: " + e.getMessage();
        }
        return name + " 未运行";
    }

    private void resetLinuxDockerPositions() {
        File positionsFile = getPromtailPositionsFile();
        if (positionsFile.exists()) {
            try {
                Files.delete(positionsFile.toPath());
            } catch (IOException e) {
                throw new RuntimeException("删除 Promtail positions 文件失败: " + e.getMessage());
            }
        }
    }

    private File getPromtailPositionsFile() {
        String configured = environment.getProperty("gms.log.promtail-positions-file");
        if (configured == null || configured.isBlank()) {
            configured = environment.getProperty("GMS_LOG_PROMTAIL_POSITIONS_FILE");
        }
        if (configured == null || configured.isBlank()) {
            configured = System.getenv("GMS_LOG_PROMTAIL_POSITIONS_FILE");
        }
        if (configured != null && !configured.isBlank()) {
            return new File(configured.trim());
        }
        File configDir = resolveConfigDir();
        return new File(configDir, "promtail-positions.yaml");
    }

    // --- 2. 动态配置管理 ---

    @Operation(summary = "获取所有查询选项", description = "一次性获取模块、动作、行为类型和来源的列表，用于前端查询下拉框")
    @GetMapping("/config/all-options")
    public ResultBody<Map<String, List<Map<String, Object>>>> getAllOptions() {
        Map<String, List<Map<String, Object>>> result = new HashMap<>();
        result.put("modules", getEnumOptions(LogModule.class, e -> ((LogModule) e).getI18nVal()));
        result.put("actions", getEnumOptions(LogAction.class, e -> ((LogAction) e).getI18nVal()));
        result.put("traceabilityActionTypes", getEnumOptions(TraceabilityService.ActionType.class, e -> ((TraceabilityService.ActionType) e).getI18nVal()));
        result.put("traceabilityActionSourceTypes", getEnumOptions(TraceabilityService.ActionSourceType.class, e -> ((TraceabilityService.ActionSourceType) e).getI18nVal()));
        return ResultBody.success(result);
    }

    private <T extends Enum<T>> List<Map<String, Object>> getEnumOptions(Class<T> enumClass, java.util.function.Function<T, String> i18nMapper) {
        return Stream.of(enumClass.getEnumConstants())
                .map(e -> {
                    Map<String, Object> map = new HashMap<>();
                    map.put("value", e.name());
                    map.put("label", i18nMapper.apply(e));
                    return map;
                })
                .collect(Collectors.toList());
    }

    @Operation(summary = "获取模块列表", description = "返回所有日志模块及其国际化名称")
    @GetMapping("/config/modules")
    public ResultBody<List<Map<String, Object>>> getModules() {
        return ResultBody.success(getEnumOptions(LogModule.class, e -> ((LogModule) e).getI18nVal()));
    }

    @Operation(summary = "获取动作列表", description = "返回所有日志动作及其国际化名称")
    @GetMapping("/config/actions")
    public ResultBody<List<Map<String, Object>>> getActions() {
        return ResultBody.success(getEnumOptions(LogAction.class, e -> ((LogAction) e).getI18nVal()));
    }

    @Operation(summary = "获取模块日志开关", description = "返回当前所有已注册模块的日志开启状态")
    @GetMapping("/config/module-switches")
    public ResultBody<Map<String, Boolean>> getModuleSwitches() {
        return ResultBody.success(AuditLogger.getModuleConfig());
    }

    @Operation(summary = "设置模块日志开关", description = "实时开启或关闭指定模块的日志记录")
    @PostMapping("/config/module-switches")
    public ResultBody<String> setModuleConfig(
            @Parameter(description = "模块名称 (如 SHOP, LOGIN)", required = true) @RequestParam String module,
            @Parameter(description = "是否开启", required = true) @RequestParam boolean enabled) {
        AuditLogger.setModuleEnabled(module, enabled);
        return ResultBody.success("模块 [" + module + "] 已" + (enabled ? "开启" : "关闭"));
    }

    @Operation(summary = "获取 Logger 级别", description = "返回 Log4j2 中所有 Logger 的当前级别")
    @GetMapping("/config/levels")
    public ResultBody<Map<String, String>> getLoggerLevels() {
        Map<String, String> levels = new HashMap<>();
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        ctx.getConfiguration().getLoggers().forEach((name, loggerConfig) -> {
            levels.put(name.isEmpty() ? "root" : name, loggerConfig.getLevel().toString());
        });
        return ResultBody.success(levels);
    }

    @Operation(summary = "设置 Logger 级别", description = "动态修改指定 Logger 的日志级别")
    @PostMapping("/config/levels")
    public ResultBody<String> setLoggerLevel(
            @Parameter(description = "Logger 名称 (root 表示根 Logger)", required = true) @RequestParam String loggerName,
            @Parameter(description = "日志级别 (INFO, DEBUG, WARN, ERROR, OFF)", required = true) @RequestParam String level) {
        try {
            Level newLevel = Level.valueOf(level.toUpperCase());
            if ("root".equalsIgnoreCase(loggerName)) {
                Configurator.setRootLevel(newLevel);
            } else {
                Configurator.setLevel(loggerName, newLevel);
            }
            return ResultBody.success("Logger [" + loggerName + "] 级别已设置为 " + newLevel);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("无效的日志级别: " + level);
        }
    }

    // --- 3. 静态文件配置管理 ---

    @Operation(summary = "获取配置文件列表", description = "返回可编辑的配置文件名列表")
    @GetMapping("/files")
    public ResultBody<List<String>> getConfigFiles() {
        // 移除了 dashboard-layout.json
        return ResultBody.success(Arrays.asList("loki-config.yaml", "promtail-config.yaml", "log4j2.xml", "dashboard-layout.json"));
    }

    @Operation(summary = "读取配置文件内容 (文本)", description = "以纯文本格式读取配置文件")
    @GetMapping("/files/{fileName}")
    public ResultBody<String> readConfigFile(
            @Parameter(description = "文件名", required = true) @PathVariable String fileName) {
        File file = getConfigFile(fileName);
        if (file == null) {
            throw new RuntimeException("非法的文件名: " + fileName);
        }
        
        // 修复：dashboard-layout.json 不存在时返回默认空数组，不报错
        if (!file.exists()) {
            if ("dashboard-layout.json".equals(fileName)) {
                return ResultBody.success("[]");
            }
            throw new RuntimeException("文件不存在: " + file.getAbsolutePath());
        }
        
        try {
            return ResultBody.success(Files.readString(file.toPath(), StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new RuntimeException("读取失败 [" + fileName + "]: " + e.getMessage());
        }
    }

    @Operation(summary = "保存配置文件内容 (文本)", description = "以纯文本格式保存配置文件")
    @PostMapping("/files/{fileName}")
    public ResultBody<String> saveConfigFile(
            @Parameter(description = "文件名", required = true) @PathVariable String fileName,
            @RequestBody String content) {
        File file = getConfigFile(fileName);
        if (file == null) {
            throw new RuntimeException("非法的文件名: " + fileName);
        }
        try {
            Files.writeString(file.toPath(), content, StandardCharsets.UTF_8);
            return ResultBody.success("文件已保存");
        } catch (IOException e) {
            throw new RuntimeException("保存失败 [" + fileName + "]: " + e.getMessage());
        }
    }

    // --- 4. 结构化配置管理 (YAML/JSON) ---

    @Operation(summary = "读取 YAML 配置 (JSON)", description = "读取 YAML 配置文件并解析为 JSON 对象，方便前端编辑器使用")
    @GetMapping("/config/yaml/{fileName}")
    public ResultBody<Object> getConfigYaml(
            @Parameter(description = "文件名 (仅限 .yaml 文件)", required = true) @PathVariable String fileName) {
        if (!fileName.endsWith(".yaml")) {
            throw new RuntimeException("仅支持 .yaml 文件");
        }
        File file = getConfigFile(fileName);
        if (file == null) {
            throw new RuntimeException("非法的文件名: " + fileName);
        }
        if (!file.exists()) {
            throw new RuntimeException("文件不存在: " + file.getAbsolutePath());
        }
        try {
            String content = Files.readString(file.toPath(), StandardCharsets.UTF_8);
            Yaml yaml = new Yaml();
            return ResultBody.success(yaml.load(content));
        } catch (Exception e) {
            throw new RuntimeException("解析失败 [" + fileName + "]: " + e.getMessage());
        }
    }

    @Operation(summary = "保存 YAML 配置 (JSON)", description = "接收 JSON 对象，转换为 YAML 格式并保存")
    @PostMapping("/config/yaml/{fileName}")
    public ResultBody<Map<String, String>> saveConfigYaml(
            @Parameter(description = "文件名 (仅限 .yaml 文件)", required = true) @PathVariable String fileName,
            @RequestBody Map<String, Object> config) {
        if (!fileName.endsWith(".yaml")) {
            throw new RuntimeException("仅支持 .yaml 文件");
        }
        File file = getConfigFile(fileName);
        if (file == null) {
            throw new RuntimeException("非法的文件名: " + fileName);
        }
        try {
            DumperOptions options = new DumperOptions();
            options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK); // 使用块风格，更易读
            options.setPrettyFlow(true);
            
            Yaml yaml = new Yaml(options);
            String content = yaml.dump(config); // 使用 dump 而不是 dumpAsMap，以支持更复杂的结构
            Files.writeString(file.toPath(), content, StandardCharsets.UTF_8);
            return ResultBody.success(Collections.singletonMap("status", "文件已保存"));
        } catch (Exception e) {
            throw new RuntimeException("保存失败 [" + fileName + "]: " + e.getMessage());
        }
    }
    
    // --- 5. 自动填充搜索 ---
    
    @Operation(summary = "搜索账号", description = "根据关键词搜索账号名或ID")
    @GetMapping("/search/account")
    public ResultBody<List<Map<String, Object>>> searchAccount(@RequestParam String keyword) {
        return ResultBody.success(accountService.searchAccounts(keyword));
    }
    
    @Operation(summary = "搜索角色", description = "根据关键词搜索角色名或ID")
    @GetMapping("/search/character")
    public ResultBody<List<Map<String, Object>>> searchCharacter(@RequestParam String keyword) {
        return ResultBody.success(accountService.searchCharacters(keyword));
    }
    
    @Operation(summary = "搜索IP", description = "根据关键词搜索IP")
    @GetMapping("/search/ip")
    public ResultBody<List<String>> searchIp(@RequestParam String keyword) {
        return ResultBody.success(accountService.searchIps(keyword));
    }
    
    @Operation(summary = "搜索MAC", description = "根据关键词搜索MAC")
    @GetMapping("/search/mac")
    public ResultBody<List<String>> searchMac(@RequestParam String keyword) {
        return ResultBody.success(accountService.searchMacs(keyword));
    }
    
    @Operation(summary = "搜索HWID", description = "根据关键词搜索HWID")
    @GetMapping("/search/hwid")
    public ResultBody<List<String>> searchHwid(@RequestParam String keyword) {
        return ResultBody.success(accountService.searchHwids(keyword));
    }

    // --- 6. 日志查询代理 (Loki) ---

    private final HttpClient httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    // 动态获取 Loki URL
    private String getLokiUrl() {
        String configuredUrl = environment.getProperty("gms.log.loki-url");
        if (configuredUrl == null || configuredUrl.isBlank()) {
            configuredUrl = environment.getProperty("GMS_LOG_LOKI_URL");
        }
        if (configuredUrl == null || configuredUrl.isBlank()) {
            configuredUrl = System.getenv("GMS_LOG_LOKI_URL");
        }
        if (configuredUrl != null && !configuredUrl.isBlank()) {
            return configuredUrl.trim().replaceAll("/+$", "");
        }

        String defaultUrl = "http://127.0.0.1:3100";
        File configFile = getConfigFile("loki-config.yaml");
        if (configFile == null || !configFile.exists()) {
            return defaultUrl;
        }

        try {
            String content = Files.readString(configFile.toPath(), StandardCharsets.UTF_8);
            Yaml yaml = new Yaml();
            Map<String, Object> config = yaml.load(content);
            
            String host = "127.0.0.1";
            int port = 3100;

            if (config.containsKey("common")) {
                Map<String, Object> common = (Map<String, Object>) config.get("common");
                if (common.containsKey("instance_addr")) {
                    host = common.get("instance_addr").toString();
                }
            }
            
            if (config.containsKey("server")) {
                Map<String, Object> server = (Map<String, Object>) config.get("server");
                if (server.containsKey("http_listen_port")) {
                    port = Integer.parseInt(server.get("http_listen_port").toString());
                }
            }
            
            return "http://" + host + ":" + port;
        } catch (Exception e) {
            // 解析失败，回退到默认值
            return defaultUrl;
        }
    }

    @Operation(summary = "查询日志 (Range)", description = "查询指定时间范围内的日志")
    @GetMapping("/query/range")
    public ResultBody<Object> queryLokiRange(
            @Parameter(description = "LogQL 查询语句") @RequestParam String query,
            @Parameter(description = "开始时间 (纳秒)") @RequestParam(required = false) Long start,
            @Parameter(description = "结束时间 (纳秒)") @RequestParam(required = false) Long end,
            @Parameter(description = "时间范围 (如 1h, 24h)") @RequestParam(required = false) String range,
            @Parameter(description = "条数限制") @RequestParam(defaultValue = "100") Integer limit,
            @Parameter(description = "方向 (BACKWARD/FORWARD)") @RequestParam(defaultValue = "BACKWARD") String direction) {
        
        try {
            long nowNs = System.currentTimeMillis() * 1000000L;
            Long finalStart = start;
            Long finalEnd = end;

            // 1. 如果未指定 start/end，但指定了 range，则使用服务器时间计算
            if (finalStart == null && finalEnd == null && range != null && !range.isEmpty()) {
                long durationNs = parseDurationToNs(range);
                finalEnd = nowNs;
                finalStart = nowNs - durationNs;
            }

            // 2. 自动修正时间戳单位 (毫秒 -> 纳秒)
            // 阈值判断：当前时间(ms)约 1.7e12，当前时间(ns)约 1.7e18
            // 如果传入的值小于 1e14，则认为是毫秒，需要乘以 1,000,000
            if (finalStart != null && finalStart < 100000000000000L) {
                finalStart *= 1000000L;
            }
            if (finalEnd != null && finalEnd < 100000000000000L) {
                finalEnd *= 1000000L;
            }

            // 构建 URL
            StringBuilder urlBuilder = new StringBuilder(getLokiUrl() + "/loki/api/v1/query_range");
            urlBuilder.append("?query=").append(java.net.URLEncoder.encode(query, StandardCharsets.UTF_8));
            if (finalStart != null) urlBuilder.append("&start=").append(finalStart);
            if (finalEnd != null) urlBuilder.append("&end=").append(finalEnd);
            urlBuilder.append("&limit=").append(limit);
            urlBuilder.append("&direction=").append(direction);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(urlBuilder.toString()))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            // 关键修改：将 Loki 返回的 JSON 字符串解析为 Java 对象
            Object jsonObject = objectMapper.readValue(response.body(), Object.class);
            return ResultBody.success(jsonObject);
        } catch (Exception e) {
            throw new RuntimeException("查询失败: " + e.getMessage());
        }
    }

    private long parseDurationToNs(String range) {
        if (range == null || range.isEmpty()) return 3600L * 1000000000L; // Default 1h
        long multiplier = 1;
        String numberPart = range;
        try {
            if (range.endsWith("ms")) {
                multiplier = 1000000L;
                numberPart = range.substring(0, range.length() - 2);
            } else if (range.endsWith("s")) {
                multiplier = 1000000000L;
                numberPart = range.substring(0, range.length() - 1);
            } else if (range.endsWith("m")) {
                multiplier = 60L * 1000000000L;
                numberPart = range.substring(0, range.length() - 1);
            } else if (range.endsWith("h")) {
                multiplier = 3600L * 1000000000L;
                numberPart = range.substring(0, range.length() - 1);
            } else if (range.endsWith("d")) {
                multiplier = 24L * 3600L * 1000000000L;
                numberPart = range.substring(0, range.length() - 1);
            }
            return Long.parseLong(numberPart) * multiplier;
        } catch (Exception e) {
            return 3600L * 1000000000L; // Default 1h on error
        }
    }
    
    @Operation(summary = "获取日志统计 (图表)", description = "获取各模块的日志数量统计")
    @GetMapping("/query/stats")
    public ResultBody<Map<String, Object>> getLogStats(@RequestParam(defaultValue = "1h") String range) {
        Map<String, Object> stats = new HashMap<>();
        
        // 查询最近一段时间各模块的日志量
        String query = "sum by (mod) (count_over_time({job=\"gms-audit\"}[" + range + "]))";
        
        try {
             StringBuilder urlBuilder = new StringBuilder(getLokiUrl() + "/loki/api/v1/query_range");
             urlBuilder.append("?query=").append(java.net.URLEncoder.encode(query, StandardCharsets.UTF_8));
             urlBuilder.append("&limit=1000");
             
             HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(urlBuilder.toString()))
                    .GET()
                    .build();
             HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
             
             stats.put("query", query);
             // 同样解析为对象
             stats.put("raw", objectMapper.readValue(response.body(), Object.class));
             return ResultBody.success(stats);
        } catch (Exception e) {
            throw new RuntimeException("统计失败: " + e.getMessage());
        }
    }

    private File getConfigFile(String fileName) {
        switch (fileName) {
            case "loki-config.yaml":
                return new File(resolveConfigDir(), "loki-config.yaml");
            case "promtail-config.yaml":
                return resolvePromtailConfigFile();
            case "dashboard-layout.json":
                return new File(resolveConfigDir(), "dashboard-layout.json");
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

    private File resolveConfigDir() {
        String configuredDir = environment.getProperty("gms.log.config-dir");
        if (configuredDir == null || configuredDir.isBlank()) {
            configuredDir = environment.getProperty("GMS_LOG_CONFIG_DIR");
        }
        if (configuredDir == null || configuredDir.isBlank()) {
            configuredDir = System.getenv("GMS_LOG_CONFIG_DIR");
        }
        if (configuredDir != null && !configuredDir.isBlank()) {
            return new File(configuredDir.trim());
        }

        List<String> candidates = new ArrayList<>();
        if (isWindows()) {
            candidates.add("LogSystem/Windows/config/");
            candidates.add("../LogSystem/Windows/config/");
            candidates.add("../../LogSystem/Windows/config/");
        } else {
            candidates.add("docker/");
            candidates.add("../docker/");
            candidates.add("../../docker/");
            candidates.add("LogSystem/Docker/runtime/docker/");
            candidates.add("../LogSystem/Docker/runtime/docker/");
            candidates.add("../../LogSystem/Docker/runtime/docker/");
            candidates.add("LogSystem/Windows/config/");
            candidates.add("../LogSystem/Windows/config/");
            candidates.add("../../LogSystem/Windows/config/");
        }

        for (String path : candidates) {
            File dir = new File(path);
            if (dir.exists()) {
                return dir;
            }
        }
        return new File(candidates.get(0));
    }

    private File resolvePromtailConfigFile() {
        File configDir = resolveConfigDir();
        File yamlFile = new File(configDir, "promtail-config.yaml");
        if (yamlFile.exists()) {
            return yamlFile;
        }
        File ymlFile = new File(configDir, "promtail-config.yml");
        if (ymlFile.exists()) {
            return ymlFile;
        }
        return yamlFile;
    }
}
