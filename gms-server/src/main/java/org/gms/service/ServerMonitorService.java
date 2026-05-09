package org.gms.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.management.OperatingSystemMXBean;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.gms.config.GameConfig;
import org.gms.constants.net.ServerConstants;
import org.gms.model.dto.monitor.ContainerInfoDTO;
import org.gms.model.dto.monitor.CpuInfoDTO;
import org.gms.model.dto.monitor.CpuMonitorConfigDTO;
import org.gms.model.dto.monitor.DiskInfoDTO;
import org.gms.model.dto.monitor.DiskIoInfoDTO;
import org.gms.model.dto.monitor.JvmInfoDTO;
import org.gms.model.dto.monitor.MemoryInfoDTO;
import org.gms.model.dto.monitor.NetworkInfoDTO;
import org.gms.model.dto.monitor.NetworkInterfaceInfoDTO;
import org.gms.model.dto.monitor.RuntimeInfoDTO;
import org.gms.model.dto.monitor.SampleInfoDTO;
import org.gms.model.dto.monitor.ServerInfoDTO;
import org.gms.model.dto.monitor.ServerMonitorEventDTO;
import org.gms.model.dto.monitor.ServerMonitorHistoryDTO;
import org.gms.model.dto.monitor.ServerMonitorHistoryPointDTO;
import org.gms.model.dto.monitor.ServerMonitorSnapshotDTO;
import org.gms.net.server.Server;
import org.gms.server.logging.AuditLogger;
import org.gms.service.monitor.ContainerRuntimeDetector;
import org.gms.service.monitor.CpuAnomalyDetector;
import org.gms.service.monitor.LinuxProcMonitorCollector;
import org.apache.logging.log4j.message.MapMessage;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.File;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryUsage;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadMXBean;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

@Slf4j
@Service
public class ServerMonitorService {
    private static final Logger monitorEventLog = LogManager.getLogger("monitor-event");
    private static final String DISK_IO_NOTE = "Disk IO rate counters require Linux /proc/diskstats and two samples.";
    private static final int DEFAULT_HISTORY_MINUTES = 5;
    private static final int MAX_HISTORY_MINUTES = 7 * 24 * 60;
    private static final int SNAPSHOT_INTERVAL_SECONDS = 10;
    private static final String MONITOR_SNAPSHOT_LOGQL = "{job=\"gms-audit\", mod=\"MONITOR\", act=\"MONITOR_SNAPSHOT\"}";
    private static final int MAX_MEMORY_POINTS = MAX_HISTORY_MINUTES * 6 + 30;
    private static final String CPU_MON_CONFIG_SUB_TYPE = "monitor";
    private static final String CPU_MON_CONFIG_CODE = "cpu_mon";
    private static final String CPU_MON_CONFIG_DESC = "CPU 监控阈值配置";

    private final Environment environment;
    private final ObjectMapper objectMapper;
    private final ConfigService configService;
    private final LinuxProcMonitorCollector procCollector = new LinuxProcMonitorCollector();
    private final ContainerRuntimeDetector containerRuntimeDetector = new ContainerRuntimeDetector();
    private final CpuAnomalyDetector cpuAnomalyDetector = new CpuAnomalyDetector();
    private final HttpClient httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    private final List<ServerMonitorHistoryPointDTO> recentHistory = new ArrayList<>();
    private volatile ServerMonitorSnapshotDTO latestSnapshot;

    public ServerMonitorService(Environment environment, ObjectMapper objectMapper, ConfigService configService) {
        this.environment = environment;
        this.objectMapper = objectMapper;
        this.configService = configService;
    }

    public ServerMonitorSnapshotDTO getSnapshot() {
        ServerMonitorSnapshotDTO snapshot = latestSnapshot;
        if (snapshot != null) {
            return snapshot;
        }
        snapshot = collectSnapshot();
        latestSnapshot = snapshot;
        return snapshot;
    }

    public synchronized ServerMonitorSnapshotDTO collectSnapshot() {
        long sampledAt = System.currentTimeMillis();
        RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
        List<String> warnings = new ArrayList<>();
        LinuxProcMonitorCollector.ProcSample procSample = procCollector.collect();
        warnings.addAll(procSample.getWarnings());
        ContainerInfoDTO containerInfo = containerRuntimeDetector.detect(warnings);

        return ServerMonitorSnapshotDTO.builder()
                .sample(SampleInfoDTO.builder()
                        .sampledAt(sampledAt)
                        .sampledAtIso(Instant.ofEpochMilli(sampledAt).toString())
                        .partial(procSample.isPartial() || !warnings.isEmpty())
                        .warnings(warnings)
                        .build())
                .server(buildServerInfo())
                .runtime(buildRuntimeInfo(runtimeMXBean))
                .cpu(buildCpuInfo(procSample))
                .jvm(buildJvmInfo())
                .disks(buildDiskInfo())
                .diskIo(procSample.getDiskIo() != null ? procSample.getDiskIo() : DiskIoInfoDTO.builder()
                        .available(false)
                        .note(DISK_IO_NOTE)
                        .build())
                .network(buildNetworkInfo(procSample))
                .container(containerInfo)
                .build();
    }


    @Scheduled(fixedDelay = 10_000L, initialDelay = 2_000L)
    public void emitScheduledSnapshotEvent() {
        long startedAt = System.currentTimeMillis();
        try {
            ServerMonitorSnapshotDTO snapshot = collectSnapshot();
            CpuMonitorConfigDTO cpuConfig = getCpuMonitorConfig();
            List<ServerMonitorHistoryPointDTO> previousPoints = getRecentHistoryPoints(System.currentTimeMillis() - 10L * 60L * 1000L, System.currentTimeMillis(), 30);
            CpuAnomalyDetector.Result anomaly = cpuAnomalyDetector.detect(toHistoryPoint(snapshot, null), previousPoints, cpuConfig);
            ServerMonitorHistoryPointDTO point = toHistoryPoint(snapshot, anomaly);
            appendRecentHistory(point);
            emitMonitorEvent("MONITOR_SNAPSHOT", point);
            if (anomaly.anomaly()) {
                emitMonitorEvent("CPU_ANOMALY", point);
            }
            latestSnapshot = snapshot;
            long costMs = System.currentTimeMillis() - startedAt;
            if (costMs > 200L) {
                log.warn("Server monitor snapshot collection took {}ms", costMs);
            }
        } catch (Exception e) {
            log.warn("Failed to emit server monitor snapshot event", e);
        }
    }

    public CpuMonitorConfigDTO getCpuMonitorConfig() {
        CpuMonitorConfigDTO config = GameConfig.get("server", CPU_MON_CONFIG_SUB_TYPE, CPU_MON_CONFIG_CODE, null);
        CpuMonitorConfigDTO normalized = cpuAnomalyDetector.normalize(config);
        if (config == null || !Objects.equals(writeJson(config), writeJson(normalized))) {
            persistCpuMonitorConfig(normalized);
        }
        return normalized;
    }

    public CpuMonitorConfigDTO updateCpuMonitorConfig(CpuMonitorConfigDTO config) {
        CpuMonitorConfigDTO normalized = cpuAnomalyDetector.normalize(config);
        persistCpuMonitorConfig(normalized);
        return normalized;
    }

    private void persistCpuMonitorConfig(CpuMonitorConfigDTO config) {
        String json = writeJson(config);
        if (json == null) {
            return;
        }
        configService.upsertServerConfig(
                CPU_MON_CONFIG_SUB_TYPE,
                CPU_MON_CONFIG_CODE,
                CpuMonitorConfigDTO.class.getName(),
                json,
                CPU_MON_CONFIG_DESC
        );
    }

    public ServerMonitorHistoryDTO getHistory(Integer minutes) {
        return getHistory(minutes, null, null, null);
    }

    public ServerMonitorHistoryDTO getHistory(Integer minutes, String range, Long start, Long end) {
        long to = end != null ? normalizeTimestampMs(end) : System.currentTimeMillis();
        int safeMinutes = normalizeMinutes(minutes, range, start, end);
        long from = start != null ? normalizeTimestampMs(start) : to - safeMinutes * 60_000L;
        if (from > to) {
            long tmp = from;
            from = to;
            to = tmp;
        }
        safeMinutes = (int) Math.max(1L, Math.min(MAX_HISTORY_MINUTES, (long) Math.ceil((to - from) / 60_000.0D)));

        List<ServerMonitorHistoryPointDTO> points = loadHistoryPointsFromLoki(from, to, safeMinutes);
        if (points.isEmpty()) {
            points = getRecentHistoryPoints(from, to, safeMinutes * 6 + 10);
        }
        final long finalFrom = from;
        final long finalTo = to;
        points = points.stream()
                .filter(point -> point.getSampledAt() != null && point.getSampledAt() >= finalFrom && point.getSampledAt() <= finalTo)
                .sorted((a, b) -> Long.compare(a.getSampledAt(), b.getSampledAt()))
                .toList();

        List<ServerMonitorEventDTO> events = buildEventsFromPoints(points);
        return ServerMonitorHistoryDTO.builder()
                .from(from)
                .to(to)
                .minutes(safeMinutes)
                .intervalSeconds(SNAPSHOT_INTERVAL_SECONDS)
                .points(downsample(points, maxReturnPoints(safeMinutes)))
                .events(events)
                .build();
    }

    private int normalizeMinutes(Integer minutes) {
        return normalizeMinutes(minutes, null, null, null);
    }

    private int normalizeMinutes(Integer minutes, String range, Long start, Long end) {
        if (start != null && end != null) {
            long diffMs = Math.abs(normalizeTimestampMs(end) - normalizeTimestampMs(start));
            return (int) Math.max(1L, Math.min(MAX_HISTORY_MINUTES, (long) Math.ceil(diffMs / 60_000.0D)));
        }
        if (range != null && !range.isBlank()) {
            return (int) Math.max(1L, Math.min(MAX_HISTORY_MINUTES, parseRangeToMinutes(range)));
        }
        if (minutes == null) {
            return DEFAULT_HISTORY_MINUTES;
        }
        return Math.max(1, Math.min(MAX_HISTORY_MINUTES, minutes));
    }

    private long normalizeTimestampMs(long value) {
        return value > 100_000_000_000_000L ? value / 1_000_000L : value;
    }

    private long parseRangeToMinutes(String range) {
        String value = range.trim().toLowerCase(Locale.ROOT);
        try {
            if (value.endsWith("ms")) return Math.max(1L, Long.parseLong(value.substring(0, value.length() - 2)) / 60_000L);
            if (value.endsWith("s")) return Math.max(1L, Long.parseLong(value.substring(0, value.length() - 1)) / 60L);
            if (value.endsWith("m")) return Long.parseLong(value.substring(0, value.length() - 1));
            if (value.endsWith("h")) return Long.parseLong(value.substring(0, value.length() - 1)) * 60L;
            if (value.endsWith("d")) return Long.parseLong(value.substring(0, value.length() - 1)) * 24L * 60L;
            return Long.parseLong(value);
        } catch (Exception ignored) {
            return DEFAULT_HISTORY_MINUTES;
        }
    }

    private List<ServerMonitorHistoryPointDTO> loadHistoryPointsFromLoki(long from, long to, int minutes) {
        String lokiUrl = resolveLokiUrl();
        if (lokiUrl == null || lokiUrl.isBlank()) {
            return List.of();
        }
        try {
            int limit = Math.min(100_000, Math.max(100, minutes * 6 + 100));
            StringBuilder url = new StringBuilder(lokiUrl.replaceAll("/+$", ""));
            url.append("/loki/api/v1/query_range");
            url.append("?query=").append(URLEncoder.encode(MONITOR_SNAPSHOT_LOGQL, StandardCharsets.UTF_8));
            url.append("&start=").append(from * 1_000_000L);
            url.append("&end=").append(to * 1_000_000L);
            url.append("&limit=").append(limit);
            url.append("&direction=FORWARD");
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url.toString()))
                    .timeout(Duration.ofSeconds(8))
                    .GET()
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < HttpURLConnection.HTTP_OK || response.statusCode() >= HttpURLConnection.HTTP_MULT_CHOICE) {
                log.warn("Loki monitor history query failed with status {}", response.statusCode());
                return List.of();
            }
            return parseLokiHistoryPoints(response.body());
        } catch (Exception e) {
            log.warn("Failed to query monitor history from Loki, fallback to memory window: {}", e.getMessage());
            return List.of();
        }
    }

    private String resolveLokiUrl() {
        String configuredUrl = environment.getProperty("gms.log.loki-url");
        if (configuredUrl == null || configuredUrl.isBlank()) {
            configuredUrl = environment.getProperty("GMS_LOG_LOKI_URL");
        }
        if (configuredUrl == null || configuredUrl.isBlank()) {
            configuredUrl = System.getenv("GMS_LOG_LOKI_URL");
        }
        if (configuredUrl == null || configuredUrl.isBlank()) {
            configuredUrl = "http://127.0.0.1:3100";
        }
        return configuredUrl.trim();
    }

    private List<ServerMonitorHistoryPointDTO> parseLokiHistoryPoints(String body) throws JsonProcessingException {
        JsonNode root = objectMapper.readTree(body);
        JsonNode results = root.path("data").path("result");
        if (!results.isArray()) {
            return List.of();
        }
        List<ServerMonitorHistoryPointDTO> points = new ArrayList<>();
        for (JsonNode stream : results) {
            JsonNode values = stream.path("values");
            if (!values.isArray()) continue;
            for (JsonNode value : values) {
                if (!value.isArray() || value.size() < 2) continue;
                String line = value.get(1).asText("");
                ServerMonitorHistoryPointDTO point = parseMonitorLine(line);
                if (point != null && point.getSampledAt() != null) points.add(point);
            }
        }
        points.sort((a, b) -> Long.compare(a.getSampledAt(), b.getSampledAt()));
        return points;
    }

    private ServerMonitorHistoryPointDTO parseMonitorLine(String line) {
        try {
            JsonNode node = objectMapper.readTree(line);
            Long sampledAt = longValue(node, "sampledAt");
            if (sampledAt == null) sampledAt = longValue(node, "ts");
            String sampledAtIso = textValue(node, "sampledAtIso");
            if ((sampledAtIso == null || sampledAtIso.isBlank()) && sampledAt != null) {
                sampledAtIso = Instant.ofEpochMilli(sampledAt).toString();
            }
            return ServerMonitorHistoryPointDTO.builder()
                    .sampledAt(sampledAt)
                    .sampledAtIso(sampledAtIso)
                    .systemCpuLoad(doubleValue(node, "systemCpuLoad"))
                    .processCpuLoad(doubleValue(node, "processCpuLoad"))
                    .systemLoadAverage(doubleValue(node, "systemLoadAverage"))
                    .systemMemoryUsage(doubleValue(node, "systemMemoryUsage"))
                    .jvmHeapUsage(doubleValue(node, "jvmHeapUsage"))
                    .jvmNonHeapUsage(doubleValue(node, "jvmNonHeapUsage"))
                    .threadCount(integerValue(node, "threadCount"))
                    .gcCount(longValue(node, "gcCount"))
                    .gcTimeMs(longValue(node, "gcTimeMs"))
                    .diskUsageMax(doubleValue(node, "diskUsageMax"))
                    .networkRxBytesPerSecond(doubleValue(node, "networkRxBytesPerSecond"))
                    .networkTxBytesPerSecond(doubleValue(node, "networkTxBytesPerSecond"))
                    .diskReadBytesPerSecond(doubleValue(node, "diskReadBytesPerSecond"))
                    .diskWriteBytesPerSecond(doubleValue(node, "diskWriteBytesPerSecond"))
                    .cpuAnomaly(booleanValue(node, "cpuAnomaly"))
                    .cpuAnomalyLevel(textValue(node, "cpuAnomalyLevel"))
                    .cpuAnomalyReason(textValue(node, "cpuAnomalyReason"))
                    .cpuAnomalyBaseline(doubleValue(node, "cpuAnomalyBaseline"))
                    .partial(booleanValue(node, "partial"))
                    .warnings(parseWarnings(node.path("warnings")))
                    .build();
        } catch (Exception e) {
            log.debug("Skip unparsable monitor log line", e);
            return null;
        }
    }

    private List<ServerMonitorEventDTO> buildEventsFromPoints(List<ServerMonitorHistoryPointDTO> points) {
        return points.stream()
                .filter(point -> Boolean.TRUE.equals(point.getCpuAnomaly()))
                .map(point -> ServerMonitorEventDTO.builder()
                        .occurredAt(point.getSampledAt())
                        .occurredAtIso(point.getSampledAtIso())
                        .type("CPU_ANOMALY")
                        .level(point.getCpuAnomalyLevel())
                        .message(point.getCpuAnomalyReason())
                        .value(point.getSystemCpuLoad())
                        .baseline(point.getCpuAnomalyBaseline())
                        .build())
                .toList();
    }

    private int maxReturnPoints(int minutes) {
        if (minutes <= 60) return minutes * 6 + 30;
        if (minutes <= 24 * 60) return 600;
        return 1200;
    }

    private List<ServerMonitorHistoryPointDTO> downsample(List<ServerMonitorHistoryPointDTO> points, int maxPoints) {
        if (points.size() <= maxPoints) return points;
        List<ServerMonitorHistoryPointDTO> result = new ArrayList<>(maxPoints);
        double step = (double) points.size() / maxPoints;
        for (int i = 0; i < maxPoints; i++) {
            result.add(points.get(Math.min(points.size() - 1, (int) Math.floor(i * step))));
        }
        return result.stream().filter(Objects::nonNull).toList();
    }

    private Double doubleValue(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (value.isMissingNode() || value.isNull()) return null;
        try {
            String text = value.asText();
            if (text == null || text.isBlank()) return null;
            double parsed = Double.parseDouble(text);
            return Double.isFinite(parsed) ? parsed : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private Long longValue(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (value.isMissingNode() || value.isNull()) return null;
        try {
            String text = value.asText();
            if (text == null || text.isBlank()) return null;
            return Long.parseLong(text);
        } catch (Exception ignored) {
            return null;
        }
    }

    private Integer integerValue(JsonNode node, String field) {
        Long value = longValue(node, field);
        return value == null ? null : value.intValue();
    }

    private Boolean booleanValue(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (value.isMissingNode() || value.isNull()) return null;
        String text = value.asText();
        if (text == null || text.isBlank()) return null;
        return Boolean.parseBoolean(text);
    }

    private String textValue(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (value.isMissingNode() || value.isNull()) return null;
        String text = value.asText();
        return text == null || text.isBlank() ? null : text;
    }

    private List<String> parseWarnings(JsonNode value) {
        if (value == null || value.isMissingNode() || value.isNull()) return List.of();
        try {
            if (value.isArray()) {
                List<String> warnings = new ArrayList<>();
                value.forEach(item -> warnings.add(item.asText()));
                return warnings;
            }
            String text = value.asText();
            if (text == null || text.isBlank()) return List.of();
            JsonNode array = objectMapper.readTree(text);
            if (array.isArray()) {
                List<String> warnings = new ArrayList<>();
                array.forEach(item -> warnings.add(item.asText()));
                return warnings;
            }
        } catch (Exception ignored) {
            return List.of(value.asText());
        }
        return List.of(value.asText());
    }

    private synchronized void appendRecentHistory(ServerMonitorHistoryPointDTO point) {
        recentHistory.removeIf(item -> item.getSampledAt() != null && item.getSampledAt().equals(point.getSampledAt()));
        recentHistory.add(point);
        recentHistory.sort((a, b) -> Long.compare(a.getSampledAt() == null ? 0L : a.getSampledAt(), b.getSampledAt() == null ? 0L : b.getSampledAt()));
        while (recentHistory.size() > MAX_MEMORY_POINTS) {
            recentHistory.remove(0);
        }
    }

    private synchronized List<ServerMonitorHistoryPointDTO> getRecentHistoryPoints(long from, long to, int limit) {
        return recentHistory.stream()
                .filter(point -> point.getSampledAt() != null && point.getSampledAt() >= from && point.getSampledAt() <= to)
                .limit(Math.max(1, limit))
                .toList();
    }

    private void emitMonitorEvent(String eventType, ServerMonitorHistoryPointDTO point) {
        MapMessage data = new MapMessage()
                .with("eventType", eventType)
                .with("msg", eventType)
                .with("sampledAt", String.valueOf(point.getSampledAt()))
                .with("sampledAtIso", String.valueOf(point.getSampledAtIso()))
                .with("systemCpuLoad", stringValue(point.getSystemCpuLoad()))
                .with("processCpuLoad", stringValue(point.getProcessCpuLoad()))
                .with("systemLoadAverage", stringValue(point.getSystemLoadAverage()))
                .with("systemMemoryUsage", stringValue(point.getSystemMemoryUsage()))
                .with("jvmHeapUsage", stringValue(point.getJvmHeapUsage()))
                .with("jvmNonHeapUsage", stringValue(point.getJvmNonHeapUsage()))
                .with("threadCount", stringValue(point.getThreadCount()))
                .with("gcCount", stringValue(point.getGcCount()))
                .with("gcTimeMs", stringValue(point.getGcTimeMs()))
                .with("diskUsageMax", stringValue(point.getDiskUsageMax()))
                .with("networkRxBytesPerSecond", stringValue(point.getNetworkRxBytesPerSecond()))
                .with("networkTxBytesPerSecond", stringValue(point.getNetworkTxBytesPerSecond()))
                .with("diskReadBytesPerSecond", stringValue(point.getDiskReadBytesPerSecond()))
                .with("diskWriteBytesPerSecond", stringValue(point.getDiskWriteBytesPerSecond()))
                .with("cpuAnomaly", stringValue(point.getCpuAnomaly()))
                .with("partial", stringValue(point.getPartial()))
                .with("warnings", writeJson(point.getWarnings()));
        if (point.getCpuAnomalyLevel() != null) data.with("cpuAnomalyLevel", point.getCpuAnomalyLevel());
        if (point.getCpuAnomalyReason() != null) data.with("cpuAnomalyReason", point.getCpuAnomalyReason());
        if (point.getCpuAnomalyBaseline() != null) data.with("cpuAnomalyBaseline", stringValue(point.getCpuAnomalyBaseline()));
        String json = writeJson(data.getData());
        if (json != null) {
            writeMonitorEventLog(eventType, point.getCpuAnomalyLevel(), json);
        }
        if ("CPU_ANOMALY".equals(eventType) && "ERROR".equalsIgnoreCase(point.getCpuAnomalyLevel())) {
            AuditLogger.error("MONITOR", eventType, data, null);
        } else {
            AuditLogger.info("MONITOR", eventType, data);
        }
    }

    private void writeMonitorEventLog(String eventType, String level, String json) {
        if (!"CPU_ANOMALY".equals(eventType)) {
            monitorEventLog.info(json);
            return;
        }
        if ("ERROR".equalsIgnoreCase(level)) {
            monitorEventLog.error(json);
            return;
        }
        monitorEventLog.warn(json);
    }

    private String stringValue(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private ServerMonitorHistoryPointDTO toHistoryPoint(ServerMonitorSnapshotDTO snapshot, CpuAnomalyDetector.Result anomaly) {
        CpuInfoDTO cpu = snapshot.getCpu();
        JvmInfoDTO jvm = snapshot.getJvm();
        SampleInfoDTO sample = snapshot.getSample();
        return ServerMonitorHistoryPointDTO.builder()
                .sampledAt(sample != null ? sample.getSampledAt() : null)
                .sampledAtIso(sample != null ? sample.getSampledAtIso() : null)
                .systemCpuLoad(cpu != null ? cpu.getSystemCpuLoad() : null)
                .processCpuLoad(cpu != null ? cpu.getProcessCpuLoad() : null)
                .systemLoadAverage(cpu != null ? cpu.getSystemLoadAverage() : null)
                .systemMemoryUsage(cpu != null && cpu.getSystemMemory() != null ? cpu.getSystemMemory().getUsage() : null)
                .jvmHeapUsage(jvm != null && jvm.getHeap() != null ? jvm.getHeap().getUsage() : null)
                .jvmNonHeapUsage(jvm != null && jvm.getNonHeap() != null ? jvm.getNonHeap().getUsage() : null)
                .threadCount(jvm != null ? jvm.getThreadCount() : null)
                .gcCount(jvm != null ? jvm.getGcCount() : null)
                .gcTimeMs(jvm != null ? jvm.getGcTimeMs() : null)
                .diskUsageMax(snapshot.getDisks() == null ? null : snapshot.getDisks().stream()
                        .map(DiskInfoDTO::getUsage)
                        .filter(value -> value != null && Double.isFinite(value))
                        .max(Double::compareTo)
                        .orElse(null))
                .networkRxBytesPerSecond(snapshot.getNetwork() != null ? snapshot.getNetwork().getRxBytesPerSecond() : null)
                .networkTxBytesPerSecond(snapshot.getNetwork() != null ? snapshot.getNetwork().getTxBytesPerSecond() : null)
                .diskReadBytesPerSecond(snapshot.getDiskIo() != null ? snapshot.getDiskIo().getReadBytesPerSecond() : null)
                .diskWriteBytesPerSecond(snapshot.getDiskIo() != null ? snapshot.getDiskIo().getWriteBytesPerSecond() : null)
                .cpuAnomaly(anomaly != null && anomaly.anomaly())
                .cpuAnomalyLevel(anomaly != null ? anomaly.level() : null)
                .cpuAnomalyReason(anomaly != null ? anomaly.reason() : null)
                .cpuAnomalyBaseline(anomaly != null ? anomaly.baseline() : null)
                .partial(sample != null ? sample.getPartial() : null)
                .warnings(sample != null ? sample.getWarnings() : List.of())
                .build();
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            return null;
        }
    }

    private ServerInfoDTO buildServerInfo() {
        return ServerInfoDTO.builder()
                .online(Server.getInstance().isOnline())
                .version(ServerConstants.BEI_DOU_VERSION)
                .build();
    }

    private RuntimeInfoDTO buildRuntimeInfo(RuntimeMXBean runtimeMXBean) {
        long startedAt = runtimeMXBean.getStartTime();
        return RuntimeInfoDTO.builder()
                .pid(ProcessHandle.current().pid())
                .uptimeMs(runtimeMXBean.getUptime())
                .startedAt(startedAt)
                .startedAtIso(Instant.ofEpochMilli(startedAt).toString())
                .userDir(System.getProperty("user.dir"))
                .environment(resolveEnvironment())
                .activeProfiles(environment.getActiveProfiles())
                .build();
    }

    private CpuInfoDTO buildCpuInfo(LinuxProcMonitorCollector.ProcSample procSample) {
        java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
        CpuInfoDTO.CpuInfoDTOBuilder builder = CpuInfoDTO.builder()
                .osName(System.getProperty("os.name"))
                .osVersion(System.getProperty("os.version"))
                .osArch(System.getProperty("os.arch"))
                .processorModel(resolveProcessorModel())
                .availableProcessors(osBean.getAvailableProcessors())
                .systemLoadAverage(normalizeLoad(osBean.getSystemLoadAverage()));

        if (osBean instanceof OperatingSystemMXBean extendedOsBean) {
            builder.processCpuLoad(normalizeLoad(extendedOsBean.getProcessCpuLoad()))
                    .systemCpuLoad(normalizeLoad(extendedOsBean.getCpuLoad()));
        }
        if (procSample.getSystemCpuLoad() != null) {
            builder.systemCpuLoad(procSample.getSystemCpuLoad());
        }
        if (procSample.getSystemMemory() != null) {
            builder.systemMemory(procSample.getSystemMemory());
        }
        return builder.build();
    }


    private String resolveProcessorModel() {
        String osName = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (!osName.contains("linux")) {
            return null;
        }
        Path cpuInfo = Path.of("/proc/cpuinfo");
        try {
            if (!Files.isReadable(cpuInfo)) {
                return null;
            }
            for (String line : Files.readAllLines(cpuInfo)) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2 && "model name".equalsIgnoreCase(parts[0].trim())) {
                    String value = parts[1].trim();
                    return value.isEmpty() ? null : value;
                }
            }
        } catch (Exception ignored) {
            return null;
        }
        return null;
    }

    private JvmInfoDTO buildJvmInfo() {
        ThreadMXBean threadMXBean = ManagementFactory.getThreadMXBean();
        RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
        long gcCount = 0L;
        long gcTimeMs = 0L;
        for (GarbageCollectorMXBean gcBean : ManagementFactory.getGarbageCollectorMXBeans()) {
            if (gcBean.getCollectionCount() >= 0) {
                gcCount += gcBean.getCollectionCount();
            }
            if (gcBean.getCollectionTime() >= 0) {
                gcTimeMs += gcBean.getCollectionTime();
            }
        }

        return JvmInfoDTO.builder()
                .javaVersion(System.getProperty("java.version"))
                .javaVendor(System.getProperty("java.vendor"))
                .vmName(runtimeMXBean.getVmName())
                .vmVersion(runtimeMXBean.getVmVersion())
                .heap(toMemoryInfo(ManagementFactory.getMemoryMXBean().getHeapMemoryUsage()))
                .nonHeap(toMemoryInfo(ManagementFactory.getMemoryMXBean().getNonHeapMemoryUsage()))
                .threadCount(threadMXBean.getThreadCount())
                .daemonThreadCount(threadMXBean.getDaemonThreadCount())
                .peakThreadCount(threadMXBean.getPeakThreadCount())
                .totalStartedThreadCount(threadMXBean.getTotalStartedThreadCount())
                .gcCount(gcCount)
                .gcTimeMs(gcTimeMs)
                .build();
    }

    private MemoryInfoDTO toMemoryInfo(MemoryUsage memoryUsage) {
        long used = memoryUsage.getUsed();
        long max = memoryUsage.getMax();
        return MemoryInfoDTO.builder()
                .init(memoryUsage.getInit())
                .used(used)
                .committed(memoryUsage.getCommitted())
                .max(max)
                .usage(max > 0 ? (double) used / max : null)
                .build();
    }

    private List<DiskInfoDTO> buildDiskInfo() {
        File[] roots = File.listRoots();
        if (roots == null) {
            return Collections.emptyList();
        }
        List<DiskInfoDTO> disks = new ArrayList<>();
        for (File root : roots) {
            long total = root.getTotalSpace();
            long free = root.getFreeSpace();
            long usable = root.getUsableSpace();
            long used = Math.max(0L, total - free);
            disks.add(DiskInfoDTO.builder()
                    .path(root.getAbsolutePath())
                    .total(total)
                    .free(free)
                    .usable(usable)
                    .used(used)
                    .usage(total > 0 ? (double) used / total : null)
                    .build());
        }
        return disks;
    }

    private NetworkInfoDTO buildNetworkInfo(LinuxProcMonitorCollector.ProcSample procSample) {
        return NetworkInfoDTO.builder()
                .hostName(resolveHostName())
                .interfaces(resolveNetworkInterfaces())
                .rxBytesPerSecond(procSample.getNetworkRxBytesPerSecond())
                .txBytesPerSecond(procSample.getNetworkTxBytesPerSecond())
                .build();
    }

    private String resolveHostName() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            return null;
        }
    }

    private List<NetworkInterfaceInfoDTO> resolveNetworkInterfaces() {
        List<NetworkInterfaceInfoDTO> result = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            if (interfaces == null) {
                return result;
            }
            while (interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                result.add(NetworkInterfaceInfoDTO.builder()
                        .name(networkInterface.getName())
                        .displayName(networkInterface.getDisplayName())
                        .up(networkInterface.isUp())
                        .loopback(networkInterface.isLoopback())
                        .virtual(networkInterface.isVirtual())
                        .mtu(networkInterface.getMTU())
                        .addresses(networkInterface.inetAddresses()
                                .map(InetAddress::getHostAddress)
                                .toList())
                        .build());
            }
        } catch (Exception e) {
            return result;
        }
        return result;
    }

    private String resolveEnvironment() {
        String[] activeProfiles = environment.getActiveProfiles();
        if (activeProfiles.length > 0) {
            return String.join(",", activeProfiles);
        }

        String configuredEnv = firstNonBlank(
                environment.getProperty("spring.profiles.active"),
                environment.getProperty("spring.profiles.default"),
                environment.getProperty("app.env"),
                environment.getProperty("application.environment")
        );
        if (configuredEnv != null) {
            return configuredEnv;
        }

        String userDir = System.getProperty("user.dir", "").toLowerCase(Locale.ROOT);
        if (userDir.contains("prod")) {
            return "prod";
        }
        if (userDir.contains("test")) {
            return "test";
        }
        if (userDir.contains("dev")) {
            return "dev";
        }
        return "unknown";
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private Double normalizeLoad(double value) {
        return value >= 0 ? value : null;
    }
}


