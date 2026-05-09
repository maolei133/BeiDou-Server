package org.gms.service.monitor;

import org.gms.model.dto.monitor.CpuMonitorConfigDTO;
import org.gms.model.dto.monitor.ServerMonitorHistoryPointDTO;

import java.util.Comparator;
import java.util.List;
import java.util.Locale;

public class CpuAnomalyDetector {
    private static final double SPIKE_MIN_CURRENT = 0.70D;
    private static final double SPIKE_DELTA = 0.30D;
    private static final int BASELINE_POINTS = 5;
    private static final long MIN_INTERVAL_MS = 3_000L;
    private static final long MAX_INTERVAL_MS = 60_000L;

    public Result detect(ServerMonitorHistoryPointDTO current, List<ServerMonitorHistoryPointDTO> previousPoints) {
        return detect(current, previousPoints, CpuMonitorConfigDTO.defaults());
    }

    public Result detect(ServerMonitorHistoryPointDTO current, List<ServerMonitorHistoryPointDTO> previousPoints, CpuMonitorConfigDTO config) {
        if (current == null || current.getSystemCpuLoad() == null || Boolean.TRUE.equals(current.getPartial())) {
            return Result.normal();
        }
        double currentCpu = current.getSystemCpuLoad();
        if (!Double.isFinite(currentCpu) || currentCpu < 0D) {
            return Result.normal();
        }

        List<ServerMonitorHistoryPointDTO> validPrevious = previousPoints == null ? List.of() : previousPoints.stream()
                .filter(point -> point.getSampledAt() != null)
                .filter(point -> point.getSystemCpuLoad() != null)
                .filter(point -> !Boolean.TRUE.equals(point.getPartial()))
                .filter(point -> Double.isFinite(point.getSystemCpuLoad()))
                .sorted(Comparator.comparing(ServerMonitorHistoryPointDTO::getSampledAt).reversed())
                .toList();
        if (validPrevious.isEmpty()) {
            return Result.normal();
        }

        ServerMonitorHistoryPointDTO last = validPrevious.get(0);
        long interval = current.getSampledAt() != null ? current.getSampledAt() - last.getSampledAt() : 0L;
        if (interval < MIN_INTERVAL_MS || interval > MAX_INTERVAL_MS) {
            return Result.normal();
        }

        RuleMatch thresholdMatch = matchRule(currentCpu, normalize(config).getRules());
        if (thresholdMatch != null) {
            return new Result(true, thresholdMatch.level(), format("CPU threshold: current=%.2f%% threshold=%.2f%% level=" + thresholdMatch.level(), currentCpu, thresholdMatch.threshold()), null);
        }

        List<Double> baselineValues = validPrevious.stream()
                .limit(BASELINE_POINTS)
                .map(ServerMonitorHistoryPointDTO::getSystemCpuLoad)
                .toList();
        if (baselineValues.size() >= BASELINE_POINTS) {
            double baseline = baselineValues.stream().mapToDouble(Double::doubleValue).average().orElse(0D);
            double delta = currentCpu - baseline;
            if (currentCpu >= SPIKE_MIN_CURRENT && delta >= SPIKE_DELTA) {
                return new Result(true, "WARN", format("CPU spike: current=%.2f%% baseline=%.2f%% delta=%.2f%%", currentCpu, baseline, delta), baseline);
            }
        }
        return Result.normal();
    }

    public CpuMonitorConfigDTO normalize(CpuMonitorConfigDTO config) {
        List<CpuMonitorConfigDTO.Rule> rules = config == null ? List.of() : config.getRules();
        List<CpuMonitorConfigDTO.Rule> normalized = rules == null ? List.of() : rules.stream()
                .filter(rule -> rule != null && rule.getP() != null)
                .map(rule -> CpuMonitorConfigDTO.Rule.builder()
                        .p(Math.max(0D, Math.min(rule.getP(), 1D)))
                        .lv(normalizeLevel(rule.getLv()))
                        .build())
                .filter(rule -> rule.getP() > 0D)
                .sorted(Comparator.comparing(CpuMonitorConfigDTO.Rule::getP))
                .toList();
        return normalized.isEmpty() ? CpuMonitorConfigDTO.defaults() : CpuMonitorConfigDTO.builder().rules(normalized).build();
    }

    private RuleMatch matchRule(double currentCpu, List<CpuMonitorConfigDTO.Rule> rules) {
        RuleMatch matched = null;
        for (CpuMonitorConfigDTO.Rule rule : rules) {
            if (currentCpu >= rule.getP()) {
                matched = new RuleMatch(rule.getP(), rule.getLv());
            }
        }
        return matched;
    }

    private String normalizeLevel(String level) {
        if (level == null || level.isBlank()) {
            return "WARN";
        }
        String normalized = level.trim().toUpperCase(Locale.ROOT);
        return "ERROR".equals(normalized) ? "ERROR" : "WARN";
    }

    private static String format(String template, double... ratios) {
        Object[] percents = new Object[ratios.length];
        for (int i = 0; i < ratios.length; i++) {
            percents[i] = ratios[i] * 100D;
        }
        return String.format(Locale.ROOT, template, percents);
    }

    private record RuleMatch(double threshold, String level) {
    }

    public record Result(boolean anomaly, String level, String reason, Double baseline) {
        public static Result normal() {
            return new Result(false, null, null, null);
        }
    }
}
