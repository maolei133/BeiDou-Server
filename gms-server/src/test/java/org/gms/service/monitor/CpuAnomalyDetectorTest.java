package org.gms.service.monitor;

import org.gms.model.dto.monitor.CpuMonitorConfigDTO;
import org.gms.model.dto.monitor.ServerMonitorHistoryPointDTO;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CpuAnomalyDetectorTest {

    @Test
    void skipsFirstAndNullSamples() {
        CpuAnomalyDetector detector = new CpuAnomalyDetector();

        CpuAnomalyDetector.Result first = detector.detect(point(1_000L, 0.91, false), List.of());
        CpuAnomalyDetector.Result missing = detector.detect(point(11_000L, null, false), List.of(point(1_000L, 0.91, false)));

        assertFalse(first.anomaly());
        assertFalse(missing.anomaly());
    }

    @Test
    void marksConfiguredCpuThresholdsAsWarning() {
        CpuAnomalyDetector detector = new CpuAnomalyDetector();
        List<ServerMonitorHistoryPointDTO> history = List.of(
                point(1_000L, 0.20, false)
        );

        CpuAnomalyDetector.Result result = detector.detect(point(11_000L, 0.52, false), history, CpuMonitorConfigDTO.defaults());

        assertTrue(result.anomaly());
        assertEquals("WARN", result.level());
        assertTrue(result.reason().contains("CPU threshold"));
    }

    @Test
    void marksConfiguredCpuThresholdsAsError() {
        CpuAnomalyDetector detector = new CpuAnomalyDetector();
        List<ServerMonitorHistoryPointDTO> history = List.of(
                point(1_000L, 0.20, false)
        );

        CpuAnomalyDetector.Result result = detector.detect(point(11_000L, 0.72, false), history, CpuMonitorConfigDTO.defaults());

        assertTrue(result.anomaly());
        assertEquals("ERROR", result.level());
    }

    @Test
    void usesHighestMatchingConfiguredRule() {
        CpuAnomalyDetector detector = new CpuAnomalyDetector();
        CpuMonitorConfigDTO config = CpuMonitorConfigDTO.builder().rules(List.of(
                CpuMonitorConfigDTO.Rule.builder().p(0.20D).lv("WARN").build(),
                CpuMonitorConfigDTO.Rule.builder().p(0.60D).lv("ERROR").build(),
                CpuMonitorConfigDTO.Rule.builder().p(0.80D).lv("WARN").build()
        )).build();

        CpuAnomalyDetector.Result result = detector.detect(point(11_000L, 0.82, false), List.of(point(1_000L, 0.20, false)), config);

        assertTrue(result.anomaly());
        assertEquals("WARN", result.level());
    }

    @Test
    void marksCpuSpikeAgainstBaseline() {
        CpuAnomalyDetector detector = new CpuAnomalyDetector();
        CpuMonitorConfigDTO config = CpuMonitorConfigDTO.builder().rules(List.of(
                CpuMonitorConfigDTO.Rule.builder().p(0.90D).lv("ERROR").build()
        )).build();
        List<ServerMonitorHistoryPointDTO> history = List.of(
                point(1_000L, 0.30, false),
                point(11_000L, 0.35, false),
                point(21_000L, 0.32, false),
                point(31_000L, 0.34, false),
                point(41_000L, 0.33, false)
        );

        CpuAnomalyDetector.Result result = detector.detect(point(51_000L, 0.76, false), history, config);

        assertTrue(result.anomaly());
        assertEquals("WARN", result.level());
        assertTrue(result.reason().contains("CPU spike"));
        assertNotNull(result.baseline());
    }

    @Test
    void ignoresPartialSamples() {
        CpuAnomalyDetector detector = new CpuAnomalyDetector();
        List<ServerMonitorHistoryPointDTO> history = List.of(
                point(1_000L, 0.96, false)
        );

        CpuAnomalyDetector.Result result = detector.detect(point(11_000L, 0.97, true), history);

        assertFalse(result.anomaly());
    }

    private static ServerMonitorHistoryPointDTO point(long sampledAt, Double cpu, boolean partial) {
        return ServerMonitorHistoryPointDTO.builder()
                .sampledAt(sampledAt)
                .systemCpuLoad(cpu)
                .partial(partial)
                .build();
    }
}
