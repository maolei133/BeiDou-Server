package org.gms.service.monitor;

import org.gms.model.dto.monitor.DiskIoInfoDTO;
import org.gms.model.dto.monitor.MemoryInfoDTO;
import oshi.SystemInfo;
import oshi.hardware.CentralProcessor;
import oshi.hardware.GlobalMemory;
import oshi.hardware.HWDiskStore;
import oshi.hardware.HardwareAbstractionLayer;
import oshi.hardware.NetworkIF;
import oshi.software.os.OSProcess;
import oshi.software.os.OperatingSystem;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 基于 OSHI 的跨平台指标采集器，用于 Windows 与其他非 Linux 系统。
 */
public class OshiSystemMetricsCollector implements SystemMetricsCollector {
    private static final String DISK_IO_FIRST_SAMPLE_NOTE = "磁盘 IO 速率需要两次采样，下次请求后可用。";
    private static final String DISK_IO_UNAVAILABLE_NOTE = "当前平台无法采集磁盘 IO 速率。";

    private final SystemInfo systemInfo;
    private final HardwareAbstractionLayer hardware;
    private final OperatingSystem operatingSystem;
    private OshiCounters previous;

    public OshiSystemMetricsCollector() {
        this(new SystemInfo());
    }

    OshiSystemMetricsCollector(SystemInfo systemInfo) {
        this.systemInfo = systemInfo;
        this.hardware = systemInfo.getHardware();
        this.operatingSystem = systemInfo.getOperatingSystem();
    }

    @Override
    public synchronized SystemMetricsSample collect() {
        return collect(null);
    }

    @Override
    public synchronized SystemMetricsSample collect(String networkInterfaceName) {
        long now = System.currentTimeMillis();
        OshiCounters current = readCounters(now);
        SystemMetricsSample sample = new SystemMetricsSample();

        sample.setSystemCpuLoad(readSystemCpuLoad());
        sample.setSystemMemory(buildSystemMemory());

        if (previous != null) {
            double seconds = Math.max(0.001D, (now - previous.timestampMs) / 1000.0D);
            applyNetworkRates(sample, current.network, previous.network, seconds, networkInterfaceName);
            applyDiskRates(sample, current.disk, previous.disk, seconds);
            SystemMetricsSample.ProcessIoRate processIoRate = buildProcessIoRate(current.processDisk, previous.processDisk, seconds);
            sample.setProcessIoRate(processIoRate);
            if (sample.getDiskIo() != null && processIoRate != null) {
                sample.getDiskIo().setProcessReadBytesPerSecond(processIoRate.getReadBytesPerSecond());
                sample.getDiskIo().setProcessWriteBytesPerSecond(processIoRate.getWriteBytesPerSecond());
            }
        } else {
            sample.setDiskIo(DiskIoInfoDTO.builder()
                    .available(false)
                    .note(DISK_IO_FIRST_SAMPLE_NOTE)
                    .build());
        }

        previous = current;
        sample.setWarnings(List.of());
        sample.setPartial(false);
        return sample;
    }

    public Double getProcessCpuLoad() {
        try {
            OSProcess process = operatingSystem.getProcess(operatingSystem.getProcessId());
            if (process == null) {
                return null;
            }
            return normalizeLoad(process.getProcessCpuLoadCumulative());
        } catch (Exception ignored) {
            return null;
        }
    }

    public String getProcessorModel() {
        try {
            CentralProcessor.ProcessorIdentifier identifier = hardware.getProcessor().getProcessorIdentifier();
            String name = identifier == null ? null : identifier.getName();
            return name == null || name.isBlank() ? null : name.trim();
        } catch (Exception ignored) {
            return null;
        }
    }

    private Double readSystemCpuLoad() {
        try {
            return normalizeLoad(hardware.getProcessor().getSystemCpuLoad(0L));
        } catch (Exception ignored) {
            return null;
        }
    }

    private MemoryInfoDTO buildSystemMemory() {
        try {
            GlobalMemory memory = hardware.getMemory();
            long total = memory.getTotal();
            long available = memory.getAvailable();
            if (total <= 0 || available < 0) {
                return null;
            }
            long used = Math.max(0L, total - available);
            return MemoryInfoDTO.builder()
                    .used(used)
                    .max(total)
                    .usage((double) used / total)
                    .build();
        } catch (Exception ignored) {
            return null;
        }
    }

    private OshiCounters readCounters(long now) {
        OshiCounters counters = new OshiCounters(now);
        try {
            for (NetworkIF network : hardware.getNetworkIFs()) {
                network.updateAttributes();
                String name = network.getName();
                if (name == null || name.isBlank()) {
                    continue;
                }
                counters.network.put(name, new NetworkCounters(network.getBytesRecv(), network.getBytesSent()));
            }
        } catch (Exception ignored) {
            // 网卡计数器读取失败时保持为空，快照仍可返回但速率为空。
        }
        try {
            for (HWDiskStore disk : hardware.getDiskStores()) {
                disk.updateAttributes();
                counters.disk.readBytes += disk.getReadBytes();
                counters.disk.writeBytes += disk.getWriteBytes();
                counters.disk.readOps += disk.getReads();
                counters.disk.writeOps += disk.getWrites();
            }
        } catch (Exception ignored) {
            // 磁盘计数器读取失败时保留零值，是否可用由后续差值计算决定。
        }
        try {
            OSProcess process = operatingSystem.getProcess(operatingSystem.getProcessId());
            if (process != null) {
                counters.processDisk = new ProcessDiskCounters(process.getBytesRead(), process.getBytesWritten());
            }
        } catch (Exception ignored) {
            // 平台不提供进程磁盘计数器时保持为空。
        }
        return counters;
    }

    private void applyNetworkRates(SystemMetricsSample sample, Map<String, NetworkCounters> current,
                                   Map<String, NetworkCounters> previous, double seconds, String networkInterfaceName) {
        if (current == null || previous == null || current.isEmpty()) {
            return;
        }
        Map<String, SystemMetricsSample.NetworkRate> rates = new HashMap<>();
        current.forEach((name, currentCounters) -> {
            NetworkCounters previousCounters = previous.get(name);
            if (previousCounters != null) {
                rates.put(name, new SystemMetricsSample.NetworkRate(
                        rate(currentCounters.rxBytes, previousCounters.rxBytes, seconds),
                        rate(currentCounters.txBytes, previousCounters.txBytes, seconds)
                ));
            }
        });
        sample.setNetworkRates(rates);

        String selectedName = firstNonBlank(networkInterfaceName, rates.keySet().stream().findFirst().orElse(null));
        SystemMetricsSample.NetworkRate selectedRate = selectedName == null ? null : rates.get(selectedName);
        if (selectedRate == null && !rates.isEmpty()) {
            selectedRate = rates.values().iterator().next();
        }
        if (selectedRate != null) {
            sample.setNetworkRxBytesPerSecond(selectedRate.getRxBytesPerSecond());
            sample.setNetworkTxBytesPerSecond(selectedRate.getTxBytesPerSecond());
        }
    }

    private void applyDiskRates(SystemMetricsSample sample, DiskCounters current, DiskCounters previous, double seconds) {
        if (current == null || previous == null) {
            sample.setDiskIo(DiskIoInfoDTO.builder()
                    .available(false)
                    .note(DISK_IO_UNAVAILABLE_NOTE)
                    .build());
            return;
        }
        Double readBytesPerSecond = rate(current.readBytes, previous.readBytes, seconds);
        Double writeBytesPerSecond = rate(current.writeBytes, previous.writeBytes, seconds);
        Double readOpsPerSecond = rate(current.readOps, previous.readOps, seconds);
        Double writeOpsPerSecond = rate(current.writeOps, previous.writeOps, seconds);
        boolean available = readBytesPerSecond != null || writeBytesPerSecond != null || readOpsPerSecond != null || writeOpsPerSecond != null;
        sample.setDiskIo(DiskIoInfoDTO.builder()
                .available(available)
                .note(available ? null : DISK_IO_UNAVAILABLE_NOTE)
                .readBytesPerSecond(readBytesPerSecond)
                .writeBytesPerSecond(writeBytesPerSecond)
                .readOpsPerSecond(readOpsPerSecond)
                .writeOpsPerSecond(writeOpsPerSecond)
                .build());
    }

    private SystemMetricsSample.ProcessIoRate buildProcessIoRate(ProcessDiskCounters current, ProcessDiskCounters previous, double seconds) {
        if (current == null || previous == null) {
            return null;
        }
        return new SystemMetricsSample.ProcessIoRate(
                rate(current.readBytes, previous.readBytes, seconds),
                rate(current.writeBytes, previous.writeBytes, seconds)
        );
    }

    private Double rate(long current, long previous, double seconds) {
        long delta = current - previous;
        if (delta < 0) {
            return null;
        }
        return delta / seconds;
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
        return value >= 0 && value <= 1D && Double.isFinite(value) ? value : null;
    }

    private static class OshiCounters {
        private final long timestampMs;
        private final Map<String, NetworkCounters> network = new HashMap<>();
        private final DiskCounters disk = new DiskCounters();
        private ProcessDiskCounters processDisk;

        private OshiCounters(long timestampMs) {
            this.timestampMs = timestampMs;
        }
    }

    private record NetworkCounters(long rxBytes, long txBytes) {}
    private record ProcessDiskCounters(long readBytes, long writeBytes) {}

    private static class DiskCounters {
        private long readBytes;
        private long writeBytes;
        private long readOps;
        private long writeOps;
    }
}
