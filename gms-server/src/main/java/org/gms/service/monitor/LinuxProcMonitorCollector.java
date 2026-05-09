package org.gms.service.monitor;

import org.gms.model.dto.monitor.DiskIoInfoDTO;
import org.gms.model.dto.monitor.MemoryInfoDTO;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Lightweight Linux /proc collector. It never throws to callers: unsupported platforms,
 * missing procfs files and parse/read failures are reported as warnings on the sample.
 */
public class LinuxProcMonitorCollector implements SystemMetricsCollector {
    private static final Path PROC_STAT = Path.of("/proc/stat");
    private static final Path PROC_MEMINFO = Path.of("/proc/meminfo");
    private static final Path PROC_NET_DEV = Path.of("/proc/net/dev");
    private static final Path PROC_DISKSTATS = Path.of("/proc/diskstats");
    private static final long DISK_SECTOR_SIZE = 512L;

    private ProcCounters previous;

    @Override
    public synchronized SystemMetricsSample collect() {
        List<String> warnings = new ArrayList<>();
        SystemMetricsSample sample = new SystemMetricsSample();

        if (!isLinux()) {
            warnings.add("Linux /proc metrics are unavailable on this operating system.");
            sample.setPartial(true);
            sample.setWarnings(warnings);
            return sample;
        }

        long now = System.currentTimeMillis();
        ProcCounters current = new ProcCounters(now);
        current.cpu = readCpu(warnings);
        current.meminfo = readMeminfo(warnings);
        current.net = readNetDev(warnings);
        current.disk = readDiskstats(warnings);

        if (current.meminfo != null) {
            long total = current.meminfo.getOrDefault("MemTotal", 0L);
            long available = current.meminfo.getOrDefault("MemAvailable", current.meminfo.getOrDefault("MemFree", 0L));
            long used = Math.max(0L, total - available);
            sample.setSystemMemory(MemoryInfoDTO.builder()
                    .used(used)
                    .max(total)
                    .usage(total > 0 ? (double) used / total : null)
                    .build());
        }

        if (previous != null) {
            double seconds = Math.max(0.001D, (now - previous.timestampMs) / 1000.0D);
            if (current.cpu != null && previous.cpu != null) {
                long totalDelta = current.cpu.total - previous.cpu.total;
                long idleDelta = current.cpu.idle - previous.cpu.idle;
                if (totalDelta > 0) {
                    sample.setSystemCpuLoad(clamp01((double) (totalDelta - idleDelta) / totalDelta));
                }
            }
            applyNetworkRates(sample, current.net, previous.net, seconds);
            applyDiskRates(sample, current.disk, previous.disk, seconds);
        } else {
            warnings.add("Linux /proc rate metrics require two samples; rates will be available on the next request.");
        }

        previous = current;
        sample.setPartial(!warnings.isEmpty());
        sample.setWarnings(warnings);
        return sample;
    }

    private boolean isLinux() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("linux");
    }

    private CpuCounters readCpu(List<String> warnings) {
        try {
            if (!Files.isReadable(PROC_STAT)) {
                warnings.add(PROC_STAT + " is not readable; CPU /proc usage is unavailable.");
                return null;
            }
            for (String line : Files.readAllLines(PROC_STAT)) {
                if (line.startsWith("cpu ")) {
                    String[] parts = line.trim().split("\\s+");
                    long idle = parseLong(parts, 4) + parseLong(parts, 5);
                    long total = 0L;
                    for (int i = 1; i < parts.length; i++) {
                        total += parseLong(parts, i);
                    }
                    return new CpuCounters(total, idle);
                }
            }
            warnings.add(PROC_STAT + " does not contain an aggregate cpu line.");
        } catch (Exception e) {
            warnings.add("Failed to read " + PROC_STAT + ": " + e.getClass().getSimpleName());
        }
        return null;
    }

    private Map<String, Long> readMeminfo(List<String> warnings) {
        try {
            if (!Files.isReadable(PROC_MEMINFO)) {
                warnings.add(PROC_MEMINFO + " is not readable; system memory is unavailable.");
                return null;
            }
            Map<String, Long> values = new HashMap<>();
            for (String line : Files.readAllLines(PROC_MEMINFO)) {
                String[] parts = line.split(":", 2);
                if (parts.length != 2) {
                    continue;
                }
                String[] valueParts = parts[1].trim().split("\\s+");
                if (valueParts.length > 0) {
                    values.put(parts[0], Long.parseLong(valueParts[0]) * 1024L);
                }
            }
            return values;
        } catch (Exception e) {
            warnings.add("Failed to read " + PROC_MEMINFO + ": " + e.getClass().getSimpleName());
            return null;
        }
    }

    private NetCounters readNetDev(List<String> warnings) {
        try {
            if (!Files.isReadable(PROC_NET_DEV)) {
                warnings.add(PROC_NET_DEV + " is not readable; network rates are unavailable.");
                return null;
            }
            NetCounters counters = new NetCounters();
            for (String line : Files.readAllLines(PROC_NET_DEV)) {
                if (!line.contains(":")) {
                    continue;
                }
                String[] nameAndData = line.trim().split(":", 2);
                String name = nameAndData[0].trim();
                if ("lo".equals(name)) {
                    continue;
                }
                String[] fields = nameAndData[1].trim().split("\\s+");
                if (fields.length >= 16) {
                    counters.rxBytes += Long.parseLong(fields[0]);
                    counters.txBytes += Long.parseLong(fields[8]);
                }
            }
            return counters;
        } catch (Exception e) {
            warnings.add("Failed to read " + PROC_NET_DEV + ": " + e.getClass().getSimpleName());
            return null;
        }
    }

    private DiskCounters readDiskstats(List<String> warnings) {
        try {
            if (!Files.isReadable(PROC_DISKSTATS)) {
                warnings.add(PROC_DISKSTATS + " is not readable; disk IO rates are unavailable.");
                return null;
            }
            DiskCounters counters = new DiskCounters();
            for (String line : Files.readAllLines(PROC_DISKSTATS)) {
                String[] fields = line.trim().split("\\s+");
                if (fields.length < 10 || isVirtualDisk(fields[2])) {
                    continue;
                }
                counters.readOps += Long.parseLong(fields[3]);
                counters.readBytes += Long.parseLong(fields[5]) * DISK_SECTOR_SIZE;
                counters.writeOps += Long.parseLong(fields[7]);
                counters.writeBytes += Long.parseLong(fields[9]) * DISK_SECTOR_SIZE;
            }
            return counters;
        } catch (Exception e) {
            warnings.add("Failed to read " + PROC_DISKSTATS + ": " + e.getClass().getSimpleName());
            return null;
        }
    }

    private boolean isVirtualDisk(String name) {
        return name.startsWith("loop") || name.startsWith("ram") || name.startsWith("fd");
    }

    private void applyNetworkRates(SystemMetricsSample sample, NetCounters current, NetCounters previous, double seconds) {
        if (current == null || previous == null) {
            return;
        }
        sample.setNetworkRxBytesPerSecond(rate(current.rxBytes, previous.rxBytes, seconds));
        sample.setNetworkTxBytesPerSecond(rate(current.txBytes, previous.txBytes, seconds));
    }

    private void applyDiskRates(SystemMetricsSample sample, DiskCounters current, DiskCounters previous, double seconds) {
        if (current == null || previous == null) {
            sample.setDiskIo(DiskIoInfoDTO.builder()
                    .available(false)
                    .note("Disk IO rate counters require two samples; rates will be available on the next request.")
                    .build());
            return;
        }
        sample.setDiskIo(DiskIoInfoDTO.builder()
                .available(true)
                .readBytesPerSecond(rate(current.readBytes, previous.readBytes, seconds))
                .writeBytesPerSecond(rate(current.writeBytes, previous.writeBytes, seconds))
                .readOpsPerSecond(rate(current.readOps, previous.readOps, seconds))
                .writeOpsPerSecond(rate(current.writeOps, previous.writeOps, seconds))
                .build());
    }

    private Double rate(long current, long previous, double seconds) {
        long delta = current - previous;
        if (delta < 0) {
            return null;
        }
        return delta / seconds;
    }

    private long parseLong(String[] parts, int index) {
        if (index >= parts.length) {
            return 0L;
        }
        try {
            return Long.parseLong(parts[index]);
        } catch (NumberFormatException ignored) {
            return 0L;
        }
    }

    private double clamp01(double value) {
        return Math.max(0D, Math.min(1D, value));
    }

    private static class ProcCounters {
        private final long timestampMs;
        private CpuCounters cpu;
        private Map<String, Long> meminfo;
        private NetCounters net;
        private DiskCounters disk;

        private ProcCounters(long timestampMs) {
            this.timestampMs = timestampMs;
        }
    }

    private record CpuCounters(long total, long idle) {}

    private static class NetCounters {
        private long rxBytes;
        private long txBytes;
    }

    private static class DiskCounters {
        private long readBytes;
        private long writeBytes;
        private long readOps;
        private long writeOps;
    }
}
