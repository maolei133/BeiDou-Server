package org.gms.service.monitor;

import org.gms.model.dto.monitor.ContainerInfoDTO;
import org.gms.model.dto.monitor.MemoryInfoDTO;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Detects Docker/cgroup context and reads cgroup memory usage/limits without shelling out.
 */
public class ContainerRuntimeDetector {
    private static final Path DOCKER_ENV = Path.of("/.dockerenv");
    private static final Path PROC_1_CGROUP = Path.of("/proc/1/cgroup");
    private static final long UNLIMITED_THRESHOLD = Long.MAX_VALUE / 2;

    public ContainerInfoDTO detect(List<String> warnings) {
        ContainerInfoDTO.ContainerInfoDTOBuilder builder = ContainerInfoDTO.builder()
                .runtime("none")
                .detected(false);

        if (!isLinux()) {
            warnings.add("Container cgroup metrics are unavailable on this operating system.");
            return builder.build();
        }

        boolean dockerenv = Files.exists(DOCKER_ENV);
        boolean cgroupMarker = false;
        List<String> cgroupLines = readProc1Cgroup(warnings);
        String memoryCgroupPath = "/";
        for (String line : cgroupLines) {
            String lower = line.toLowerCase(Locale.ROOT);
            if (lower.contains("docker") || lower.contains("kubepods") || lower.contains("containerd")) {
                cgroupMarker = true;
            }
            String[] parts = line.split(":", 3);
            if (parts.length == 3 && (parts[1].isEmpty() || parts[1].contains("memory"))) {
                memoryCgroupPath = parts[2].isBlank() ? "/" : parts[2];
            }
        }

        String runtime = dockerenv || cgroupMarker ? "docker/cgroup" : "cgroup";
        MemoryInfoDTO memory = readMemory(memoryCgroupPath, warnings);
        boolean detected = dockerenv || cgroupMarker || memory != null;

        return builder
                .detected(detected)
                .runtime(detected ? runtime : "none")
                .dockerEnv(dockerenv)
                .cgroupPath(memoryCgroupPath)
                .memory(memory)
                .build();
    }

    private boolean isLinux() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("linux");
    }

    private List<String> readProc1Cgroup(List<String> warnings) {
        try {
            if (!Files.isReadable(PROC_1_CGROUP)) {
                warnings.add(PROC_1_CGROUP + " is not readable; container runtime detection is limited.");
                return List.of();
            }
            return Files.readAllLines(PROC_1_CGROUP);
        } catch (Exception e) {
            warnings.add("Failed to read " + PROC_1_CGROUP + ": " + e.getClass().getSimpleName());
            return List.of();
        }
    }

    private MemoryInfoDTO readMemory(String cgroupPath, List<String> warnings) {
        List<Path> candidates = new ArrayList<>();
        String relative = normalizeCgroupPath(cgroupPath);
        candidates.add(Path.of("/sys/fs/cgroup").resolve(relative));
        candidates.add(Path.of("/sys/fs/cgroup/memory").resolve(relative));
        candidates.add(Path.of("/sys/fs/cgroup/memory"));
        candidates.add(Path.of("/sys/fs/cgroup"));

        for (Path base : candidates) {
            Long current = readLongFile(base.resolve("memory.current"), false, warnings);
            Long max = readCgroupMax(base.resolve("memory.max"), false, warnings);
            if (current == null) {
                current = readLongFile(base.resolve("memory.usage_in_bytes"), false, warnings);
            }
            if (max == null) {
                max = readCgroupMax(base.resolve("memory.limit_in_bytes"), false, warnings);
            }
            if (current != null || max != null) {
                Long normalizedMax = normalizeMax(max);
                return MemoryInfoDTO.builder()
                        .used(current)
                        .max(normalizedMax)
                        .usage(current != null && normalizedMax != null && normalizedMax > 0 ? (double) current / normalizedMax : null)
                        .build();
            }
        }

        warnings.add("No readable cgroup memory.current/memory.max or cgroup v1 memory files were found.");
        return null;
    }

    private String normalizeCgroupPath(String cgroupPath) {
        if (cgroupPath == null || cgroupPath.isBlank() || "/".equals(cgroupPath)) {
            return "";
        }
        String normalized = cgroupPath.startsWith("/") ? cgroupPath.substring(1) : cgroupPath;
        return normalized.replace("..", "");
    }

    private Long readCgroupMax(Path path, boolean warnMissing, List<String> warnings) {
        try {
            if (!Files.isReadable(path)) {
                if (warnMissing) {
                    warnings.add(path + " is not readable.");
                }
                return null;
            }
            String value = Files.readString(path).trim();
            if (value.equalsIgnoreCase("max")) {
                return null;
            }
            return Long.parseLong(value);
        } catch (Exception e) {
            warnings.add("Failed to read " + path + ": " + e.getClass().getSimpleName());
            return null;
        }
    }

    private Long readLongFile(Path path, boolean warnMissing, List<String> warnings) {
        try {
            if (!Files.isReadable(path)) {
                if (warnMissing) {
                    warnings.add(path + " is not readable.");
                }
                return null;
            }
            return Long.parseLong(Files.readString(path).trim());
        } catch (Exception e) {
            warnings.add("Failed to read " + path + ": " + e.getClass().getSimpleName());
            return null;
        }
    }

    private Long normalizeMax(Long max) {
        if (max == null || max <= 0 || max >= UNLIMITED_THRESHOLD) {
            return null;
        }
        return max;
    }
}
