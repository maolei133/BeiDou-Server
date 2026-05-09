package org.gms.service.monitor;

import org.gms.model.dto.monitor.DiskIoInfoDTO;
import org.gms.model.dto.monitor.MemoryInfoDTO;

import java.util.List;

public class SystemMetricsSample {
    private boolean partial;
    private List<String> warnings = List.of();
    private Double systemCpuLoad;
    private MemoryInfoDTO systemMemory;
    private Double networkRxBytesPerSecond;
    private Double networkTxBytesPerSecond;
    private DiskIoInfoDTO diskIo;

    public boolean isPartial() { return partial; }
    public void setPartial(boolean partial) { this.partial = partial; }
    public List<String> getWarnings() { return warnings; }
    public void setWarnings(List<String> warnings) { this.warnings = warnings == null ? List.of() : warnings; }
    public Double getSystemCpuLoad() { return systemCpuLoad; }
    public void setSystemCpuLoad(Double systemCpuLoad) { this.systemCpuLoad = systemCpuLoad; }
    public MemoryInfoDTO getSystemMemory() { return systemMemory; }
    public void setSystemMemory(MemoryInfoDTO systemMemory) { this.systemMemory = systemMemory; }
    public Double getNetworkRxBytesPerSecond() { return networkRxBytesPerSecond; }
    public void setNetworkRxBytesPerSecond(Double networkRxBytesPerSecond) { this.networkRxBytesPerSecond = networkRxBytesPerSecond; }
    public Double getNetworkTxBytesPerSecond() { return networkTxBytesPerSecond; }
    public void setNetworkTxBytesPerSecond(Double networkTxBytesPerSecond) { this.networkTxBytesPerSecond = networkTxBytesPerSecond; }
    public DiskIoInfoDTO getDiskIo() { return diskIo; }
    public void setDiskIo(DiskIoInfoDTO diskIo) { this.diskIo = diskIo; }
}
