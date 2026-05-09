package org.gms.model.dto.monitor;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ServerMonitorSnapshotDTO {
    private SampleInfoDTO sample;
    private ServerInfoDTO server;
    private RuntimeInfoDTO runtime;
    private CpuInfoDTO cpu;
    private JvmInfoDTO jvm;
    private List<DiskInfoDTO> disks;
    private DiskIoInfoDTO diskIo;
    private NetworkInfoDTO network;
    private ContainerInfoDTO container;
}
