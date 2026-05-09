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
public class NetworkInfoDTO {
    private Double hostRxBytesPerSecond;
    private Double hostTxBytesPerSecond;
    private String hostName;
    private String selectedInterfaceName;
    private String defaultInterfaceName;
    private List<NetworkInterfaceInfoDTO> interfaces;
    private Double rxBytesPerSecond;
    private Double txBytesPerSecond;
}
