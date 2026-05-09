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
    private String hostName;
    private List<NetworkInterfaceInfoDTO> interfaces;
    private Double rxBytesPerSecond;
    private Double txBytesPerSecond;
}
