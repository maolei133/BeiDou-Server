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
public class NetworkInterfaceInfoDTO {
    private String name;
    private String displayName;
    private Boolean up;
    private Boolean loopback;
    private Boolean virtual;
    private Boolean internetReachable;
    private Boolean defaultInterface;
    private Integer mtu;
    private String primaryAddress;
    private List<String> addresses;
}
