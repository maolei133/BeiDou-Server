package org.gms.model.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class BanInfoRtnDTO {
    private List<String> ips;
    private List<String> macs;
    private String hwid;
}
