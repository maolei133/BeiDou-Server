package org.gms.model.dto;

import lombok.Data;

import java.util.List;

@Data
public class BanPlayerReqDTO {
    private List<Integer> ids;
    private boolean all;
    private String reason;
    private Integer duration; // minutes, null or 0 for permanent
    private Long banUntil; // timestamp, if set, overrides duration
    private boolean banIp;
    private boolean banMac;
    private boolean banHwid;
    private boolean notify;
    private String notifyContent;
    
    // Front-end optional selection for IPs and MACs
    private List<String> ips;
    private List<String> macs;
}
