package org.gms.model.dto;

import lombok.Data;

import java.util.List;

@Data
public class ChrIdDTO {
    private Integer id;
    private boolean unbanIp;
    private boolean unbanMac;
    private boolean unbanHwid;
    private List<String> ips;
    private List<String> macs;
}
