package org.gms.model.dto;

import lombok.Data;

import java.util.List;

@Data
public class BanPlayerReqDTO {
    private List<Integer> ids;
    private boolean all;
    private String reason;
    private Integer duration; // minutes, null or 0 for permanent
    private boolean banIp;
    private boolean banMac;
    private boolean banHwid;
    private boolean notify;
    private String notifyContent;
}
