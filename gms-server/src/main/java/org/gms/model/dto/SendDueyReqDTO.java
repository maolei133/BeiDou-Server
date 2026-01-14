package org.gms.model.dto;

import lombok.Data;

@Data
public class SendDueyReqDTO {
    private String receiverName;
    private Integer receiverId;
    private Boolean isAll;
    private Integer mesos;
    private String message;
    private Integer itemId;
    private Integer quantity;
    private Boolean quick;
    private String senderName;
    private Long expireTime;
    private Integer expireDays;
}
