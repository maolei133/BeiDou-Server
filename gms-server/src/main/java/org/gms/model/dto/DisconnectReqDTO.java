package org.gms.model.dto;

import lombok.Data;

import java.util.List;

@Data
public class DisconnectReqDTO {
    private List<Integer> ids;
    private boolean all;
}
