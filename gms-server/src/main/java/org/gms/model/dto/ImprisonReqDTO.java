package org.gms.model.dto;

import lombok.Data;

@Data
public class ImprisonReqDTO {
    private Integer playerId;
    private int minutes = 5;
}
