package org.gms.model.dto;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class ItemInfoRtnDTO {
    private Integer itemId;
    private Integer quantity;
    private String owner;
    private Long expiration;
    private String name;
    private String desc;
}
