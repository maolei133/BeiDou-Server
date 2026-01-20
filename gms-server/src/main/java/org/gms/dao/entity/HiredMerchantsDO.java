package org.gms.dao.entity;

import com.mybatisflex.annotation.Id;
import com.mybatisflex.annotation.KeyType;
import com.mybatisflex.annotation.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("hired_merchants")
public class HiredMerchantsDO implements Serializable {
    public static final String STATUS_PREPARING = "PREPARING";
    public static final String STATUS_ACTIVE = "ACTIVE";
    public static final String STATUS_CLOSED = "CLOSED";
    public static final String STATUS_EXPIRED = "EXPIRED";
    public static final String STATUS_MAINTAINED = "MAINTAINED";

    @Id(keyType = KeyType.Auto)
    private Integer id;
    private Integer ownerId;
    private Integer channel;
    private Integer worldId;
    private Integer mapId;
    private Integer x;
    private Integer y;
    private String description;
    private Integer itemId;
    private String status;
    private Long startTime;
    private Long closeTime;
    private Long mesos;
}
