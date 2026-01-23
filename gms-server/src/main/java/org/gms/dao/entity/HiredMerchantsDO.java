package org.gms.dao.entity;

import com.mybatisflex.annotation.Id;
import com.mybatisflex.annotation.KeyType;
import com.mybatisflex.annotation.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * 雇佣商店实体类
 * 对应数据库表: hired_merchants
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("hired_merchants")
public class HiredMerchantsDO implements Serializable {
    /** 状态：准备中（预开业） */
    public static final String STATUS_PREPARING = "PREPARING";
    /** 状态：营业中 */
    public static final String STATUS_ACTIVE = "ACTIVE";
    /** 状态：已关闭 */
    public static final String STATUS_CLOSED = "CLOSED";
    /** 状态：已过期 */
    public static final String STATUS_EXPIRED = "EXPIRED";
    /** 状态：维护中 */
    public static final String STATUS_MAINTAINED = "MAINTAINED";

    /** 商店唯一标识 ID */
    @Id(keyType = KeyType.Auto)
    private Integer id;
    /** 店主角色 ID */
    private Integer ownerId;
    /** 所在频道 */
    private Integer channel;
    /** 所在世界 ID */
    private Integer worldId;
    /** 所在地图 ID */
    private Integer mapId;
    /** 商店 X 坐标 */
    private Integer x;
    /** 商店 Y 坐标 */
    private Integer y;
    /** 商店描述/店名 */
    private String description;
    /** 雇佣商人道具 ID (外观) */
    private Integer itemId;
    /** 商店状态 (PREPARING, ACTIVE, CLOSED, EXPIRED, MAINTAINED) */
    private String status;
    /** 开店时间戳 */
    private Long startTime;
    /** 关闭时间戳 */
    private Long closeTime;
    /** 当前未取回的金币余额 (可提现金额) */
    private Long mesos;
}
