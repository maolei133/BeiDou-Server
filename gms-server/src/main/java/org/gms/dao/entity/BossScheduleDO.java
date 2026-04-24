package org.gms.dao.entity;

import com.mybatisflex.annotation.Column;
import com.mybatisflex.annotation.Id;
import com.mybatisflex.annotation.KeyType;
import com.mybatisflex.annotation.Table;
import java.io.Serializable;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.io.Serial;

/**
 * 野外BOSS刷新调度表
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("boss_schedule")
public class BossScheduleDO implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Id(keyType = KeyType.Auto)
    private Integer id;

    private Integer world;

    private Integer channel;

    private Integer map;

    private Integer mob;
    @Column("nextSpawnTime")
    private Long nextSpawnTime;

}