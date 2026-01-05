package org.gms.dao.entity;

import com.mybatisflex.annotation.Id;
import com.mybatisflex.annotation.KeyType;
import com.mybatisflex.annotation.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(value = "bit_votingrecords")
public class VotingrecordsDO {
    @Id(keyType = KeyType.Auto)
    private Integer id;
    private String account;
    private Integer date;
}
