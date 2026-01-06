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
@Table("hiredmerchitems")
public class HiredmerchitemsDO implements Serializable {
    @Id(keyType = KeyType.Auto)
    private Integer id;
    private Integer packageid;
    private Integer itemid;
    private Integer quantity;
    private Integer price;
}
