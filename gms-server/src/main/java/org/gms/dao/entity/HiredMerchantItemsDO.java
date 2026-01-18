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
@Table("hired_merchant_items")
public class HiredMerchantItemsDO implements Serializable {
    @Id(keyType = KeyType.Auto)
    private Integer id;
    private Integer merchantId;
    private Long inventoryItemId;
    private Integer itemId;
    private Integer quantity;
    private Integer soldQuantity;
    private Integer price;
    private Integer bundles;
    private String status;
    private String itemData;
    private Long settledTime;
}
