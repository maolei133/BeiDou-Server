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
@Table("hired_merchant_transactions")
public class HiredMerchantTransactionsDO implements Serializable {
    public static final String TYPE_ADD = "ADD";
    public static final String TYPE_BUY = "BUY";
    public static final String TYPE_REMOVE = "REMOVE";
    public static final String TYPE_RETURN = "RETURN";

    @Id(keyType = KeyType.Auto)
    private Integer id;
    private Integer merchantId;
    private Integer itemId;
    private Integer buyerId;
    private String type;
    private Integer quantity;
    private Integer price;
    private Long totalPrice;
    private Long timestamp;
}
