package org.gms.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @zh-CN 行为类型数据传输对象，用于前端展示
 * @en-US Action Type Data Transfer Object, for frontend display
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ActionTypeDTO {
    private String value;
    private String label; // 本地化后的名称
}
