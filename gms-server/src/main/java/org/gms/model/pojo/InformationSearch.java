package org.gms.model.pojo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class InformationSearch {
    /**
     * 接口参数，web传参
     * types = InformationType
     * filter = id or name
     */
    private List<String> types;
    private String filter;
    /**
     * 非接口参数，给服务内部调用
     * filterType = 0-both 1-id 2-name
     * fullMatch = 是否精确匹配
     */
    private int filterType;
    private boolean fullMatch;

    /**
     * 分页参数
     */
    private Integer page;
    private Integer pageSize;

    /**
     * 筛选参数
     * gender: 0-男 1-女 2-通用
     * color: 0-7 (对应发型/脸型颜色)
     */
    private Integer gender;
    private Integer color;
    
    /**
     * 装备分类筛选 (仅当 types 包含 eqp 时有效)
     * 例如: Weapon, Cap, Coat, Pants, Shoes, Gloves, Cape, Shield, etc.
     */
    private String category;
}
