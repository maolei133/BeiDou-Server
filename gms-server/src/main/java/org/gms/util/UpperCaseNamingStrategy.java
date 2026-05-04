package org.gms.util;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;

/**
 * 自定义Jackson属性命名策略，将所有字段名转换为全大写。
 * 例如：`fieldName` -> `FIELDNAME`
 */
public class UpperCaseNamingStrategy extends PropertyNamingStrategies.NamingBase {
    @Override
    public String translate(String propertyName) {
        if (propertyName == null || propertyName.isEmpty()) {
            return propertyName;
        }
        return propertyName.toUpperCase();
    }
}
