/* This file is part of the BeiDou Maple Story Server
Copyright (C) 2025 BeiDou Server https://github.com/BeiDouMS/BeiDou-Server
Magical-H https://github.com/Magical-H

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation version 3 as published by
the Free Software Foundation. You may not use, modify or distribute
this program under any otheer version of the GNU Affero General Public
License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; witout even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.


You should have received a copy of the GNU Affero General Public License
along with this program. If not, see http://www.gnu.org/licenses/.
*/

package org.gms.logsystem.util;

import com.alibaba.fastjson2.JSONObject;
import org.gms.logsystem.annotation.LogField;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 日志字段工具类 - 使用反射自动处理@LogField注解的字段
 * 支持自动从源对象读取并写入目标JSON
 *
 * @author logs-system
 */
public class LogFieldUtils {
    private static final Logger log = LoggerFactory.getLogger(LogFieldUtils.class);

    /**
     * 根据@LogField注解自动将源对象的字段写入JSON对象
     * 
     * @param json 目标JSON对象
     * @param source 源对象
     */
    public static void populateJsonFromAnnotation(JSONObject json, Object source) {
        if (json == null || source == null) {
            return;
        }

        try {
            // 获取源对象的所有字段（包括父类）
            List<Field> fields = getAllFields(source.getClass());

            for (Field field : fields) {
                // 检查字段是否有@LogField注解
                LogField logField = field.getAnnotation(LogField.class);
                if (logField == null) {
                    continue;
                }

                // 设置字段可访问
                field.setAccessible(true);

                try {
                    Object value = field.get(source);

                    // 如果字段为null且标记为必须，则跳过
                    if (value == null && logField.required()) {
                        log.debug("[LOG_FIELD] 字段 {} 为null且标记为required，跳过", field.getName());
                        continue;
                    }

                    // 确定JSON键名
                    String jsonKey = logField.name().isEmpty() ? field.getName() : logField.name();

                    // 根据值类型写入JSON
                    if (value != null) {
                        // MAC地址特殊处理：如果是逗号分隔的字符串，转换为数组
                        if ("mac".equals(jsonKey) && value instanceof String) {
                            String macStr = (String) value;
                            if (!macStr.isEmpty()) {
                                json.put(jsonKey, Arrays.asList(macStr.split(",")));
                            }
                        } else {
                            json.put(jsonKey, value);
                        }
                    }
                } catch (IllegalAccessException e) {
                    log.error("[LOG_FIELD] 无法访问字段 {}: {}", field.getName(), e.getMessage());
                }
            }
        } catch (Exception e) {
            log.error("[LOG_FIELD] 处理@LogField注解时出错", e);
        }
    }

    /**
     * 获取类的所有字段，包括父类的字段
     */
    private static List<Field> getAllFields(Class<?> clazz) {
        return Arrays.stream(clazz.getDeclaredFields())
                .collect(Collectors.toList());
    }
}
