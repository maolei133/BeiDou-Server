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

package org.gms.logsystem.formatter;

import com.alibaba.fastjson2.JSONObject;
import org.gms.constants.net.ServerConstants;
import org.gms.logsystem.context.GameLogContext;
import org.gms.logsystem.core.GameLogEntry;
import org.gms.logsystem.util.LogFieldUtils;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * 游戏日志格式化器 - 将日志条目格式化为标准JSON格式
 * 支持上下文信息的自动注入
 *
 * @author logs-system
 */
public class GameLogFormatter {
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    /**
     * 将日志条目格式化为JSON字符串
     * 
     * @param entry 日志条目
     * @param context 日志上下文
     * @return 格式化后的JSON字符串
     */
    public static String formatToJson(GameLogEntry entry, GameLogContext context) {
        JSONObject json = new JSONObject();

        // 时间戳
        json.put("t", LocalDateTime.now().format(DATE_FORMATTER));

        // 版本（从配置读取）
        json.put("v", ServerConstants.BEI_DOU_VERSION);

        // 日志级别
        json.put("lvl", entry.getLevel() != null ? entry.getLevel() : "INFO");

        // 硬件信息 - 使用反射自动从context提取标注的字段
        if (context != null) {
            LogFieldUtils.populateJsonFromAnnotation(json, context);
        } else if (entry != null) {
            // 如果没有context，尽量从entry中获取
            if (entry.getHardwareId() != null) json.put("hwid", entry.getHardwareId());
            if (entry.getIpAddress() != null) json.put("ip", entry.getIpAddress());
            if (entry.getMacAddress() != null) json.put("mac", entry.getMacAddress().split(","));
            if (entry.getAccountName() != null) json.put("acc", entry.getAccountName());
            if (entry.getAccountId() > 0) json.put("accId", entry.getAccountId());
            if (entry.getCharacterName() != null) json.put("chr", entry.getCharacterName());
            if (entry.getCharacterId() > 0) json.put("chrId", entry.getCharacterId());
            if (entry.getMapName() != null) json.put("map", entry.getMapName());
            if (entry.getMapId() > 0) json.put("mid", entry.getMapId());
        }

        // 自定义数据
        JSONObject customField = new JSONObject();
        customField.put("major", entry.getMajorCategory());
        customField.put("minor", entry.getMinorCategory());
        customField.put("msg", entry.getMessage());
        if (entry.getExtraData() != null) {
            // 尝试解析extraData为JSON，如果失败则作为字符串
            try {
                customField.put("details", com.alibaba.fastjson2.JSON.parseObject(entry.getExtraData()));
            } catch (Exception e) {
                customField.put("details", entry.getExtraData());
            }
        }
        json.put("cf", customField);

        return json.toJSONString();
    }

    /**
     * 简化版格式化 - 仅包含基本信息
     */
    public static String formatSimple(GameLogEntry entry) {
        return formatToJson(entry, null);
    }

    /**
     * 从JSON字符串解析日志条目
     */
    public static GameLogEntry parseFromJson(String jsonString) {
        JSONObject json = com.alibaba.fastjson2.JSON.parseObject(jsonString);

        GameLogEntry entry = GameLogEntry.builder()
                .logId(json.getString("logId"))
                .timestamp(json.getLongValue("timestamp"))
                .ipAddress(json.getString("ip"))
                .macAddress(json.getJSONArray("mac") != null ? 
                        String.join(",", json.getJSONArray("mac").toList(String.class)) : null)
                .hardwareId(json.getString("hwid"))
                .accountId(json.getIntValue("accId"))
                .accountName(json.getString("acc"))
                .characterId(json.getIntValue("chrId"))
                .characterName(json.getString("chr"))
                .mapId(json.getIntValue("mid"))
                .mapName(json.getString("map"))
                .level(json.getString("lvl"))
                .build();

        JSONObject cf = json.getJSONObject("cf");
        if (cf != null) {
            entry.setMajorCategory(cf.getString("major"));
            entry.setMinorCategory(cf.getString("minor"));
            entry.setMessage(cf.getString("msg"));
            if (cf.getJSONObject("details") != null) {
                entry.setExtraData(cf.getJSONObject("details").toJSONString());
            }
            // 兼容旧字段名
            if (entry.getMajorCategory() == null) {
                entry.setMajorCategory(cf.getString("majorCategory"));
            }
            if (entry.getMinorCategory() == null) {
                entry.setMinorCategory(cf.getString("minorCategory"));
            }
            if (entry.getMessage() == null) {
                entry.setMessage(cf.getString("message"));
            }
        }

        return entry;
    }
}
