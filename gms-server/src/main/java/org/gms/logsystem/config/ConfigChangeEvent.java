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

package org.gms.logsystem.config;

import lombok.Data;

/**
 * 配置变更事件类
 * 用于通知配置监听器配置已发生变更
 */
@Data
public class ConfigChangeEvent {
    private String configType;        // 配置类型: system, performance, category, packet
    private String configKey;         // 配置键
    private Object oldValue;          // 旧值
    private Object newValue;          // 新值
    private long changeTime;          // 变更时间
    private String changeSource;      // 变更来源: REST API, 配置文件等

    public ConfigChangeEvent(String configType, String configKey, Object oldValue, Object newValue, String changeSource) {
        this.configType = configType;
        this.configKey = configKey;
        this.oldValue = oldValue;
        this.newValue = newValue;
        this.changeTime = System.currentTimeMillis();
        this.changeSource = changeSource;
    }
}
