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

package org.gms.logsystem.context;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.gms.logsystem.annotation.LogField;

/**
 * 游戏日志上下文 - 存储日志相关的上下文信息
 * 通过ThreadLocal机制在整个请求生命周期中传递
 *
 * @author logs-system
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class GameLogContext {
    /** 上下文ID */
    private String contextId;

    /** 硬件ID */
    @LogField(name = "hwid")
    private String hardwareId;

    /** IP地址 */
    @LogField(name = "ip")
    private String ipAddress;

    /** MAC地址（可能有多个） */
    @LogField(name = "mac")
    private String macAddress;

    /** 账号名 */
    @LogField(name = "acc")
    private String accountName;

    /** 账号ID */
    @LogField(name = "accId")
    private int accountId;

    /** 角色名 */
    @LogField(name = "chr")
    private String characterName;

    /** 角色ID */
    @LogField(name = "chrId")
    private int characterId;

    /** 角色等级 */
    @LogField(name = "chrLv")
    private int characterLevel;

    /** 职业名称 */
    @LogField(name = "job")
    private String jobName;

    /** 职业ID */
    @LogField(name = "jobId")
    private int jobId;

    /** 频道ID */
    @LogField(name = "ch")
    private int channelId;

    /** 地图名 */
    @LogField(name = "map")
    private String mapName;

    /** 地图ID */
    @LogField(name = "mid")
    private int mapId;

    /** X坐标 */
    private int posX;

    /** Y坐标 */
    private int posY;

    /** 其他自定义数据 */
    private String customData;

    /** 上下文创建时间 */
    private long createdTime;

    /** 上下文最后访问时间 */
    private long lastAccessTime;

    /** 检查上下文是否过期（5分钟） */
    public boolean isExpired() {
        return System.currentTimeMillis() - lastAccessTime > 5 * 60 * 1000;
    }

    /** 更新最后访问时间 */
    public void updateAccessTime() {
        this.lastAccessTime = System.currentTimeMillis();
    }
}
