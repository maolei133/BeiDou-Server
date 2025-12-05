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
import java.util.HashSet;
import java.util.Set;

/**
 * 网络封包日志配置类
 * 管理入站、出站和监控角色的网络包日志配置
 *
 * @author logs-system
 */
@Data
public class PacketLogConfig {
    /**
     * 是否启用网络包日志
     */
    private boolean enabled = true;

    /**
     * 是否启用入站包日志
     */
    private boolean logIncoming = true;

    /**
     * 是否启用出站包日志
     */
    private boolean logOutgoing = true;

    /**
     * 是否启用监控角色日志
     */
    private boolean monitoredChrLogEnabled = true;

    /**
     * 入站包屏蔽列表（Opcode集合）
     */
    private Set<Integer> inPacketBlocklist = new HashSet<>();

    /**
     * 出站包屏蔽列表（Opcode集合）
     */
    private Set<Integer> outPacketBlocklist = new HashSet<>();

    /**
     * 监控角色列表
     */
    private Set<Integer> monitoredCharacterIds = new HashSet<>();

    /**
     * 入站包日志缓冲区大小
     */
    private int inPacketBufferSize = 2048;

    /**
     * 出站包日志缓冲区大小
     */
    private int outPacketBufferSize = 2048;

    /**
     * 包日志刷新间隔（毫秒）
     */
    private int packetLogFlushInterval = 500;

    /**
     * 是否记录包内容（可能影响性能）
     */
    private boolean capturePacketContent = false;

    /**
     * 包内容最大长度（字节）
     */
    private int maxPacketContentLength = 512;

    /**
     * 检查入站包是否被屏蔽
     */
    public boolean isInPacketBlocked(int opcode) {
        return inPacketBlocklist.contains(opcode);
    }

    /**
     * 检查出站包是否被屏蔽
     */
    public boolean isOutPacketBlocked(int opcode) {
        return outPacketBlocklist.contains(opcode);
    }

    /**
     * 添加入站包屏蔽
     */
    public void addInPacketBlock(int opcode) {
        inPacketBlocklist.add(opcode);
    }

    /**
     * 移除入站包屏蔽
     */
    public void removeInPacketBlock(int opcode) {
        inPacketBlocklist.remove(opcode);
    }

    /**
     * 添加出站包屏蔽
     */
    public void addOutPacketBlock(int opcode) {
        outPacketBlocklist.add(opcode);
    }

    /**
     * 移除出站包屏蔽
     */
    public void removeOutPacketBlock(int opcode) {
        outPacketBlocklist.remove(opcode);
    }

    /**
     * 添加入站屏蔽操作码
     */
    public void addInBlockOpcode(int opcode) {
        addInPacketBlock(opcode);
    }

    /**
     * 移除入站屏蔽操作码
     */
    public void removeInBlockOpcode(int opcode) {
        removeInPacketBlock(opcode);
    }

    /**
     * 添加出站屏蔽操作码
     */
    public void addOutBlockOpcode(int opcode) {
        addOutPacketBlock(opcode);
    }

    /**
     * 移除出站屏蔽操作码
     */
    public void removeOutBlockOpcode(int opcode) {
        removeOutPacketBlock(opcode);
    }

    /**
     * 检查入站操作码是否被屏蔽
     */
    public boolean isInBlockedOpcode(int opcode) {
        return isInPacketBlocked(opcode);
    }

    /**
     * 检查出站操作码是否被屏蔽
     */
    public boolean isOutBlockedOpcode(int opcode) {
        return isOutPacketBlocked(opcode);
    }

    /**
     * 获取入站屏蔽列表
     */
    public Set<Integer> getInBlockList() {
        return new HashSet<>(inPacketBlocklist);
    }

    /**
     * 获取出站屏蔽列表
     */
    public Set<Integer> getOutBlockList() {
        return new HashSet<>(outPacketBlocklist);
    }

    /**
     * 清空所有屏蔽列表
     */
    public void clearBlockLists() {
        inPacketBlocklist.clear();
        outPacketBlocklist.clear();
    }

    /**
     * 添加监控角色
     */
    public void addMonitoredCharacter(int characterId) {
        monitoredCharacterIds.add(characterId);
    }

    /**
     * 移除监控角色
     */
    public void removeMonitoredCharacter(int characterId) {
        monitoredCharacterIds.remove(characterId);
    }

    /**
     * 检查角色是否被监控
     */
    public boolean isMonitoredCharacter(int characterId) {
        return monitoredCharacterIds.contains(characterId);
    }
}
