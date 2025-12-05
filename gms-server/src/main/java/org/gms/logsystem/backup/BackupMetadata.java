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

package org.gms.logsystem.backup;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 备份元数据
 * 记录每次备份的详细信息
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BackupMetadata {
    
    /**
     * 备份ID (唯一标识)
     */
    private String backupId;
    
    /**
     * 备份类型
     * FULL: 完整备份
     * INCREMENTAL: 增量备份
     */
    private String backupType;
    
    /**
     * 备份文件路径
     */
    private String backupPath;
    
    /**
     * 备份文件大小 (字节)
     */
    private Long fileSize;
    
    /**
     * 压缩后大小 (字节)
     */
    private Long compressedSize;
    
    /**
     * 压缩率 (%)
     */
    private Double compressionRatio;
    
    /**
     * 备份开始时间
     */
    private LocalDateTime startTime;
    
    /**
     * 备份结束时间
     */
    private LocalDateTime endTime;
    
    /**
     * 备份耗时 (毫秒)
     */
    private Long durationMillis;
    
    /**
     * 备份状态
     * SUCCESS: 成功
     * FAILURE: 失败
     * PARTIAL: 部分成功
     */
    private String status;
    
    /**
     * 错误信息 (失败时)
     */
    private String errorMessage;
    
    /**
     * 备份涵盖的日志数量
     */
    private Long logCount;
    
    /**
     * 覆盖的时间范围 (开始)
     */
    private LocalDateTime logStartTime;
    
    /**
     * 覆盖的时间范围 (结束)
     */
    private LocalDateTime logEndTime;
    
    /**
     * 校验和 (用于验证完整性)
     */
    private String checksum;
    
    /**
     * 完整性检查结果
     */
    private Boolean integrityVerified;
    
    /**
     * 备份执行者
     */
    private String executedBy;
    
    /**
     * 备份执行的原因
     * SCHEDULED: 定时备份
     * MANUAL: 手动备份
     * AUTOMATIC: 自动备份
     */
    private String executionReason;
    
    /**
     * 上次完整备份的ID (对于增量备份)
     */
    private String baseBackupId;
    
    /**
     * 备注
     */
    private String remark;
    
    /**
     * 获取格式化的输出
     */
    public String getSummary() {
        return String.format(
            "Backup: %s | Type: %s | Size: %.2fMB | Logs: %d | Duration: %dms | Status: %s",
            backupId, backupType, fileSize / 1024.0 / 1024.0, logCount, durationMillis, status
        );
    }
}
