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

import lombok.Data;

import java.time.LocalDateTime;

/**
 * 备份策略
 * 定义备份的时间表和配置参数
 */
@Data
public class BackupStrategy {
    
    /**
     * 备份类型
     * FULL: 完整备份
     * INCREMENTAL: 增量备份
     */
    private String backupType;
    
    /**
     * 备份位置
     * 本地路径或远程URL
     */
    private String backupLocation;
    
    /**
     * 保留天数
     * 超过该天数的备份将被删除
     */
    private Integer retentionDays;
    
    /**
     * 压缩算法
     * GZIP, ZIP, 7Z, NONE
     */
    private String compressionAlgorithm;
    
    /**
     * 是否启用
     */
    private Boolean enabled;
    
    /**
     * 上次备份时间
     */
    private LocalDateTime lastBackupTime;
    
    /**
     * 上次备份大小 (字节)
     */
    private Long lastBackupSize;
    
    /**
     * 备份状态
     * PENDING, IN_PROGRESS, SUCCESS, FAILURE
     */
    private String status;
    
    /**
     * 错误信息
     */
    private String errorMessage;
    
    /**
     * 并发线程数
     */
    private Integer concurrentThreads;
    
    /**
     * 是否检查完整性
     */
    private Boolean verifyIntegrity;
    
    /**
     * 是否加密备份
     */
    private Boolean encrypted;
    
    /**
     * 加密密钥 (如果启用加密)
     */
    private String encryptionKey;
}
