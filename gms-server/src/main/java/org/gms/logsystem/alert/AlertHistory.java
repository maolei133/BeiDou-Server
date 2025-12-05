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

package org.gms.logsystem.alert;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 告警历史记录
 * 记录每次告警事件的详细信息
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AlertHistory {
    
    /**
     * 历史记录ID
     */
    private Long id;
    
    /**
     * 关联的规则ID
     */
    private Long ruleId;
    
    /**
     * 规则名称 (冗余存储,便于查询)
     */
    private String ruleName;
    
    /**
     * 告警时间
     */
    private LocalDateTime alertTime;
    
    /**
     * 触发的条件
     * 例如: "FailureRate > 10%" 或 "Latency > 200ms"
     */
    private String condition;
    
    /**
     * 实际值
     * 例如: 12.5 (表示12.5%)
     */
    private Double actualValue;
    
    /**
     * 阈值
     */
    private Double threshold;
    
    /**
     * 相关分类
     */
    private String targetCategory;
    
    /**
     * 告警级别
     * 可选值: INFO, WARN, ERROR, CRITICAL
     */
    private String severity;
    
    /**
     * 告警消息
     */
    private String message;
    
    /**
     * 动作类型
     */
    private String actionType;
    
    /**
     * 动作目标
     */
    private String actionTarget;
    
    /**
     * 动作执行结果
     * 可选值: SUCCESS, FAILURE, PENDING
     */
    private String actionResult;
    
    /**
     * 执行错误信息 (如果失败)
     */
    private String errorMessage;
    
    /**
     * 相关数据 (JSON格式)
     * 存储告警时的相关上下文数据
     */
    private String contextData;
    
    /**
     * 处理状态
     * 可选值: NEW, ACKNOWLEDGED, RESOLVED, IGNORED
     */
    private String status;
    
    /**
     * 处理时间
     */
    private LocalDateTime resolvedTime;
    
    /**
     * 处理备注
     */
    private String remark;
}
