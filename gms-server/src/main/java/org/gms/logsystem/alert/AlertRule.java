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
 * 告警规则实体
 * 定义日志系统的告警规则和触发条件
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AlertRule {
    
    /**
     * 规则ID (唯一标识)
     */
    private Long id;
    
    /**
     * 规则名称 (用户友好的名称)
     */
    private String ruleName;
    
    /**
     * 规则描述
     */
    private String description;
    
    /**
     * 是否启用
     */
    private Boolean enabled;
    
    // ========== 条件配置 ==========
    
    /**
     * 条件类型
     * 可选值: FailureRate, Latency, QPS, MemoryUsage, CustomExpression
     */
    private String conditionType;
    
    /**
     * 目标分类 (如果为空则表示所有分类)
     * 格式: "major:minor" 或 "major:*"
     */
    private String targetCategory;
    
    /**
     * 阈值
     * - FailureRate: 0-100 (百分比)
     * - Latency: 毫秒数 (ms)
     * - QPS: 请求数/秒
     * - MemoryUsage: 百分比 0-100
     */
    private Double threshold;
    
    /**
     * 比较操作符
     * 可选值: >, <, >=, <=, ==, !=
     */
    private String operator;
    
    /**
     * 持续时间 (秒)
     * 只有当条件持续该时长才触发告警
     */
    private Integer duration;
    
    /**
     * 统计周期 (秒)
     * 用于计算平均值、QPS等指标的时间窗口
     */
    private Integer statisticsPeriod;
    
    // ========== 动作配置 ==========
    
    /**
     * 告警动作类型
     * 可选值: LOG, EMAIL, SMS, WEBHOOK, DATABASE
     */
    private String actionType;
    
    /**
     * 告警动作目标
     * - LOG: 日志级别 (INFO, WARN, ERROR)
     * - EMAIL: 邮箱地址 (支持多个,用逗号分隔)
     * - SMS: 手机号 (支持多个,用逗号分隔)
     * - WEBHOOK: URL地址
     * - DATABASE: 表名
     */
    private String actionTarget;
    
    /**
     * 告警消息模板
     */
    private String messageTemplate;
    
    /**
     * 是否发送通知
     */
    private Boolean notificationEnabled;
    
    /**
     * 通知接收者 (邮箱/钉钉/企业微信等)
     */
    private String notificationReceiver;
    
    // ========== 告警频率控制 ==========
    
    /**
     * 告警频率限制 (秒)
     * 相同规则在该时间内最多只发一次告警
     */
    private Integer alertInterval;
    
    /**
     * 上次告警时间
     */
    private LocalDateTime lastAlertTime;
    
    /**
     * 告警计数
     */
    private Integer alertCount;
    
    // ========== 元数据 ==========
    
    /**
     * 创建时间
     */
    private LocalDateTime createdAt;
    
    /**
     * 修改时间
     */
    private LocalDateTime updatedAt;
    
    /**
     * 创建者
     */
    private String createdBy;
    
    /**
     * 修改者
     */
    private String updatedBy;
    
    // ========== 方法 ==========
    
    /**
     * 检查是否应该触发告警
     * (基于告警频率限制)
     */
    public boolean shouldTriggerAlert() {
        if (lastAlertTime == null) {
            return true;  // 第一次总是触发
        }
        
        LocalDateTime now = LocalDateTime.now();
        long secondsElapsed = java.time.temporal.ChronoUnit.SECONDS
            .between(lastAlertTime, now);
        
        return secondsElapsed >= (alertInterval != null ? alertInterval : 60);
    }
    
    /**
     * 更新上次告警时间
     */
    public void updateLastAlertTime() {
        this.lastAlertTime = LocalDateTime.now();
        if (alertCount == null) {
            alertCount = 0;
        }
        alertCount++;
    }
    
    /**
     * 验证规则配置
     */
    public boolean isValid() {
        if (ruleName == null || ruleName.isEmpty()) {
            return false;
        }
        if (conditionType == null || conditionType.isEmpty()) {
            return false;
        }
        if (threshold == null) {
            return false;
        }
        if (operator == null || operator.isEmpty()) {
            return false;
        }
        if (duration == null || duration <= 0) {
            return false;
        }
        if (actionType == null || actionType.isEmpty()) {
            return false;
        }
        return true;
    }
    
    /**
     * 获取规则摘要 (用于日志和显示)
     */
    public String getSummary() {
        return String.format(
            "Rule: %s | Type: %s | Condition: %s %s %.2f | Duration: %ds | Action: %s",
            ruleName, conditionType, conditionType, operator, threshold, duration, actionType
        );
    }
}
