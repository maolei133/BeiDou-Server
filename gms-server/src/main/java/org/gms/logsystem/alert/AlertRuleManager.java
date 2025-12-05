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

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * 告警规则管理服务
 * 负责告警规则的CRUD操作和告警执行
 */
@Slf4j
@Service
public class AlertRuleManager {
    
    /**
     * 规则存储 (内存存储)
     * 实际应用中应使用数据库
     */
    private final Map<Long, AlertRule> ruleStore = new ConcurrentHashMap<>();
    
    /**
     * 告警历史存储 (内存存储)
     */
    private final Map<Long, AlertHistory> historyStore = new ConcurrentHashMap<>();
    
    /**
     * 规则ID自增生成器
     */
    private final AtomicLong ruleIdGenerator = new AtomicLong(1000);
    
    /**
     * 历史记录ID自增生成器
     */
    private final AtomicLong historyIdGenerator = new AtomicLong(10000);
    
    /**
     * 创建告警规则
     */
    public synchronized AlertRule createRule(AlertRule rule) {
        // 验证规则
        if (!rule.isValid()) {
            throw new IllegalArgumentException("Invalid alert rule configuration");
        }
        
        // 生成ID
        Long id = ruleIdGenerator.incrementAndGet();
        rule.setId(id);
        
        // 设置默认值
        if (rule.getEnabled() == null) {
            rule.setEnabled(true);
        }
        if (rule.getAlertInterval() == null) {
            rule.setAlertInterval(60);  // 默认60秒
        }
        if (rule.getStatisticsPeriod() == null) {
            rule.setStatisticsPeriod(60);  // 默认60秒
        }
        if (rule.getNotificationEnabled() == null) {
            rule.setNotificationEnabled(true);
        }
        if (rule.getAlertCount() == null) {
            rule.setAlertCount(0);
        }
        
        // 设置时间戳
        rule.setCreatedAt(LocalDateTime.now());
        rule.setUpdatedAt(LocalDateTime.now());
        
        // 存储规则
        ruleStore.put(id, rule);
        
        log.info("Alert rule created: {} (ID: {})", rule.getSummary(), id);
        return rule;
    }
    
    /**
     * 获取规则详情
     */
    public AlertRule getRule(Long ruleId) {
        AlertRule rule = ruleStore.get(ruleId);
        if (rule == null) {
            log.warn("Alert rule not found: {}", ruleId);
            return null;
        }
        return rule;
    }
    
    /**
     * 获取所有规则
     */
    public List<AlertRule> getAllRules() {
        return new ArrayList<>(ruleStore.values());
    }
    
    /**
     * 获取启用的规则
     */
    public List<AlertRule> getEnabledRules() {
        return ruleStore.values().stream()
            .filter(r -> r.getEnabled() != null && r.getEnabled())
            .collect(Collectors.toList());
    }
    
    /**
     * 按类型获取规则
     */
    public List<AlertRule> getRulesByType(String conditionType) {
        return ruleStore.values().stream()
            .filter(r -> conditionType.equals(r.getConditionType()))
            .collect(Collectors.toList());
    }
    
    /**
     * 更新规则
     */
    public synchronized AlertRule updateRule(Long ruleId, AlertRule updates) {
        AlertRule existing = ruleStore.get(ruleId);
        if (existing == null) {
            throw new IllegalArgumentException("Rule not found: " + ruleId);
        }
        
        // 更新字段
        if (updates.getRuleName() != null) {
            existing.setRuleName(updates.getRuleName());
        }
        if (updates.getDescription() != null) {
            existing.setDescription(updates.getDescription());
        }
        if (updates.getEnabled() != null) {
            existing.setEnabled(updates.getEnabled());
        }
        if (updates.getConditionType() != null) {
            existing.setConditionType(updates.getConditionType());
        }
        if (updates.getThreshold() != null) {
            existing.setThreshold(updates.getThreshold());
        }
        if (updates.getOperator() != null) {
            existing.setOperator(updates.getOperator());
        }
        if (updates.getDuration() != null) {
            existing.setDuration(updates.getDuration());
        }
        if (updates.getActionType() != null) {
            existing.setActionType(updates.getActionType());
        }
        if (updates.getActionTarget() != null) {
            existing.setActionTarget(updates.getActionTarget());
        }
        if (updates.getAlertInterval() != null) {
            existing.setAlertInterval(updates.getAlertInterval());
        }
        
        existing.setUpdatedAt(LocalDateTime.now());
        
        log.info("Alert rule updated: {} (ID: {})", existing.getSummary(), ruleId);
        return existing;
    }
    
    /**
     * 删除规则
     */
    public synchronized boolean deleteRule(Long ruleId) {
        AlertRule removed = ruleStore.remove(ruleId);
        if (removed != null) {
            log.info("Alert rule deleted: {} (ID: {})", removed.getSummary(), ruleId);
            return true;
        }
        return false;
    }
    
    /**
     * 启用规则
     */
    public synchronized void enableRule(Long ruleId) {
        AlertRule rule = ruleStore.get(ruleId);
        if (rule != null) {
            rule.setEnabled(true);
            rule.setUpdatedAt(LocalDateTime.now());
            log.info("Alert rule enabled: {}", ruleId);
        }
    }
    
    /**
     * 禁用规则
     */
    public synchronized void disableRule(Long ruleId) {
        AlertRule rule = ruleStore.get(ruleId);
        if (rule != null) {
            rule.setEnabled(false);
            rule.setUpdatedAt(LocalDateTime.now());
            log.info("Alert rule disabled: {}", ruleId);
        }
    }
    
    /**
     * 记录告警历史
     */
    public synchronized AlertHistory recordAlert(Long ruleId, Double actualValue, 
                                                  String message, String severity) {
        AlertRule rule = ruleStore.get(ruleId);
        if (rule == null) {
            log.warn("Cannot record alert for non-existent rule: {}", ruleId);
            return null;
        }
        
        // 创建历史记录
        AlertHistory history = AlertHistory.builder()
            .id(historyIdGenerator.incrementAndGet())
            .ruleId(ruleId)
            .ruleName(rule.getRuleName())
            .alertTime(LocalDateTime.now())
            .condition(rule.getConditionType())
            .actualValue(actualValue)
            .threshold(rule.getThreshold())
            .targetCategory(rule.getTargetCategory())
            .severity(severity)
            .message(message)
            .actionType(rule.getActionType())
            .actionTarget(rule.getActionTarget())
            .actionResult("PENDING")
            .status("NEW")
            .build();
        
        // 存储历史记录
        historyStore.put(history.getId(), history);
        
        // 更新规则的告警时间和计数
        rule.updateLastAlertTime();
        
        log.warn("Alert triggered: Rule={}, Value={}, Severity={}", 
                 rule.getRuleName(), actualValue, severity);
        
        return history;
    }
    
    /**
     * 获取告警历史
     */
    public List<AlertHistory> getAlertHistory(Long ruleId, int limit) {
        return historyStore.values().stream()
            .filter(h -> ruleId.equals(h.getRuleId()))
            .sorted((h1, h2) -> h2.getAlertTime().compareTo(h1.getAlertTime()))
            .limit(limit)
            .collect(Collectors.toList());
    }
    
    /**
     * 获取最近的告警
     */
    public List<AlertHistory> getRecentAlerts(int limit) {
        return historyStore.values().stream()
            .sorted((h1, h2) -> h2.getAlertTime().compareTo(h1.getAlertTime()))
            .limit(limit)
            .collect(Collectors.toList());
    }
    
    /**
     * 获取未处理的告警
     */
    public List<AlertHistory> getUnresolvedAlerts() {
        return historyStore.values().stream()
            .filter(h -> "NEW".equals(h.getStatus()) || "ACKNOWLEDGED".equals(h.getStatus()))
            .sorted((h1, h2) -> h2.getAlertTime().compareTo(h1.getAlertTime()))
            .collect(Collectors.toList());
    }
    
    /**
     * 确认告警
     */
    public synchronized void acknowledgeAlert(Long historyId) {
        AlertHistory history = historyStore.get(historyId);
        if (history != null) {
            history.setStatus("ACKNOWLEDGED");
            history.setResolvedTime(LocalDateTime.now());
            log.info("Alert acknowledged: {}", historyId);
        }
    }
    
    /**
     * 解决告警
     */
    public synchronized void resolveAlert(Long historyId, String remark) {
        AlertHistory history = historyStore.get(historyId);
        if (history != null) {
            history.setStatus("RESOLVED");
            history.setResolvedTime(LocalDateTime.now());
            history.setRemark(remark);
            log.info("Alert resolved: {}", historyId);
        }
    }
    
    /**
     * 获取统计信息
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        List<AlertRule> allRules = getAllRules();
        List<AlertRule> enabledRules = getEnabledRules();
        List<AlertHistory> unresolvedAlerts = getUnresolvedAlerts();
        
        stats.put("totalRules", allRules.size());
        stats.put("enabledRules", enabledRules.size());
        stats.put("disabledRules", allRules.size() - enabledRules.size());
        stats.put("totalAlerts", historyStore.size());
        stats.put("unresolvedAlerts", unresolvedAlerts.size());
        
        // 按类型分组统计
        Map<String, Long> rulesByType = allRules.stream()
            .collect(Collectors.groupingBy(AlertRule::getConditionType, Collectors.counting()));
        stats.put("rulesByType", rulesByType);
        
        // 统计最近24小时的告警
        LocalDateTime oneDayAgo = LocalDateTime.now().minusHours(24);
        long alertsLast24h = historyStore.values().stream()
            .filter(h -> h.getAlertTime().isAfter(oneDayAgo))
            .count();
        stats.put("alertsLast24h", alertsLast24h);
        
        return stats;
    }
    
    /**
     * 清空所有数据 (用于测试)
     */
    public synchronized void clear() {
        ruleStore.clear();
        historyStore.clear();
        log.info("All alert rules and history cleared");
    }
}
