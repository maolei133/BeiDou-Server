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

package org.gms.logsystem.monitor;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
@Service
public class AlertRuleService {
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    
    private final Map<String, AlertRule> alertRules = new ConcurrentHashMap<>();
    private final Map<String, AlertHistory> alertHistory = new ConcurrentHashMap<>();
    private final List<AlertRuleListener> listeners = new ArrayList<>();
    private long ruleVersion = 0;

    public void addAlertRule(AlertRule rule) {
        if (rule == null || rule.getRuleId() == null) {
            log.warn("告警规则ID不能为空");
            return;
        }
        
        alertRules.put(rule.getRuleId(), rule);
        ruleVersion++;
        notifyListeners(rule, AlertRuleListener.RuleEvent.ADDED);
        log.info("告警规则已添加: {} - {}", rule.getRuleId(), rule.getRuleName());
    }

    public void updateAlertRule(AlertRule rule) {
        if (rule == null || rule.getRuleId() == null) {
            log.warn("告警规则ID不能为空");
            return;
        }
        
        AlertRule existing = alertRules.get(rule.getRuleId());
        if (existing == null) {
            log.warn("告警规则不存在: {}", rule.getRuleId());
            return;
        }
        
        alertRules.put(rule.getRuleId(), rule);
        ruleVersion++;
        notifyListeners(rule, AlertRuleListener.RuleEvent.UPDATED);
        log.info("告警规则已更新: {} - {}", rule.getRuleId(), rule.getRuleName());
    }

    public void removeAlertRule(String ruleId) {
        AlertRule removed = alertRules.remove(ruleId);
        if (removed != null) {
            ruleVersion++;
            notifyListeners(removed, AlertRuleListener.RuleEvent.REMOVED);
            log.info("告警规则已删除: {}", ruleId);
        }
    }

    public AlertRule getAlertRule(String ruleId) {
        return alertRules.get(ruleId);
    }

    public Collection<AlertRule> getAllAlertRules() {
        return alertRules.values();
    }

    public List<AlertRule> getEnabledAlertRules() {
        return alertRules.values().stream()
                .filter(AlertRule::isEnabled)
                .collect(Collectors.toList());
    }

    public void recordAlertHistory(String ruleId, String accountName, String message) {
        AlertRule rule = alertRules.get(ruleId);
        if (rule == null) return;

        AlertHistory history = new AlertHistory();
        history.setHistoryId(UUID.randomUUID().toString());
        history.setRuleId(ruleId);
        history.setRuleName(rule.getRuleName());
        history.setAlertType(rule.getAlertType());
        history.setAccountName(accountName);
        history.setMessage(message);
        history.setTriggeredTime(System.currentTimeMillis());
        history.setAlertLevel(rule.getAlertLevel());

        alertHistory.put(history.getHistoryId(), history);
        
        // 只保留最近10000条记录
        if (alertHistory.size() > 10000) {
            String oldestKey = alertHistory.entrySet().stream()
                    .min(Comparator.comparingLong(e -> e.getValue().getTriggeredTime()))
                    .map(Map.Entry::getKey)
                    .orElse(null);
            if (oldestKey != null) {
                alertHistory.remove(oldestKey);
            }
        }

        log.warn("告警已触发: {} - {}", rule.getRuleName(), message);
    }

    public List<AlertHistory> getAlertHistory(int limit) {
        return alertHistory.values().stream()
                .sorted(Comparator.comparingLong(AlertHistory::getTriggeredTime).reversed())
                .limit(limit)
                .collect(Collectors.toList());
    }

    public List<AlertHistory> getAlertHistoryByRuleId(String ruleId, int limit) {
        return alertHistory.values().stream()
                .filter(h -> h.getRuleId().equals(ruleId))
                .sorted(Comparator.comparingLong(AlertHistory::getTriggeredTime).reversed())
                .limit(limit)
                .collect(Collectors.toList());
    }

    public long getAlertCount(String ruleId) {
        return alertHistory.values().stream()
                .filter(h -> h.getRuleId().equals(ruleId))
                .count();
    }

    public void registerListener(AlertRuleListener listener) {
        if (!listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    public void unregisterListener(AlertRuleListener listener) {
        listeners.remove(listener);
    }

    private void notifyListeners(AlertRule rule, AlertRuleListener.RuleEvent event) {
        for (AlertRuleListener listener : listeners) {
            try {
                listener.onRuleChange(rule, event);
            } catch (Exception e) {
                log.error("告警规则监听器执行失败", e);
            }
        }
    }

    public long getRuleVersion() {
        return ruleVersion;
    }

    public Map<String, Integer> getAlertStats() {
        Map<String, Integer> stats = new LinkedHashMap<>();
        stats.put("totalRules", alertRules.size());
        stats.put("enabledRules", (int) alertRules.values().stream().filter(AlertRule::isEnabled).count());
        stats.put("totalAlerts", alertHistory.size());
        return stats;
    }

    /**
     * 获取所有告警规则（列表格式）
     */
    public List<Map<String, Object>> getAllAlertRulesAsMaps() {
        List<Map<String, Object>> rules = new ArrayList<>();
        for (AlertRule rule : alertRules.values()) {
            Map<String, Object> ruleMap = new LinkedHashMap<>();
            ruleMap.put("ruleId", rule.getRuleId());
            ruleMap.put("ruleName", rule.getRuleName());
            ruleMap.put("description", rule.getDescription());
            ruleMap.put("alertType", rule.getAlertType());
            ruleMap.put("alertLevel", rule.getAlertLevel());
            ruleMap.put("enabled", rule.isEnabled());
            ruleMap.put("createdTime", rule.getCreatedTime());
            rules.add(ruleMap);
        }
        return rules;
    }

    /**
     * 添加告警规则
     */
    public boolean addAlertRule(Map<String, Object> ruleData) {
        try {
            AlertRule rule = new AlertRule();
            rule.setRuleId(UUID.randomUUID().toString());
            rule.setRuleName((String) ruleData.get("ruleName"));
            rule.setDescription((String) ruleData.get("description"));
            rule.setAlertType((String) ruleData.get("alertType"));
            rule.setAlertLevel((String) ruleData.get("alertLevel"));
            rule.setEnabled((Boolean) ruleData.getOrDefault("enabled", true));
            
            addAlertRule(rule);
            return true;
        } catch (Exception e) {
            log.error("添加告警规则失败", e);
            return false;
        }
    }

    /**
     * 删除告警规则
     */
    public boolean deleteAlertRule(String ruleId) {
        if (alertRules.containsKey(ruleId)) {
            removeAlertRule(ruleId);
            return true;
        }
        return false;
    }

    @Data
    public static class AlertRule {
        private String ruleId;
        private String ruleName;
        private String description;
        private String alertType; // ERROR, WARN, INFO
        private String alertLevel; // CRITICAL, HIGH, MEDIUM, LOW
        private String majorCategory;
        private String minorCategory;
        private String keyword;
        private String accountName;
        private int threshold; // 触发阈值
        private int timeWindowSeconds; // 时间窗口（秒）
        private boolean enabled = true;
        private long createdTime = System.currentTimeMillis();
        private long lastModifiedTime = System.currentTimeMillis();
    }

    @Data
    public static class AlertHistory {
        private String historyId;
        private String ruleId;
        private String ruleName;
        private String alertType;
        private String accountName;
        private String message;
        private long triggeredTime;
        private String alertLevel;

        public String getTriggeredTimeStr() {
            return LocalDateTime.now().format(formatter);
        }
    }

    public interface AlertRuleListener {
        void onRuleChange(AlertRule rule, RuleEvent event);

        enum RuleEvent {
            ADDED, UPDATED, REMOVED
        }
    }
}

