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

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
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
public class LogAlertService {
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final Map<String, AlertRule> alertRules = new ConcurrentHashMap<>();
    private final List<AlertHistory> alertHistory = Collections.synchronizedList(new ArrayList<>());
    private final List<AlertListener> listeners = Collections.synchronizedList(new ArrayList<>());
    private static final int MAX_ALERT_HISTORY = 10000;

    public void addAlertRule(AlertRule rule) {
        if (rule == null || rule.getRuleName() == null) {
            log.warn("添加告警规则失败: 规则名称不能为空");
            return;
        }
        alertRules.put(rule.getRuleName(), rule);
        log.info("添加告警规则成功: {}", rule.getRuleName());
    }

    public void removeAlertRule(String ruleName) {
        if (alertRules.remove(ruleName) != null) {
            log.info("删除告警规则成功: {}", ruleName);
        }
    }

    public Collection<AlertRule> getAllAlertRules() {
        return alertRules.values();
    }

    public AlertRule getAlertRule(String ruleName) {
        return alertRules.get(ruleName);
    }

    public void checkAlert(String majorCategory, String minorCategory, String message,
                          String accountName, String ipAddress) {
        for (AlertRule rule : alertRules.values()) {
            if (matchesRule(rule, majorCategory, minorCategory, message, accountName, ipAddress)) {
                triggerAlert(rule, majorCategory, minorCategory, message, accountName, ipAddress);
            }
        }
    }

    private boolean matchesRule(AlertRule rule, String majorCategory, String minorCategory,
                               String message, String accountName, String ipAddress) {
        if (rule.getMajorCategory() != null && !rule.getMajorCategory().isEmpty()) {
            if (!rule.getMajorCategory().equals(majorCategory)) {
                return false;
            }
        }

        if (rule.getMinorCategory() != null && !rule.getMinorCategory().isEmpty()) {
            if (!rule.getMinorCategory().equals(minorCategory)) {
                return false;
            }
        }

        if (rule.getKeyword() != null && !rule.getKeyword().isEmpty()) {
            String msg = message != null ? message.toLowerCase() : "";
            if (!msg.contains(rule.getKeyword().toLowerCase())) {
                return false;
            }
        }

        if (rule.getAccountName() != null && !rule.getAccountName().isEmpty()) {
            if (!rule.getAccountName().equals(accountName)) {
                return false;
            }
        }

        if (rule.getIpAddress() != null && !rule.getIpAddress().isEmpty()) {
            if (!rule.getIpAddress().equals(ipAddress)) {
                return false;
            }
        }

        return true;
    }

    private void triggerAlert(AlertRule rule, String majorCategory, String minorCategory,
                             String message, String accountName, String ipAddress) {
        AlertHistory history = new AlertHistory();
        history.setAlertId(UUID.randomUUID().toString());
        history.setRuleName(rule.getRuleName());
        history.setAlertType(rule.getAlertType());
        history.setMajorCategory(majorCategory);
        history.setMinorCategory(minorCategory);
        history.setMessage(message);
        history.setAccountName(accountName);
        history.setIpAddress(ipAddress);
        history.setTriggerTime(System.currentTimeMillis());
        history.setStatus("TRIGGERED");

        alertHistory.add(history);
        if (alertHistory.size() > MAX_ALERT_HISTORY) {
            alertHistory.remove(0);
        }

        log.warn("触发告警规则: {} - {}", rule.getRuleName(), message);
        notifyListeners(history, rule);
    }

    public void registerListener(AlertListener listener) {
        if (listener != null) {
            listeners.add(listener);
            log.info("注册告警监听器成功");
        }
    }

    public void unregisterListener(AlertListener listener) {
        if (listeners.remove(listener)) {
            log.info("注销告警监听器成功");
        }
    }

    private void notifyListeners(AlertHistory history, AlertRule rule) {
        for (AlertListener listener : listeners) {
            try {
                listener.onAlert(history, rule);
            } catch (Exception e) {
                log.error("告警监听器执行失败", e);
            }
        }
    }

    public List<AlertHistory> getAlertHistory(int limit) {
        return alertHistory.stream()
                .skip(Math.max(0, alertHistory.size() - limit))
                .collect(Collectors.toList());
    }

    public long getAlertCount(String ruleName) {
        return alertHistory.stream()
                .filter(h -> h.getRuleName().equals(ruleName))
                .count();
    }

    public void clearAlertHistory() {
        alertHistory.clear();
        log.info("告警历史已清空");
    }

    public String exportAlertRules() {
        return JSON.toJSONString(alertRules.values());
    }

    public void importAlertRules(String jsonData) {
        try {
            List<AlertRule> rules = JSON.parseArray(jsonData, AlertRule.class);
            for (AlertRule rule : rules) {
                addAlertRule(rule);
            }
            log.info("导入{}条告警规则成功", rules.size());
        } catch (Exception e) {
            log.error("导入告警规则失败", e);
        }
    }

    @Data
    public static class AlertRule {
        private String ruleName;
        private String alertType;
        private String majorCategory;
        private String minorCategory;
        private String keyword;
        private String accountName;
        private String ipAddress;
        private boolean enabled = true;
        private String description;
    }

    @Data
    public static class AlertHistory {
        private String alertId;
        private String ruleName;
        private String alertType;
        private String majorCategory;
        private String minorCategory;
        private String message;
        private String accountName;
        private String ipAddress;
        private long triggerTime;
        private String status;

        public String getTriggerTimeStr() {
            return new java.util.Date(triggerTime).toString();
        }
    }

    public interface AlertListener {
        void onAlert(AlertHistory history, AlertRule rule);
    }
}
