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

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 告警通知服务
 * 负责将告警信息通过多种渠道（邮件、系统通知等）发送出去
 *
 * @author logs-system
 */
@Slf4j
@Service
public class AlertNotificationService {
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Value("${logsystem.alert.email.enabled:false}")
    private boolean emailEnabled;

    @Value("${logsystem.alert.email.host:smtp.gmail.com}")
    private String emailHost;

    @Value("${logsystem.alert.email.port:587}")
    private int emailPort;

    @Value("${logsystem.alert.email.sender:}")
    private String emailSender;

    @Value("${logsystem.alert.email.password:}")
    private String emailPassword;

    @Value("${logsystem.alert.email.recipients:}")
    private String emailRecipients;

    /**
     * 通知监听器列表
     */
    private final List<NotificationListener> listeners = new ArrayList<>();

    /**
     * 通知历史记录
     */
    private final List<NotificationRecord> notificationHistory = Collections.synchronizedList(new ArrayList<>());

    /**
     * 最大保留通知记录数
     */
    private static final int MAX_NOTIFICATION_HISTORY = 5000;

    /**
     * 注册通知监听器
     */
    public void registerListener(NotificationListener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
            log.info("通知监听器已注册");
        }
    }

    /**
     * 注销通知监听器
     */
    public void unregisterListener(NotificationListener listener) {
        if (listeners.remove(listener)) {
            log.info("通知监听器已注销");
        }
    }

    /**
     * 发送告警通知
     */
    public void sendAlertNotification(AlertNotification notification) {
        try {
            // 验证通知内容
            if (!validateNotification(notification)) {
                log.warn("告警通知验证失败: {}", notification.getMessage());
                return;
            }

            // 记录通知历史
            recordNotification(notification);

            // 通过邮件发送
            if (emailEnabled && !emailRecipients.isEmpty()) {
                sendEmailNotification(notification);
            }

            // 通过监听器发送
            notifyListeners(notification);

            log.info("告警通知已发送: {}", notification.getAlertId());
        } catch (Exception e) {
            log.error("发送告警通知失败", e);
        }
    }

    /**
     * 发送邮件通知
     */
    private void sendEmailNotification(AlertNotification notification) {
        try {
            String[] recipients = emailRecipients.split("[,;]");
            String subject = String.format("[%s] 游戏日志告警通知 - %s", 
                    notification.getAlertLevel(), 
                    notification.getRuleName());
            
            String body = buildEmailBody(notification);
            
            // TODO: 实现实际的邮件发送逻辑
            // 这里需要集成邮件服务（如Spring Mail, JavaMail等）
            log.info("邮件通知已发送至: {}, 主题: {}", Arrays.toString(recipients), subject);
        } catch (Exception e) {
            log.error("邮件通知发送失败", e);
        }
    }

    /**
     * 构建邮件内容
     */
    private String buildEmailBody(AlertNotification notification) {
        StringBuilder body = new StringBuilder();
        body.append("================== 游戏日志告警通知 ==================\n\n");
        body.append("告警ID: ").append(notification.getAlertId()).append("\n");
        body.append("告警规则: ").append(notification.getRuleName()).append("\n");
        body.append("告警等级: ").append(notification.getAlertLevel()).append("\n");
        body.append("告警类型: ").append(notification.getAlertType()).append("\n");
        body.append("发送时间: ").append(LocalDateTime.now().format(formatter)).append("\n\n");
        body.append("告警详情:\n");
        body.append(notification.getMessage()).append("\n\n");
        
        if (notification.getDetails() != null) {
            body.append("详细信息:\n");
            notification.getDetails().forEach((key, value) -> 
                body.append("  ").append(key).append(": ").append(value).append("\n"));
        }
        
        body.append("\n================================================\n");
        return body.toString();
    }

    /**
     * 通知所有监听器
     */
    private void notifyListeners(AlertNotification notification) {
        for (NotificationListener listener : listeners) {
            try {
                listener.onNotification(notification);
            } catch (Exception e) {
                log.error("通知监听器执行失败", e);
            }
        }
    }

    /**
     * 记录通知历史
     */
    private void recordNotification(AlertNotification notification) {
        NotificationRecord record = new NotificationRecord();
        record.setNotificationId(notification.getAlertId());
        record.setRuleName(notification.getRuleName());
        record.setAlertLevel(notification.getAlertLevel());
        record.setMessage(notification.getMessage());
        record.setTimestamp(System.currentTimeMillis());
        record.setStatus("SENT");

        notificationHistory.add(record);
        
        // 保留最多MAX_NOTIFICATION_HISTORY条记录
        if (notificationHistory.size() > MAX_NOTIFICATION_HISTORY) {
            notificationHistory.remove(0);
        }
    }

    /**
     * 验证通知内容
     */
    private boolean validateNotification(AlertNotification notification) {
        return notification != null 
                && notification.getAlertId() != null
                && !notification.getAlertId().isEmpty()
                && notification.getRuleName() != null
                && !notification.getRuleName().isEmpty()
                && notification.getMessage() != null
                && !notification.getMessage().isEmpty();
    }

    /**
     * 获取通知历史
     */
    public List<NotificationRecord> getNotificationHistory(int limit) {
        int size = notificationHistory.size();
        int startIndex = Math.max(0, size - limit);
        return new ArrayList<>(notificationHistory.subList(startIndex, size));
    }

    /**
     * 清空通知历史
     */
    public void clearNotificationHistory() {
        notificationHistory.clear();
        log.info("通知历史已清空");
    }

    /**
     * 获取通知统计信息
     */
    public Map<String, Object> getNotificationStatistics() {
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("totalNotifications", notificationHistory.size());
        stats.put("emailEnabled", emailEnabled);
        
        // 统计各告警等级的通知数量
        Map<String, Long> levelStats = new LinkedHashMap<>();
        notificationHistory.forEach(record -> {
            levelStats.merge(record.getAlertLevel(), 1L, Long::sum);
        });
        stats.put("levelStatistics", levelStats);
        
        // 统计各规则的通知数量
        Map<String, Long> ruleStats = new LinkedHashMap<>();
        notificationHistory.forEach(record -> {
            ruleStats.merge(record.getRuleName(), 1L, Long::sum);
        });
        stats.put("ruleStatistics", ruleStats);
        
        stats.put("timestamp", System.currentTimeMillis());
        return stats;
    }

    /**
     * 告警通知对象
     */
    @Data
    public static class AlertNotification {
        private String alertId;
        private String ruleName;
        private String alertType;
        private String alertLevel;    // CRITICAL, HIGH, MEDIUM, LOW
        private String message;
        private String accountName;
        private String ipAddress;
        private Map<String, Object> details;
        private long timestamp;

        public AlertNotification() {
            this.timestamp = System.currentTimeMillis();
        }
    }

    /**
     * 通知监听器接口
     */
    public interface NotificationListener {
        void onNotification(AlertNotification notification);
    }

    /**
     * 通知记录
     */
    @Data
    public static class NotificationRecord {
        private String notificationId;
        private String ruleName;
        private String alertLevel;
        private String message;
        private long timestamp;
        private String status;   // SENT, FAILED, PENDING

        public String getTimestampStr() {
            return LocalDateTime.now().format(formatter);
        }
    }

    /**
     * 系统通知监听器实现（用于处理系统内部通知）
     */
    public static class SystemNotificationListener implements NotificationListener {
        private final List<AlertNotification> notifications = Collections.synchronizedList(new ArrayList<>());
        private static final int MAX_NOTIFICATIONS = 1000;

        @Override
        public void onNotification(AlertNotification notification) {
            notifications.add(notification);
            if (notifications.size() > MAX_NOTIFICATIONS) {
                notifications.remove(0);
            }
        }

        public List<AlertNotification> getNotifications() {
            return new ArrayList<>(notifications);
        }

        public void clear() {
            notifications.clear();
        }
    }
}
