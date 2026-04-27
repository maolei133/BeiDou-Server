/*
 This file is part of the HeavenMS MapleStory Server
 Copyleft (L) 2016 - 2019 RonanLana

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as
 published by the Free Software Foundation version 3 as published by
 the Free Software Foundation. You may not use, modify or distribute
 this program under any other version of the GNU Affero General Public
 License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.gms.scripting.event.scheduler;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.gms.config.GameConfig;
import org.gms.net.server.Server;
import org.gms.server.ThreadManager;
import org.gms.server.TimerManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.script.ScriptException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @author Ronan
 */
public class EventScriptScheduler {
    private static final Logger log = LoggerFactory.getLogger(EventScriptScheduler.class);

    private boolean disposed = false;
    private int idleProcs = 0;
    // 注解：将 <Runnable, Long> 修改为 <Runnable, ScheduledEvent>，以存储更多上下文信息
    private final Map<Runnable, ScheduledEvent> registeredEntries = new HashMap<>();

    private ScheduledFuture<?> schedulerTask = null;
    private final Lock schedulerLock = new ReentrantLock(true);

    /**
     * 内部类，用于封装计划任务及其上下文信息
     */
    @Getter
    @AllArgsConstructor
    private static class ScheduledEvent {
        private final Runnable action;
        private final long executionTime;
        private final String scriptPath;
        private final String eventName;
    }

    private void runBaseSchedule() {
        List<Runnable> toRemove;
        Map<Runnable, ScheduledEvent> registeredEntriesCopy;

        schedulerLock.lock();
        try {
            if (registeredEntries.isEmpty()) {
                idleProcs++;

                if (idleProcs >= GameConfig.getServerInt("mob_status_monitor_idle")) {
                    if (schedulerTask != null) {
                        schedulerTask.cancel(false);
                        schedulerTask = null;
                    }
                }

                return;
            }

            idleProcs = 0;
            registeredEntriesCopy = new HashMap<>(registeredEntries);
        } finally {
            schedulerLock.unlock();
        }

        long timeNow = Server.getInstance().getCurrentTime();
        toRemove = new LinkedList<>();
        for (Entry<Runnable, ScheduledEvent> entry : registeredEntriesCopy.entrySet()) {
            ScheduledEvent scheduledEvent = entry.getValue();
            if (scheduledEvent.getExecutionTime() < timeNow) {
                Runnable r = scheduledEvent.getAction();

                try {
                    r.run();  // 运行计划任务
                } catch (Throwable t) { // 注解：捕获 Throwable 以包含 OutOfMemoryError
                    // 增强错误日志，提供详细的脚本路径和事件信息
                    String scriptPath = scheduledEvent.getScriptPath();
                    String eventName = scheduledEvent.getEventName();

                    if (t instanceof ScriptException se) {
                        log.error("[事件脚本] 执行失败！脚本路径: '{}', 事件: '{}', 错误: {}, 行号: {}",
                                scriptPath, eventName, se.getMessage(), se.getLineNumber());
                    } else if (t instanceof OutOfMemoryError) {
                        log.error("[事件脚本] 发生内存溢出！请立即检查脚本。脚本路径: '{}', 事件: '{}'",
                                scriptPath, eventName, t);
                    } else {
                        log.error("[事件脚本] 发生未知错误。脚本路径: '{}', 事件: '{}'",
                                scriptPath, eventName, t);
                    }
                } finally {
                    // 无论任务是否成功执行，都标记为需要移除
                    toRemove.add(r);
                }
            }
        }

        if (!toRemove.isEmpty()) {
            schedulerLock.lock();
            try {
                for (Runnable r : toRemove) {
                    registeredEntries.remove(r);
                }
            } finally {
                schedulerLock.unlock();
            }
        }
    }

    /**
     * 注册一个计划执行的事件脚本。
     * @param scheduledAction 要执行的 Runnable 任务
     * @param duration 延迟执行的时间（毫秒）
     * @param scriptPath 脚本的路径，用于日志记录
     * @param eventName 事件的名称，用于日志记录
     */
    public void registerEntry(final Runnable scheduledAction, final long duration, final String scriptPath, final String eventName) {

        ThreadManager.getInstance().newTask(() -> {
            schedulerLock.lock();
            try {
                idleProcs = 0;
                if (schedulerTask == null) {
                    if (disposed) {
                        return;
                    }

                    schedulerTask = TimerManager.getInstance().register(this::runBaseSchedule, GameConfig.getServerLong("mob_status_monitor_proc"), GameConfig.getServerLong("mob_status_monitor_proc"));
                }

                long executionTime = Server.getInstance().getCurrentTime() + duration;
                ScheduledEvent event = new ScheduledEvent(scheduledAction, executionTime, scriptPath, eventName);
                registeredEntries.put(scheduledAction, event);
            } finally {
                schedulerLock.unlock();
            }
        });
    }

    public void cancelEntry(final Runnable scheduledAction) {

        ThreadManager.getInstance().newTask(() -> {
            schedulerLock.lock();
            try {
                registeredEntries.remove(scheduledAction);
            } finally {
                schedulerLock.unlock();
            }
        });
    }

    public void dispose() {

        ThreadManager.getInstance().newTask(() -> {
            schedulerLock.lock();
            try {
                if (schedulerTask != null) {
                    schedulerTask.cancel(false);
                    schedulerTask = null;
                }

                registeredEntries.clear();
                disposed = true;
            } finally {
                schedulerLock.unlock();
            }
        });
    }
}
