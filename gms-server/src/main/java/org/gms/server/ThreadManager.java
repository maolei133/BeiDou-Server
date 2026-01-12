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
package org.gms.server;

import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * @author Ronan
 */
public class ThreadManager {
    private static final Logger log = LoggerFactory.getLogger(ThreadManager.class);

    @Getter
    private static final ThreadManager instance = new ThreadManager();

    private ExecutorService executorService;

    // 用于追踪活跃任务：Key=任务对象, Value=任务信息(名称,开始时间)
    private final Map<TrackedRunnable, TaskInfo> activeTasks = new ConcurrentHashMap<>();

    private ThreadManager() {}

    /**
     * 提交一个新任务
     * @param r 任务逻辑
     */
    public void newTask(Runnable r) {
        // 如果没有提供名称，尝试获取类名或toString，Lambda表达式可能名字不太直观
        newTask(r, r.getClass().getSimpleName().isEmpty() ? r.toString() : r.getClass().getSimpleName());
    }

    /**
     * 提交一个带名称的新任务（推荐使用，便于排查问题）
     * @param r 任务逻辑
     * @param name 任务名称
     */
    public void newTask(Runnable r, String name) {
        if (executorService == null || executorService.isShutdown()) {
            log.warn("ThreadManager已关闭，丢弃任务: {}", name);
            return;
        }
        // 包装任务以进行追踪
        executorService.execute(new TrackedRunnable(r, name));
    }

    public void start() {
        // 注意，虚拟线程不建议池化，所以也不需要拒绝策略
        executorService = Executors.newVirtualThreadPerTaskExecutor();
    }

    public void stop() {
        log.info("正在停止 ThreadManager，当前活跃任务数: {}", activeTasks.size());
        executorService.shutdown();

        long maxWaitSeconds = 60;
        long endTime = System.currentTimeMillis() + (maxWaitSeconds * 1000);

        try {
            while (System.currentTimeMillis() < endTime) {
                // 每次等待 1 秒
                if (executorService.awaitTermination(1, TimeUnit.SECONDS)) {
                    log.info("ThreadManager 所有任务已正常结束。");
                    return;
                }

                int remaining = activeTasks.size();
                if (remaining > 0) {
                    log.info("等待 ThreadManager 关闭... 剩余任务: {} 个", remaining);

                    // 打印运行时间超过 3 秒的任务，帮助定位瓶颈
                    long now = System.currentTimeMillis();
                    activeTasks.forEach((task, info) -> {
                        long duration = now - info.startTime;
                        if (duration > 3000) { // 只显示运行超过3秒的
                            log.warn(">> [慢任务警告] 任务: [{}] 已运行: {} ms", info.name, duration);
                        }
                    });
                }
            }

            log.error("ThreadManager 关闭超时 ({}s)！强制结束。剩余任务可能未完成。", maxWaitSeconds);
            // 打印所有剩余任务的名称，方便开发者修复
            String remainingTasks = activeTasks.values().stream()
                    .map(info -> info.name + "(" + (System.currentTimeMillis() - info.startTime) + "ms)")
                    .collect(Collectors.joining(", "));
            log.error("未完成的任务: {}", remainingTasks);

            executorService.shutdownNow(); // 尝试强制中断

        } catch (InterruptedException e) {
            log.error("ThreadManager 关闭过程被中断", e);
            executorService.shutdownNow();
        }
    }

    // --- 内部辅助类 ---

    private static class TaskInfo {
        String name;
        long startTime;

        TaskInfo(String name, long startTime) {
            this.name = name;
            this.startTime = startTime;
        }
    }

    private class TrackedRunnable implements Runnable {
        private final Runnable actualTask;
        private final String name;

        TrackedRunnable(Runnable actualTask, String name) {
            this.actualTask = actualTask;
            this.name = name;
        }

        @Override
        public void run() {
            activeTasks.put(this, new TaskInfo(name, System.currentTimeMillis()));
            try {
                actualTask.run();
            } catch (Throwable t) {
                log.error("任务 [{}] 执行异常", name, t);
            } finally {
                activeTasks.remove(this);
            }
        }
    }
}