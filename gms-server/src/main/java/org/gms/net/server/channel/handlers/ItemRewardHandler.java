/*
	This file is part of the OdinMS Maple Story Server
    Copyright (C) 2008 Patrick Huy <patrick.huy@frz.cc>
		       Matthias Butz <matze@odinms.de>
		       Jan Christian Meyer <vimes@odinms.de>

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
package org.gms.net.server.channel.handlers;

import org.apache.commons.lang3.StringUtils;
import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.manipulator.InventoryManipulator;
import org.gms.constants.id.NpcId;
import org.gms.constants.inventory.ItemConstants;
import org.gms.constants.string.ExtendType;
import org.gms.dao.entity.ExtendValueDO;
import org.gms.net.AbstractPacketHandler;
import org.gms.net.packet.InPacket;
import org.gms.net.server.Server;
import org.gms.scripting.AbstractScriptManager;
import org.gms.scripting.npc.NPCScriptManager;
import org.gms.server.ItemInformationProvider;
import org.gms.server.ItemInformationProvider.RewardItem;
import org.gms.server.TimerManager;
import org.gms.server.maps.MapleMap;
import org.gms.util.ExtendUtil;
import org.gms.util.PacketCreator;
import org.gms.util.Pair;
import org.gms.util.Randomizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import java.awt.*;
import java.io.File;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public final class ItemRewardHandler extends AbstractPacketHandler {
    private static final Logger logger = LoggerFactory.getLogger(ItemRewardHandler.class);

    // 常量
    private static final long DAILY_MOB_VAC_LIMIT_MS = 1080L * 60 * 1000;
    private static final String SCRIPT_BASE_DIR = "./scripts-zh-CN/";
    private static final long HOT_RELOAD_INTERVAL_MS = 30000L;

    // 可配置间隔（通过Spring注入）
    private static long MOB_VAC_INTERVAL = 1000L;
    private static long ITEM_VAC_INTERVAL = 1000L;
    private static long BAG_INTERVAL = 30000L;

    // 脚本引擎缓存（路径 -> Invocable）以及最后修改时间记录
    private static final Map<String, Invocable> scriptCache = new ConcurrentHashMap<>();
    private static final Map<String, Long> scriptLastModified = new ConcurrentHashMap<>();
    private static final ReentrantReadWriteLock cacheLock = new ReentrantReadWriteLock();
    private static ScheduledFuture<?> hotReloadTask;

    // 玩家状态
    private static final Map<Integer, PlayerState> playerStates = new ConcurrentHashMap<>();

    static {
        logger.info("默认执行间隔: 吸怪={}ms, 吸物={}ms, 整理={}ms", MOB_VAC_INTERVAL, ITEM_VAC_INTERVAL, BAG_INTERVAL);
    }

    public static void setIntervals(long mob, long item, long bag) {
        MOB_VAC_INTERVAL = mob;
        ITEM_VAC_INTERVAL = item;
        BAG_INTERVAL = bag;
        logger.info("更新间隔: 吸怪={}ms, 吸物={}ms, 整理={}ms", mob, item, bag);
    }

    public static synchronized void init() {
        if (hotReloadTask == null) {
            hotReloadTask = TimerManager.getInstance().register(() -> {
                cacheLock.writeLock().lock();
                try {
                    for (String path : scriptCache.keySet()) {
                        File file = Paths.get(SCRIPT_BASE_DIR, path).toFile();
                        long currentModified = file.exists() ? file.lastModified() : 0;
                        Long oldModified = scriptLastModified.get(path);
                        if (oldModified != null && currentModified > oldModified) {
                            logger.info("检测到脚本变更: {}, 重新加载", path);
                            reloadScriptInternal(path);
                        }
                    }
                } finally {
                    cacheLock.writeLock().unlock();
                }
            }, HOT_RELOAD_INTERVAL_MS, HOT_RELOAD_INTERVAL_MS);
            logger.info("热加载已启动，间隔={}ms", HOT_RELOAD_INTERVAL_MS);
        }
    }

    private static void reloadScriptInternal(String path) {
        try {
            ScriptEngine engine = new SpecialScriptManager().getInvocableScriptEngine(path);
            if (engine instanceof Invocable) {
                scriptCache.put(path, (Invocable) engine);
                File file = Paths.get(SCRIPT_BASE_DIR, path).toFile();
                scriptLastModified.put(path, file.lastModified());
                logger.info("热加载脚本成功: {}", path);
            } else {
                logger.warn("脚本不可调用: {}", path);
            }
        } catch (Exception e) {
            logger.error("热加载失败: {}", path, e);
        }
    }

    private static Invocable getScriptEngine(String path) {
        cacheLock.readLock().lock();
        try {
            if (scriptCache.containsKey(path)) return scriptCache.get(path);
        } finally {
            cacheLock.readLock().unlock();
        }
        cacheLock.writeLock().lock();
        try {
            if (scriptCache.containsKey(path)) return scriptCache.get(path);
            File file = Paths.get(SCRIPT_BASE_DIR, path).toFile();
            if (!file.exists()) {
                logger.error("脚本不存在: {}", path);
                return null;
            }
            ScriptEngine engine = new SpecialScriptManager().getInvocableScriptEngine(path);
            if (!(engine instanceof Invocable)) return null;
            scriptCache.put(path, (Invocable) engine);
            scriptLastModified.put(path, file.lastModified());
            return (Invocable) engine;
        } catch (Exception e) {
            logger.error("加载脚本失败: {}", path, e);
            return null;
        } finally {
            cacheLock.writeLock().unlock();
        }
    }

    // ========== 玩家状态 ==========
    private static class PlayerState {
        ScheduledFuture<?> mobTask, itemTask, bagTask;
        Point savedPos;
        MapleMap savedMap;
        long sessionStart;
        long totalBefore;
    }

    private static PlayerState getState(Character player) {
        return playerStates.computeIfAbsent(player.getId(), k -> new PlayerState());
    }

    // ========== 主处理 ==========
    @Override
    public void handlePacket(InPacket p, Client c) {
        byte slot = (byte) p.readShort();
        int itemId = p.readInt();

        if (itemId == 2022552 || itemId == 2022615 || itemId == 2022336 || itemId == 2022468) {
            specialHandle(itemId, c);
            return;
        }

        // 普通奖励道具
        Item it = c.getPlayer().getInventory(InventoryType.USE).getItem(slot);
        if (it == null || it.getItemId() != itemId || c.getPlayer().getInventory(InventoryType.USE).countById(itemId) < 1)
            return;

        ItemInformationProvider ii = ItemInformationProvider.getInstance();
        Pair<Integer, List<RewardItem>> rewards = ii.getItemReward(itemId);
        for (RewardItem reward : rewards.getRight()) {
            if (!InventoryManipulator.checkSpace(c, reward.itemid, reward.quantity, "")) {
                c.sendPacket(PacketCreator.getShowInventoryFull());
                break;
            }
            if (Randomizer.nextInt(rewards.getLeft()) < reward.prob) {
                if (ItemConstants.getInventoryType(reward.itemid) == InventoryType.EQUIP) {
                    Item item = ii.getEquipById(reward.itemid);
                    if (reward.period != -1)
                        item.setExpiration(currentServerTime() + reward.period * 60 * 60 * 10);
                    InventoryManipulator.addFromDrop(c, item, false);
                } else {
                    InventoryManipulator.addById(c, reward.itemid, reward.quantity, "", -1);
                }
                InventoryManipulator.removeById(c, InventoryType.USE, itemId, 1, false, false);
                if (reward.worldmsg != null) {
                    String msg = reward.worldmsg.replaceAll("/name", c.getPlayer().getName())
                            .replaceAll("/item", ii.getName(reward.itemid));
                    Server.getInstance().broadcastMessage(c.getWorld(), PacketCreator.serverNotice(6, msg));
                }
                break;
            }
        }
        c.sendPacket(PacketCreator.enableActions());
    }

    private void specialHandle(int itemId, Client c) {
        Character player = c.getPlayer();
        PlayerState state = getState(player);

        switch (itemId) {
            case 2022552: // 快捷菜单
                NPCScriptManager.getInstance().start(c, NpcId.BEI_DOU_NPC_BASE, null);
                break;
            case 2022336: // 吸怪
                toggleMobVac(player, state);
                break;
            case 2022468: // 吸物
                toggleItemVac(player, state);
                break;
            case 2022615: // 背包整理
                toggleBagOrganize(player, state);
                break;
        }
        c.getAbstractPlayerInteraction().enableActions();
    }

    // ========== 吸怪 ==========
    private void toggleMobVac(Character player, PlayerState state) {
        if (state.mobTask != null) {
            state.mobTask.cancel(false);
            state.mobTask = null;
            if (state.sessionStart > 0) {
                long used = System.currentTimeMillis() - state.sessionStart;
                long total = state.totalBefore + used;
                saveTotalMobVacTime(player.getId(), total);
                player.dropMessage(0, String.format("本次吸怪 %d 分钟，累计 %d 分钟", used / 60000, total / 60000));
                state.sessionStart = 0;
                state.totalBefore = 0;
            }
            state.savedPos = null;
            state.savedMap = null;
            player.dropMessage(0, "[全屏吸怪]已关闭");
            return;
        }

        long usedBefore = getTotalMobVacTime(player.getId());
        if (usedBefore >= DAILY_MOB_VAC_LIMIT_MS) {
            player.dropMessage(1, "今日吸怪时长已用完（上限" + (DAILY_MOB_VAC_LIMIT_MS / 60000) + "分钟）");
            return;
        }
        state.totalBefore = usedBefore;
        state.sessionStart = System.currentTimeMillis();
        state.savedPos = player.getPosition();
        state.savedMap = player.getMap();

        String scriptPath = "BeiDouSpecial/_mobvac.js";
        state.mobTask = startPeriodicTask(player, scriptPath, MOB_VAC_INTERVAL, "吸怪", () -> {
            if (player.getMap().getId() != state.savedMap.getId() ||
                    player.getMap().getChannelServer().getId() != state.savedMap.getChannelServer().getId()) {
                state.savedMap.resetMapObjects();
                throw new RuntimeException("地图切换");
            }
            long elapsed = System.currentTimeMillis() - state.sessionStart;
            if (state.totalBefore + elapsed >= DAILY_MOB_VAC_LIMIT_MS) {
                player.dropMessage(0, "吸怪时间已用完，自动关闭");
                toggleMobVac(player, state); // 关闭自己
                return;
            }
            Invocable inv = getScriptEngine(scriptPath);
            if (inv != null) synchronized (inv) {
                inv.invokeFunction("start", player, ItemInformationProvider.getInstance(), state.savedPos);
            }
        });
        player.dropMessage(0, "[全屏吸怪]已开启，每" + (MOB_VAC_INTERVAL / 1000) + "秒执行");
    }

    // ========== 吸物 ==========
    private void toggleItemVac(Character player, PlayerState state) {
        if (state.itemTask != null) {
            state.itemTask.cancel(false);
            state.itemTask = null;
            player.dropMessage(0, "[全屏捡物]已关闭");
            return;
        }
        String scriptPath = "BeiDouSpecial/_itemvac.js";
        state.itemTask = startPeriodicTask(player, scriptPath, ITEM_VAC_INTERVAL, "吸物", () -> {
            Invocable inv = getScriptEngine(scriptPath);
            if (inv != null) synchronized (inv) {
                inv.invokeFunction("start", player, ItemInformationProvider.getInstance());
            }
        });
        player.dropMessage(0, "[全屏捡物]已开启");
    }

    // ========== 背包整理 ==========
    private void toggleBagOrganize(Character player, PlayerState state) {
        if (state.bagTask != null) {
            state.bagTask.cancel(false);
            state.bagTask = null;
            player.dropMessage(0, "[自动整理]已关闭");
            return;
        }
        String scriptPath = "BeiDouSpecial/_organize.js";
        state.bagTask = startPeriodicTask(player, scriptPath, BAG_INTERVAL, "整理", () -> {
            Invocable inv = getScriptEngine(scriptPath);
            if (inv != null) synchronized (inv) {
                inv.invokeFunction("start", player, ItemInformationProvider.getInstance());
            }
        });
        player.dropMessage(0, "[自动整理]已开启");
    }

    // ========== 通用定时任务 ==========
    @FunctionalInterface
    private interface TaskAction {
        void run() throws Exception;
    }

    private ScheduledFuture<?> startPeriodicTask(Character player, String scriptPath, long interval, String name, TaskAction action) {
        if (getScriptEngine(scriptPath) == null) {
            logger.error("无法加载脚本: {}", scriptPath);
            player.dropMessage(0, "[" + name + "]功能加载失败");
            return null;
        }
        return TimerManager.getInstance().register(() -> {
            try {
                if (!player.isLoggedIn() || player.getMap() == null)
                    throw new RuntimeException("离线或无地图");
                action.run();
            } catch (Exception e) {
                logger.error("{}任务异常: {}", name, e.getMessage());
                // 自动清理该玩家的对应任务
                PlayerState ps = playerStates.get(player.getId());
                if (ps != null) {
                    if (name.contains("吸怪") && ps.mobTask != null) ps.mobTask.cancel(false);
                    if (name.contains("吸物") && ps.itemTask != null) ps.itemTask.cancel(false);
                    if (name.contains("整理") && ps.bagTask != null) ps.bagTask.cancel(false);
                }
            }
        }, interval);
    }

    // ========== 数据库操作 ==========
    private long getTotalMobVacTime(int playerId) {
        ExtendValueDO do_ = ExtendUtil.getExtendValue(String.valueOf(playerId), ExtendType.CHARACTER_EXTEND_DAILY.getType(), "mobvacLimit");
        String val = do_ == null ? null : do_.getExtendValue();
        return StringUtils.isBlank(val) ? 0L : Long.parseLong(val);
    }

    private void saveTotalMobVacTime(int playerId, long total) {
        ExtendUtil.saveOrUpdateExtendValue(String.valueOf(playerId), ExtendType.CHARACTER_EXTEND_DAILY.getType(), "mobvacLimit", String.valueOf(total));
    }

    // ========== 辅助 ==========
    private static class SpecialScriptManager extends AbstractScriptManager {
        @Override
        public ScriptEngine getInvocableScriptEngine(String path) {
            return super.getInvocableScriptEngine(path);
        }
    }

    public static void onPlayerLogout(int playerId) {
        PlayerState state = playerStates.remove(playerId);
        if (state != null) {
            if (state.mobTask != null) state.mobTask.cancel(false);
            if (state.itemTask != null) state.itemTask.cancel(false);
            if (state.bagTask != null) state.bagTask.cancel(false);
        }
    }
}