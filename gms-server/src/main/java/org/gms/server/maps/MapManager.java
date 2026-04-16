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
package org.gms.server.maps;

import org.gms.config.GameConfig;
import org.gms.scripting.event.EventInstanceManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class MapManager {
    private static final Logger log = LoggerFactory.getLogger(MapManager.class);
    private final int channel;
    private final int world;
    private EventInstanceManager event;

    private final Map<Integer, MapleMap> maps;
    private final Queue<MapleMap> inactiveMaps = new ConcurrentLinkedQueue<>();

    private final Lock mapsRLock;
    private final Lock mapsWLock;
    private final ScheduledExecutorService mapDisposalScheduler;

    public MapManager(EventInstanceManager eim, int world, int channel) {
        this.world = world;
        this.channel = channel;
        this.event = eim;

        final int mapLimit = GameConfig.getServerInt("map_limit", 200);

        this.maps = new LinkedHashMap<>(mapLimit, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<Integer, MapleMap> eldest) {
                if (size() > mapLimit) {
                    MapleMap map = eldest.getValue();
                    if (canDisposeMap(map)) {
                        log.info("频道 {} 的地图数量超过上限({})，释放最久未使用的空闲地图 实例: {}", channel, mapLimit, map.getId());
                        map.dispose();
                        removeFromInactiveMaps(map);
                        return true;
                    }
                }
                return false;
            }
        };

        ReadWriteLock readWriteLock = new ReentrantReadWriteLock();
        this.mapsRLock = readWriteLock.readLock();
        this.mapsWLock = readWriteLock.writeLock();

        mapDisposalScheduler = Executors.newSingleThreadScheduledExecutor();
        /** 定时释放空闲地图 */
        mapDisposalScheduler.scheduleAtFixedRate(() -> this.disposeInactiveMaps(1), 1, 1, TimeUnit.MINUTES);
    }

    /**
     * 将地图添加到待清理队列
     * @param map 地图实例
     */
    public void addToInactiveMaps(MapleMap map) {
        if (!inactiveMaps.contains(map)) {
            inactiveMaps.add(map);
        }
    }

    /**
     * 从待清理队列中移除地图
     * @param map 地图实例
     */
    public void removeFromInactiveMaps(MapleMap map) {
        inactiveMaps.remove(map);
    }

    /**
     * 判断地图是否满足添加到待清理队列的条件
     * @param map 地图实例
     * @return 是否满足添加到待清理队列的条件
     */
    public boolean canAddDisposeMap(MapleMap map) {
        return map.getCharacterCount() == 0 &&  // 没有角色
                !map.hasHiredMerchants(); // 没有雇佣商店

    }
    /**
     * 判断地图是否满足释放条件
     */
    private boolean canDisposeMap(MapleMap map) {
        return map == null ||   // 地图不存在，直接释放
                map.getCharacterCount() == 0 &&  // 没有角色
                !map.hasHiredMerchants() && // 没有雇佣商店
                map.getDroppedItemCount() <= 0 && // 没有掉落物
                map.countBosses() == 0 && // 没有boss存活
                map.getEventInstance() == null && // 不属于某个副本事件实例
                !map.isEventMap() && // 不是活动地图
                !map.hasClock() && // 没有任何时钟倒计时
                !map.hasPendingBossSpawns(); // 没有BOSS刷怪点
    }

    /**
     * 释放地图
     * @param interval 地图空闲时长（分钟），默认1分钟。
     */
    private void disposeInactiveMaps(int interval) {
        if (interval <= 0) interval = 1;

        // 记录清理前的内存
        System.gc();
        long memoryBefore = (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1024 / 1024;

        long currentTime = System.currentTimeMillis();
        int disposedCount = 0;

        Iterator<MapleMap> iterator = inactiveMaps.iterator();
        while (iterator.hasNext()) {
            MapleMap map = iterator.next();

            // 如果有玩家进入，则从待清理队列中移除
            if (map.getCharacterCount() > 0) {
                iterator.remove();
                continue;
            }

            if (canDisposeMap(map) && map.getLastChrLeftTime() > 0 && (currentTime - map.getLastChrLeftTime()) > TimeUnit.MINUTES.toMillis(interval)) {
                // 在写锁内从主地图集合中移除
                mapsWLock.lock();
                try {
                    // 再次检查以确保可以安全移除
                    if (maps.get(map.getId()) == map && canDisposeMap(map)) {
                        maps.remove(map.getId());
                        map.dispose();
                        iterator.remove(); // 从待清理队列中移除
                        disposedCount++;
                    } else {
                        // 地图已被移除或有玩家进入
                        iterator.remove();
                    }
                } finally {
                    mapsWLock.unlock();
                }
            }
        }

        if (disposedCount > 0) {
            // 记录清理后的内存
            System.gc();
            long memoryAfter = (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1024 / 1024;
            long memoryFreed = memoryBefore - memoryAfter;

            log.info("清理频道 {} 的空闲地图实例，共释放了 {} 张地图。 内存占用：清理前 {} MB，清理后 {} MB，释放了 {} MB。", channel, disposedCount,memoryBefore, memoryAfter, memoryFreed);
        }
    }

    public MapleMap resetMap(int mapid) {
        mapsWLock.lock();
        try {
            MapleMap oldMap = maps.remove(mapid);
            if (oldMap != null) {
                removeFromInactiveMaps(oldMap);
            }
        } finally {
            mapsWLock.unlock();
        }

        return getMap(mapid);
    }

    private synchronized MapleMap loadMapFromWz(int mapid, boolean cache) {
        MapleMap map;

        if (cache) {
            mapsWLock.lock();
            try {
                map = maps.get(mapid);
                if (map != null) {
                    return map;
                }
            } finally {
                mapsWLock.unlock();
            }
        }

        map = MapFactory.loadMapFromWz(mapid, world, channel, event);

        if (cache) {
            mapsWLock.lock();
            try {
                maps.put(mapid, map);
            } finally {
                mapsWLock.unlock();
            }
        }

        return map;
    }

    public MapleMap getMap(int mapid) {
        MapleMap map;

        mapsWLock.lock();
        try {
            // 需要写锁来更新 LinkedHashMap 的访问顺序
            map = maps.get(mapid);
        } finally {
            mapsWLock.unlock();
        }

        return (map != null) ? map : loadMapFromWz(mapid, true);
    }

    public MapleMap getMapByLifeId(int lifeId) {
        String mapId = MapFactory.getMapIdByLifeId(lifeId);
        return mapId == null ? null : getMap(Integer.parseInt(mapId));
    }

    public MapleMap getDisposableMap(int mapid) {
        return loadMapFromWz(mapid, false);
    }

    public boolean isMapLoaded(int mapId) {
        mapsRLock.lock();
        try {
            return maps.containsKey(mapId);
        } finally {
            mapsRLock.unlock();
        }
    }

    public Map<Integer, MapleMap> getMaps() {
        mapsRLock.lock();
        try {
            return new HashMap<>(maps);
        } finally {
            mapsRLock.unlock();
        }
    }

    public void updateMaps() {
        for (MapleMap map : getMaps().values()) {
            map.respawn();
            map.mobMpRecovery();
        }
    }

    public void dispose() {
        mapDisposalScheduler.shutdown();
        for (MapleMap map : getMaps().values()) {
            map.dispose();
        }
        inactiveMaps.clear();
        this.event = null;
    }

}
