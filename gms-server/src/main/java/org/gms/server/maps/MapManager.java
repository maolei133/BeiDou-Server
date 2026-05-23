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

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.github.benmanes.caffeine.cache.RemovalCause;
import org.gms.scripting.event.EventInstanceManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.TimeUnit;

public class MapManager {
    private static final Logger log = LoggerFactory.getLogger(MapManager.class);

    private final int channel;
    private final int world;
    private EventInstanceManager event;

    // 缓存：地图加载后由 Caffeine 自动管理生命周期，根据 canDisposeMap() 条件动态过期
    private final Cache<Integer, MapleMap> cache;

    // 被脚本标记为常驻的地图 ID（不可被 auto-dispose）
    private final Set<Integer> pinnedMaps = new HashSet<>();

    // 累计已释放的地图数量（用于统计）
    private int disposedCount;
    // 当前估算内存（字节），约每张地图 200KB 基础开销
    private static final long ESTIMATED_MAP_OVERHEAD = 200 * 1024;

    public MapManager(EventInstanceManager eim, int world, int channel) {
        this.world = world;
        this.channel = channel;
        this.event = eim;
        this.disposedCount = 0;

        MapManager self = this;
        this.cache = Caffeine.newBuilder()
                .maximumSize(2_000)
                .expireAfter(new Expiry<Integer, MapleMap>() {
                    @Override
                    public long expireAfterCreate(Integer key, MapleMap value, long currentTime) {
                        return resolveExpiry(value);
                    }
                    @Override
                    public long expireAfterUpdate(Integer key, MapleMap value,long currentTime, long currentDuration) {
                        return resolveExpiry(value);
                    }
                    @Override
                    public long expireAfterRead(Integer key, MapleMap value,long currentTime, long currentDuration) {
                        return resolveExpiry(value);
                    }
                    private long resolveExpiry(MapleMap map) {
                        if (self.canDisposeMap(map)) {
                            return TimeUnit.SECONDS.toNanos(60);   // 60秒宽限期
                        }
                        return Long.MAX_VALUE;                      // 不满足条件：永不过期
                    }
                })
                .evictionListener((Integer key, MapleMap map, RemovalCause cause) -> {
                    if (map == null || !cause.wasEvicted()) return;

                    // ★ 二次确认：宽限期到了，重新检查条件
                    if (!self.canDisposeMap(map)) {
                        return;   // 条件不满足 → 跳过本次驱逐（map 对象被丢弃，下次 getMap 重建）
                    }

                    log.debug(" 世界 {} 频道 {} 释放空闲地图 [{}] {}", world, channel, key, map.getMapName());
                    map.dispose();
                    disposedCount++;
                })
                .build();
    }

    public MapleMap resetMap(int mapid) {
        cache.invalidate(mapid);
        return getMap(mapid);
    }

    public MapleMap getMap(int mapid) {
        return cache.get(mapid, id -> {
            MapleMap map = MapFactory.loadMapFromWz(id, world, channel, event);
            map.setMapManager(this);
            return map;
        });
    }

    /** 地图占用变化时，强制缓存刷新过期评估 */
    public void touchMap(int mapid) {
        MapleMap map = cache.getIfPresent(mapid);
        if (map != null) cache.put(mapid, map);   // 触发 expireAfterUpdate
    }

    public MapleMap getMapByLifeId(int lifeId) {
        String mapId = MapFactory.getMapIdByLifeId(lifeId);
        return mapId == null ? null : getMap(Integer.parseInt(mapId));
    }

    public MapleMap getDisposableMap(int mapid) {
        return MapFactory.loadMapFromWz(mapid, world, channel, event);
    }

    public boolean isMapLoaded(int mapId) {
        return cache.getIfPresent(mapId) != null;
    }

    public Map<Integer, MapleMap> getMaps() {
        return new HashMap<>(cache.asMap());
    }

    public void updateMaps() {
        for (MapleMap map : cache.asMap().values()) {
            map.respawn();
            map.mobMpRecovery();
        }
    }

    public void dispose() {
        cache.invalidateAll();
        this.event = null;
    }

    /**
     * 判断地图是否可以释放（自动回收）。
     * 全部条件满足时才进入 60 秒宽限期，到期后二次确认仍满足才释放。
     *
     * ① 地图对象非空
     * ② 未被脚本 pin 为常驻地图
     * ③ 无玩家在线 (getCharacterCount)
     * ④ 无雇佣商人 (hiredMerchantCount)
     * ⑤ 无地面掉落物品 (droppedItemCount)
     * ⑥ 无 BOSS 存活 (spawnedBossesOnMap)
     * ⑦ 无关联的事件实例 (EventInstance)
     * ⑧ 非活动地图 (EventMap, 按 ID 范围判定)
     * ⑨ WZ <clock> 属性为 false（地图固有钟表，非玩家倒计时包）
     * ⑩ 无待刷新的 BOSS (monsterSpawnBoss 队列非空)
     */
    private boolean canDisposeMap(MapleMap map) {
        if (map == null) return true;
        if (pinnedMaps.contains(map.getId())) return false;                                     // ②
        return map.getCharacterCount() == 0                                                     // ③
                && map.getHiredMerchantCount() == 0                                             // ④
                && map.getDroppedItemCount() <= 0                                               // ⑤
                && map.getSpawnedBossesOnMap() == 0                                             // ⑥
                && map.getEventInstance() == null                                               // ⑦
                && !map.isEventMap()                                                            // ⑧
                && !map.hasClock()                                                              // ⑨
                && !map.hasPendingBossSpawns();                                                 // ⑩
    }

    public void pinMap(int mapId) {
        pinnedMaps.add(mapId);
        // pin 后强制刷新过期评估（可能之前已有60秒倒计时）
        MapleMap existing = cache.getIfPresent(mapId);
        if (existing != null) cache.put(mapId, existing);
    }

    public void unpinMap(int mapId) {
        pinnedMaps.remove(mapId);
    }

    // ---- 统计接口 ----

    public int getMapCount() {
        return cache.asMap().size();
    }

    public long getEstimatedMemoryBytes() {
        return (long) getMapCount() * ESTIMATED_MAP_OVERHEAD;
    }

    public int getDisposedCount() {
        return disposedCount;
    }

    public int getWorld() {
        return world;
    }

    public int getChannel() {
        return channel;
    }
}