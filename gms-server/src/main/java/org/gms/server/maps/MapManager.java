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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
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
                .maximumSize(5_000)
                .expireAfter(new Expiry<Integer, MapleMap>() {
                    @Override
                    public long expireAfterCreate(Integer key, MapleMap value, long currentTime) {
                        return resolveExpiry(value);
                    }

                    @Override
                    public long expireAfterUpdate(Integer key, MapleMap value,
                                                  long currentTime, long currentDuration) {
                        return resolveExpiry(value);
                    }

                    @Override
                    public long expireAfterRead(Integer key, MapleMap value,
                                                long currentTime, long currentDuration) {
                        return resolveExpiry(value);
                    }

                    private long resolveExpiry(MapleMap map) {
                        if (self.canDisposeMap(map)) {
                            return TimeUnit.SECONDS.toNanos(60);
                        }
                        return Long.MAX_VALUE;
                    }
                })
                .evictionListener((Integer key, MapleMap map, RemovalCause cause) -> {
                    if (map != null && cause.wasEvicted()) {
                        log.debug("释放空闲地图 [{}] {} 世界{}频道{}", key, map.getMapName(), world, channel);
                        map.dispose();
                        disposedCount++;
                    }
                })
                .build();
    }

    public MapleMap resetMap(int mapid) {
        cache.invalidate(mapid);
        return getMap(mapid);
    }

    public MapleMap getMap(int mapid) {
        return cache.get(mapid, id -> MapFactory.loadMapFromWz(id, world, channel, event));
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

    public boolean canAddDisposeMap(MapleMap map) {
        return map.getCharacterCount() == 0
                && !map.hasHiredMerchants();
    }

    private boolean canDisposeMap(MapleMap map) {
        if (map == null) return true;
        if (pinnedMaps.contains(map.getId())) return false;
        return map.getCharacterCount() == 0
                && !map.hasHiredMerchants()
                && map.getDroppedItemCount() <= 0
                && map.countBosses() == 0
                && map.getEventInstance() == null
                && !map.isEventMap()
                && !map.hasClock()
                && !map.hasPendingBossSpawns();
    }

    public void pinMap(int mapId) {
        pinnedMaps.add(mapId);
        // 强制触发 expireAfterUpdate 重新评估过期时间（防止 pin 前已设 60 秒倒计时）
        MapleMap existing = cache.getIfPresent(mapId);
        if (existing != null) {
            cache.put(mapId, existing);
        }
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