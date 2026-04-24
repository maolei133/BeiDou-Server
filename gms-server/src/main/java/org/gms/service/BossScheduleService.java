package org.gms.service;

import com.mybatisflex.core.query.QueryWrapper;
import org.gms.dao.entity.BossScheduleDO;
import org.gms.dao.mapper.BossScheduleMapper;
import org.gms.manager.ServerManager;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.gms.dao.entity.table.BossScheduleDOTableDef.BOSS_SCHEDULE_DO;

@Service
public class BossScheduleService {

    private final BossScheduleMapper bossScheduleMapper;

    // Cache: WorldId -> ChannelId -> MapId -> List<BossScheduleDO>
    private final Map<Integer, Map<Integer, Map<Integer, List<BossScheduleDO>>>> scheduleCache = new HashMap<>();
    private final Map<Integer, BossScheduleDO> idIndex = new HashMap<>(); // 辅助索引：id -> schedule

    public BossScheduleService(BossScheduleMapper bossScheduleMapper) {
        this.bossScheduleMapper = bossScheduleMapper;
    }

    public static BossScheduleService getInstance() {
        return ServerManager.getApplicationContext().getBean(BossScheduleService.class);
    }

    /**
     * 加载所有 boss 刷新计划
     */
    public synchronized void loadAllSchedules() {
        List<BossScheduleDO> allSchedules = bossScheduleMapper.selectListByQuery(QueryWrapper.create());
        scheduleCache.clear();
        idIndex.clear();
        if (allSchedules != null) {
            for (BossScheduleDO schedule : allSchedules) {
                scheduleCache
                    .computeIfAbsent(schedule.getWorld(), k -> new HashMap<>())
                    .computeIfAbsent(schedule.getChannel(), k -> new HashMap<>())
                    .computeIfAbsent(schedule.getMap(), k -> new ArrayList<>())
                    .add(schedule);
                // 添加ID索引，便于快速查找和更新
                idIndex.put(schedule.getId(), schedule);
            }
        }
    }

    /**
     * 获取地图的 boss 刷新计划
     * @param world 世界id
     * @param channel 频道id
     * @param mapId 地图id
     * @return boss 刷新计划列表
     */
    public List<BossScheduleDO> getSchedulesForMap(int world, int channel, int mapId) {
        if (scheduleCache.isEmpty()) {
            loadAllSchedules();
        }
        Map<Integer, Map<Integer, List<BossScheduleDO>>> worldMap = scheduleCache.get(world);
        if (worldMap != null) {
            Map<Integer, List<BossScheduleDO>> channelMap = worldMap.get(channel);
            if (channelMap != null) {
                List<BossScheduleDO> schedules = channelMap.get(mapId);
                // 返回副本以防止外部修改
                return schedules != null ? new ArrayList<>(schedules) : null;
            }
        }
        return null;
    }

    /**
     * 更新怪物下次刷新时间记录
     * @param id 记录 id
     * @param nextSpawnTimestamp 下次刷新时间戳
     */
    public synchronized void updateNextSpawnTime(int id, long nextSpawnTimestamp) {
        BossScheduleDO schedule = idIndex.get(id);
        if (schedule != null) {
            schedule.setNextSpawnTime(nextSpawnTimestamp);
            bossScheduleMapper.update(schedule);
        } else {
            // 如果缓存没有，直接操作数据库
            BossScheduleDO dbSchedule = bossScheduleMapper.selectOneById(id);
            if (dbSchedule != null) {
                dbSchedule.setNextSpawnTime(nextSpawnTimestamp);
                bossScheduleMapper.update(dbSchedule);
            }
        }
    }
    
    /**
     * 新增怪物下次刷新时间记录
     * @param world 世界id
     * @param channel 频道id
     * @param mapId 地图id
     * @param mobId 怪物id
     * @param nextSpawnTimestamp 下次刷新时间戳
     * [修改] 查找或创建怪物的刷新计划，并返回其ID。
     * 这个方法取代了原来的 addNextSpawnTime，从根本上防止重复记录。
     * @return 现有或新创建的记录的ID。
     */
    public synchronized int findOrCreateSchedule(int world, int channel, int mapId, int mobId, long nextSpawnTimestamp) {
        // 1. 首先在缓存中查找
        List<BossScheduleDO> mapSchedules = scheduleCache
                .computeIfAbsent(world, k -> new HashMap<>())
                .computeIfAbsent(channel, k -> new HashMap<>())
                .computeIfAbsent(mapId, k -> new ArrayList<>());

        Optional<BossScheduleDO> existing = mapSchedules.stream()
                .filter(s -> s.getMob() == mobId)
                .findFirst();

        if (existing.isPresent()) {
            // 2. 如果在缓存中找到，直接返回其ID
            return existing.get().getId();
        }

        // 3. 如果缓存中没有，再查询一次数据库以确保万无一失（可能其他线程刚插入）
        QueryWrapper qw = QueryWrapper.create()
                .where(BOSS_SCHEDULE_DO.WORLD.eq(world))
                .and(BOSS_SCHEDULE_DO.CHANNEL.eq(channel))
                .and(BOSS_SCHEDULE_DO.MAP.eq(mapId))
                .and(BOSS_SCHEDULE_DO.MOB.eq(mobId));
        BossScheduleDO dbSchedule = bossScheduleMapper.selectOneByQuery(qw);

        if (dbSchedule != null) {
            // 数据库中存在，但缓存没有，说明缓存可能不是最新的。更新缓存并返回ID。
            mapSchedules.add(dbSchedule);
            idIndex.put(dbSchedule.getId(), dbSchedule);
            return dbSchedule.getId();
        }

        // 4. 缓存和数据库中都没有，创建新记录
        BossScheduleDO newSchedule = BossScheduleDO.builder()
                .world(world)
                .channel(channel)
                .map(mapId)
                .mob(mobId)
                .nextSpawnTime(nextSpawnTimestamp)
                .build();
        bossScheduleMapper.insert(newSchedule); // mybatis-flex 会自动将生成的主键ID回填到 newSchedule 对象中

        // 5. 将新记录添加到缓存
        mapSchedules.add(newSchedule);
        idIndex.put(newSchedule.getId(), newSchedule);

        return newSchedule.getId();
    }
}
