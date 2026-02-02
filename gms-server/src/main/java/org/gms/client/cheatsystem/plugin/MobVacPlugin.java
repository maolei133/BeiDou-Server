package org.gms.client.cheatsystem.plugin;

import lombok.Getter;
import lombok.Setter;
import org.gms.client.cheatsystem.core.BaseCheatPlugin;
import org.gms.client.Character;
import org.gms.client.Skill;
import org.gms.client.SkillFactory;
import org.gms.client.status.MonsterStatus;
import org.gms.client.status.MonsterStatusEffect;
import org.gms.config.GameConfig;
import org.gms.dao.entity.ExtendValueDO;
import org.gms.server.TimerManager;
import org.gms.server.life.Monster;
import org.gms.server.logging.AuditLogger;
import org.gms.server.logging.LogAction;
import org.gms.server.logging.LogModule;
import org.gms.server.maps.MapObject;
import org.gms.server.maps.MapObjectType;
import org.gms.server.maps.MapleMap;
import org.gms.util.PacketCreator;

import java.awt.*;
import java.util.List;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;

@Getter
@Setter
public class MobVacPlugin extends BaseCheatPlugin {
    
    /** 吸怪内置辅助功能总开关 */
    private boolean enable = true;
    /** 每天可用次数（内置辅助） */
    private int dailyLimit = 10;
    /** 每次使用时长（秒）（内置辅助） */
    private int duration = 30;
    /** 使用次数计数器（内置辅助） */
    private Map<Integer, Integer> usageCount = new HashMap<>();
    /** 当前正在使用的玩家列表（内置辅助） */
    private Set<Integer> activeUsers = new HashSet<>();
    /** 当前吸怪任务（内置辅助） */
    private ScheduledFuture<?> mobVacTask;
    /** 吸怪范围半径（内置辅助） */
    private double radius = Double.POSITIVE_INFINITY;
    /** 当前在使用吸怪内置辅助功能的地图实例 */
    private static final Map<MapleMap, Integer> activeMapInstances = new ConcurrentHashMap<>();
    /** 吸怪开始时间（内置辅助） */
    private long startTime;
    /** 吸怪内置辅助功能所在地图实例 */
    private MapleMap mobVacMap;
    /** 当前在使用吸怪内置辅助地图中的玩家列表 */
    private Set<Integer> playersInVacMap = new HashSet<>();
    /** 开启吸怪内置辅助功能的玩家名称 */
    private String mobVacPlayerName;
    /** 预创建的SPEED状态效果，避免重复创建（内置辅助） */
    private MonsterStatusEffect speedEffect;
    /** 数据库中存储的键名（内置辅助） */
    private static final String MOB_VAC_USAGE_COUNT_KEY = "每日吸怪累计次数";

    public MobVacPlugin() {
        super();
        initSpeedEffect();
    }
    
    @Override
    public String getName() {
        return "MobVac";
    }
    
    @Override
    public String getDescription() {
        return "吸怪功能";
    }
    
    @Override
    public void initialize(Character player) {
        super.initialize(player);
        loadConfig();
    }
    
    @Override
    public void updateConfig() {
        loadConfig();
    }
    
    /**
     * 初始化SPEED状态效果，避免重复创建对象
     */
    private void initSpeedEffect() {
        try {
            Map<MonsterStatus, Integer> stati = Collections.singletonMap(MonsterStatus.SPEED, -100);
            Skill skill = SkillFactory.getSkill(1001); // 使用基础技能
            speedEffect = new MonsterStatusEffect(stati, skill, null, false);
        } catch (Exception e) {
            // 系统初始化异常，记录为系统级错误
            AuditLogger.error(LogModule.SYSTEM, LogAction.ERROR, "初始化SPEED状态效果失败", e);
        }
    }
    
    private void loadConfig() {
        enable = GameConfig.getServerBoolean("cheat_mob_vac_switch", true);
        dailyLimit = GameConfig.getServerInt("cheat_mob_vac_daily_limit", 10);
        duration = GameConfig.getServerInt("cheat_mob_vac_duration", 30) * 60; // 转换为秒
        radius = GameConfig.getServerDouble("cheat_mob_vac_radius", -1.0) == -1.0 ? Double.POSITIVE_INFINITY : GameConfig.getServerDouble("cheat_mob_vac_radius", -1.0);
    }
    
    @Override
    protected void onStart() {
        super.onStart();
        // 检查是否有启动参数
        Map<String, Object> params = getStartParameters();
        if (params != null && !params.isEmpty()) {
            // 使用参数启动吸怪功能
            handleStartWithParameters(params);
        } else {
            // 使用默认配置启动吸怪功能
            startMobVac();
        }
    }
    
    /**
     * 处理带参数的启动
     * @param params 启动参数
     */
    private void handleStartWithParameters(Map<String, Object> params) {
        // 从参数中获取配置，覆盖默认配置
        Boolean enableOverride = (Boolean) params.get("enable");
        if (enableOverride != null) {
            this.enable = enableOverride;
        }
        
        Integer dailyLimitOverride = (Integer) params.get("dailyLimit");
        if (dailyLimitOverride != null) {
            this.dailyLimit = dailyLimitOverride;
        }
        
        Integer durationOverride = (Integer) params.get("duration");
        if (durationOverride != null) {
            this.duration = durationOverride;
        }
        
        Double radiusOverride = (Double) params.get("radius");
        if (radiusOverride != null) {
            this.radius = radiusOverride;
        }
        
        // 检查是否包含忽略启用检查的参数
        Boolean ignoreEnableCheck = (Boolean) params.get("ignoreEnableCheck");
        if (ignoreEnableCheck == null) {
            ignoreEnableCheck = false;
        }
        
        // 启动吸怪功能
        startMobVac(ignoreEnableCheck);
    }
    
    @Override
    protected void onStop() {
        super.onStop(); // 调用父类的onStop方法
        stopMobVac();
    }
    
    /**
     * 开始吸怪功能（默认不忽略检查条件）
     */
    public boolean startMobVac() {
        return startMobVac(false);
    }
    
    /**
     * 开始吸怪功能
     * @param ignoreEnableCheck 是否忽略启用检查
     */
    public boolean startMobVac(boolean ignoreEnableCheck) {
        updateConfig();//更新参数配置
        // 检查功能是否启用
        if (!ignoreEnableCheck && !enable) {
            if (player != null) {
                player.dropMessage(5, "吸怪功能未启用。");
            }
            logPluginActivation("失败 - 功能未启用");
            return false;
        }
        
        // 检查玩家是否在线
        if (player == null) {
            logPluginActivation("失败 - 玩家对象为空");
            return false;
        }
        
        if (!player.isLoggedInWorld()) {
            logPluginActivation("失败 - 玩家离线");
            return false;
        }
        
        // 检查玩家是否在商城中
        if (player.getCashShop().isOpened()) {
            logPluginActivation("失败 - 玩家在商城中");
            return false;
        }
        
        // 检查玩家是否切换了频道
        if (player.getClient() == null || 
            player.getMap() == null || 
            player.getClient().getChannel() != channel) {
            logPluginActivation("失败 - 玩家切换频道");
            return false;
        }
        
        int playerId = player.getId();
        
        // 从数据库中读取使用次数
        loadUsageCountFromDB();
        
        // 检查地图条件
        String mapConditionFailure = checkMapConditionsDetailed(ignoreEnableCheck);
        if (mapConditionFailure != null) {
            player.dropMessage(5, "当前地图无法使用吸怪功能：" + mapConditionFailure);
            logPluginActivation("失败 - 地图条件不满足: " + mapConditionFailure);
            return false;
        }
        
        // 检查使用次数
        int todayUsage = usageCount.getOrDefault(playerId, 0);
        if (dailyLimit > 0) {  // 仅在dailyLimit大于0时检查使用次数
            if (todayUsage >= dailyLimit) {
                player.dropMessage(6, "今日吸怪次数已用完，每日限制：" + dailyLimit + "次。");
                logPluginActivation("失败 - 使用次数已达上限(" + todayUsage + "/" + dailyLimit + ")");
                return false;
            }
        }
        
        // 检查是否已在使用中
        if (activeUsers.contains(playerId)) {
            player.dropMessage(5, "吸怪功能已在使用中。");
            logPluginActivation("失败 - 功能已在使用中");
            return false;
        }
        
        // 记录使用次数
        usageCount.put(playerId, todayUsage + 1);
        // 将使用次数保存到数据库
        saveUsageCountToDB();
        
        activeUsers.add(playerId);
        
        // 记录玩家当前位置
        Point playerPosition = player.getPosition();
        
        // 记录地图实例正在使用吸怪
        mobVacMap = player.getMap();
        // 使用原子操作检查并添加，避免竞态条件
        if (activeMapInstances.putIfAbsent(mobVacMap, playerId) != null) {
             player.dropMessage(5, "该地图已有其他玩家开启了吸怪功能。");
             logPluginActivation("失败 - 地图已被占用");
             return false;
        }
        mobVacPlayerName = player.getName(); // 记录开启吸怪的玩家名称
        
        // 将开启吸怪的玩家添加到地图玩家列表中
        playersInVacMap.add(playerId);
        
        // 记录开始时间
        startTime = System.currentTimeMillis();
        
        // 格式化持续时间
        String durationStr = formatDuration(duration);
        
        // 发送提示信息
        if (dailyLimit > 0) {  // 仅在有限制次数时显示剩余次数
            player.dropMessage(6, "吸怪功能已开启，持续时间：" + durationStr + "，今日剩余次数：" + (dailyLimit - usageCount.get(playerId)) + "次。");
        } else {
            player.dropMessage(6, "吸怪功能已开启，持续时间：" + durationStr + "。");
        }
        mobVacMap.broadcastMessage(PacketCreator.serverNotice(6, player.getName() + " 已开启吸怪功能。"));
        
        logPluginActivation("成功 - 吸怪功能已开启，持续时间：" + durationStr + (ignoreEnableCheck ? "（忽略启用检查）" : "") + "，今日使用次数：" + usageCount.get(playerId));
        
        // 启动倒计时
        startCountdown();
        
        // 启动定时任务保持怪物位置
        startMobVacTask(playerPosition);
        
        return true;
    }
    
    /**
     * 从数据库加载使用次数
     */
    private void loadUsageCountFromDB() {
        if (player != null) {
            try {
                int accountId = player.getAccountId();
                String extendType = "12"; // 账号扩展类型
                
                ExtendValueDO extendValueDO = getAccountExtendValue(accountId, extendType, MOB_VAC_USAGE_COUNT_KEY);
                if (extendValueDO != null && extendValueDO.getExtendValue() != null) {
                    try {
                        int count = Integer.parseInt(extendValueDO.getExtendValue());
                        usageCount.put(player.getId(), count);
                    } catch (NumberFormatException e) {
                        logPluginOperationAuto("解析吸怪使用次数失败，accountId: " + accountId + ", value: " + extendValueDO.getExtendValue());
                    }
                }
            } catch (Exception e) {
                logPluginOperationAuto("从数据库加载吸怪使用次数失败: " + e.getMessage());
            }
        }
    }
    
    /**
     * 将使用次数保存到数据库
     */
    private void saveUsageCountToDB() {
        if (player != null) {
            try {
                int playerId = player.getId();
                int count = usageCount.getOrDefault(playerId, 0);
                int accountId = player.getAccountId();
                String extendType = "12"; // 账号扩展类型，日清
                
                saveOrUpdateAccountExtendValue(accountId, extendType, MOB_VAC_USAGE_COUNT_KEY, String.valueOf(count));
            } catch (Exception e) {
                logPluginOperationAuto("保存吸怪使用次数到数据库失败: " + e.getMessage());
            }
        }
    }
    
    /**
     * 检查地图条件（详细版）
     * @return null表示条件满足，非null表示失败原因
     */
    private String checkMapConditionsDetailed() {
        return checkMapConditionsDetailed(false);
    }
    
    /**
     * 检查地图条件（详细版）
     * @param ignoreEnableCheck 是否忽略启用检查
     * @return null表示条件满足，非null表示失败原因
     */
    private String checkMapConditionsDetailed(boolean ignoreEnableCheck) {
        // 检查是否有其他玩家正在使用吸怪功能
        MapleMap map = player.getMap();
        Integer currentMapUser = activeMapInstances.get(map);
        if (currentMapUser != null && currentMapUser != player.getId()) {
            Character currentUser = map.getCharacterById(currentMapUser);
            String userName = currentUser != null ? currentUser.getName() : "未知玩家";
            return "已有玩家(" + userName + ")正在使用吸怪功能";
        }
        if (!ignoreEnableCheck) {
            // 检查地图是否有事件
            if (map.getEventInstance() != null) {
                return "地图存在事件";
            }

            // 检查地图是否有倒计时
            if (map.hasClock()) {
                return "地图存在倒计时";
            }

            if (map.getTimeLimit() > 0) {
                return "地图存在时间限制";
            }

            if (map.getTimeLeft() > 0) {
                return "地图剩余时间未结束";
            }

            // 检查地图是否有Boss
            if (map.countBosses() > 0) {
                return "地图存在Boss";
            }
        }
        return null; // 条件满足
    }
    
    /**
     * 检查地图条件
     */
    private boolean checkMapConditions() {
        return checkMapConditionsDetailed() == null;
    }
    
    /**
     * 启动倒计时
     */
    private void startCountdown() {
        TimerManager.getInstance().schedule(() -> {
            if (player != null && player.isLoggedInWorld()) {
                player.dropMessage(5, "吸怪功能剩余时间：10秒");
            }
        }, (duration - 10) * 1000L);
    }
    
    /**
     * 启动吸怪任务
     */
    private void startMobVacTask(Point centerPosition) {
        stopMobVacTask();
        
        final Point position = new Point(centerPosition);
        final int playerId = player.getId();

        // 给地图添加倒计时
        mobVacMap.broadcastMessage(PacketCreator.getClock(duration));
        
        mobVacTask = TimerManager.getInstance().register(() -> {
            try {
                // 检查玩家是否仍然在线且在同一地图
                if (player == null) {
                    stopMobVac("玩家对象为空", true);
                    return;
                }
                
                if (!player.isLoggedInWorld()) {
                    // 棺材递送员: 玩家离线
                    stopMobVac("玩家离线", true);
                    return;
                }
                
                // 检查玩家是否在商城中
                if (player.getCashShop().isOpened()) {
                    stopMobVac("玩家进入商城", true);
                    return;
                }
                
                // 检查玩家是否切换了频道
                if (player.getClient() == null || 
                    player.getMap() == null || 
                    player.getClient().getChannel() != channel) {
                    stopMobVac("玩家切换频道", true);
                    return;
                }
                
                if (!activeUsers.contains(playerId)) {
                    stopMobVac("玩家退出吸怪功能", true);
                    return;
                }
                
                // 检查地图中的玩家状态
                checkPlayersInMap();
                
                // 检查玩家是否离开了地图
                boolean playerInMap = false;
                for (Character chr : mobVacMap.getCharacters()) {
                    if (chr.getId() == playerId) {
                        playerInMap = true;
                        break;
                    }
                }

                if (!playerInMap) {
                    stopMobVac("玩家离开地图", true);
                    return;
                }
                
                // 获取地图中的所有怪物
                List<MapObject> monsters = mobVacMap.getMapObjectsInRange(position, radius, List.of(MapObjectType.MONSTER));
                
                // 将怪物保持在中心位置
                for (MapObject obj : monsters) {
                    Monster mob = (Monster) obj;
                    // 不处理Boss和已死亡的怪物
                    if (!mob.isBoss() && mob.isAlive()) {
                        // 检查怪物是否偏离中心位置，如果偏离则移回
                        if (!mob.getPosition().equals(position)) {
                            mob.resetMobPosition(position);
                            // 移除了Thread.sleep(5)调用，避免阻塞定时任务线程
                            
                            // 只有当怪物没有SPEED状态时才应用新的状态效果，避免频繁创建和应用重复的BUFF
                            if (!mob.isBuffed(MonsterStatus.SPEED)) {
                                try {
                                    // 使用预创建的状态效果对象，避免重复创建
                                    if (speedEffect != null) {
                                        // 应用SPEED为0的状态效果来停止怪物移动，但不影响攻击和技能释放
                                        mob.applyStatus(player, speedEffect, false, 24 * 60 * 1000);
                                    }
                                } catch (Exception e) {
                                    // 记录业务日志 - 辆倒直下的上下文不可用
                                    logPluginOperationAuto("应用怪物状态效果失败: " + e.getMessage());
                                }
                            }
                        }
                    }
                }
            } catch (Exception ex) {
                // 记录业务日志
                logPluginOperationAuto("吸怪功能执行异常: " + ex.getMessage());
                stopMobVac("发生异常: " + ex.getMessage(), true);
            }
        }, 1000, 1000); // 每1秒检查一次
        
        // 设置功能自动结束
        TimerManager.getInstance().schedule(() -> stopMobVac("吸怪功能时间结束", true), duration * 1000L);
    }
    
    /**
     * 检查地图中的玩家状态，处理玩家进入和离开事件
     */
    private void checkPlayersInMap() {
        // 获取当前在地图中的所有玩家
        Collection<Character> currentPlayers = mobVacMap.getCharacters();
        Set<Integer> currentPlayerIds = new HashSet<>();
        
        // 添加新进入地图的玩家到倒计时列表
        for (Character chr : currentPlayers) {
            int chrId = chr.getId();
            currentPlayerIds.add(chrId);
            
            // 如果玩家是新进入地图的，为其添加倒计时
            if (!playersInVacMap.contains(chrId)) {
                handlePlayerEnterMap(chr);
            }
        }
        
        // 移除已离开地图的玩家
        playersInVacMap.removeIf(playerId -> !currentPlayerIds.contains(playerId));
    }
    
    /**
     * 处理玩家进入地图的逻辑
     * @param player 进入地图的玩家
     */
    private void handlePlayerEnterMap(Character player) {
        // 提示该玩家当前地图上已经有人开启了吸怪功能
        if (mobVacPlayerName != null) {
            player.dropMessage(5, "玩家 " + mobVacPlayerName + " 已在此地图上开启了吸怪功能。");
        }
        
        // 计算剩余时间
        long elapsed = (System.currentTimeMillis() - startTime) / 1000;
        int remainingTime = duration - (int) elapsed;
        
        // 确保剩余时间大于0
        if (remainingTime > 0) {
            player.sendPacket(PacketCreator.getClock(remainingTime));
        }
        
        // 将玩家添加到缓存中
        playersInVacMap.add(player.getId());
    }
    
    /**
     * 停止吸怪任务的统一方法
     * @param reason 停止原因
     */
    private void stopMobVac(String reason) {
        stopMobVac(reason, false, null);
    }
    
    /**
     * 停止吸怪任务的统一方法
     * @param reason 停止原因
     * @param broadcast 是否广播给地图上的所有玩家
     */
    private void stopMobVac(String reason, boolean broadcast) {
        stopMobVac(reason, broadcast, null);
    }
    
    /**
     * 停止吸怪任务的统一方法
     * @param reason 停止原因
     * @param broadcast 是否广播给地图上的所有玩家
     * @param broadcastMessage 自定义广播内容，如果为null则使用默认内容
     */
    private void stopMobVac(String reason, boolean broadcast, String broadcastMessage) {
        if (mobVacMap != null) {
            // 安全移除地图实例标记
            Integer ownerId = activeMapInstances.get(mobVacMap);
            if (ownerId != null && player != null && ownerId == player.getId()) {
                activeMapInstances.remove(mobVacMap);
            } else if (player == null) {
                // 如果玩家离线，尝试移除该地图的标记
                activeMapInstances.remove(mobVacMap);
            }

            mobVacMap.killAllMonsters(); // 清除地图中的所有怪物
            mobVacMap.restoreMapSpawnPoints();  // 重置地图刷怪点
            mobVacMap.broadcastMessage(PacketCreator.removeClock());    // 移除地图倒计时
        }
        // 发送提示信息给开启吸怪功能的玩家
        if (player != null && player.isLoggedInWorld()) {
            player.dropMessage(6, "吸怪功能已停止，原因：" + reason);
        }

        // 广播给地图上的其他玩家
        if (broadcast && mobVacMap != null && mobVacPlayerName != null) {
            String message = broadcastMessage != null ? broadcastMessage : "玩家 " + mobVacPlayerName + " 的吸怪功能已停止，原因：" + reason;
            mobVacMap.broadcastMessage(player, PacketCreator.serverNotice(6, message), false);
        }
        // 清除所有缓存
        if (player != null) {
            activeUsers.remove(player.getId());
        }
        // activeMapInstances.remove(mobVacMap); // 已经在上面处理了
        playersInVacMap.clear();
        mobVacPlayerName = null;
        // 停止任务
        stopMobVacTask();
        
        logPluginDeactivation("原因：" + reason);
    }
    
    /**
     * 停止吸怪任务
     */
    private void stopMobVacTask() {
        if (mobVacTask != null) {
            mobVacTask.cancel(true);
            mobVacTask = null;
        }
    }
    
    /**
     * 停止吸怪功能
     */
    public void stopMobVac() {
        stopMobVac("玩家主动停止吸怪功能");
    }
    
    /**
     * 获取用户当日使用次数
     */
    public int getTodayUsageCount() {
        if (player == null) return 0;
        return usageCount.getOrDefault(player.getId(), 0);
    }
    
    /**
     * 重置每日计数器（通常在每日重置时调用）
     */
    public void resetDailyCounters() {
        usageCount.clear();
    }
    
    /**
     * 当玩家进入地图时调用，用于同步倒计时
     */
    public void onPlayerEnterMap(Character player) {
        if (player == null) return;
        
        MapleMap currentMap = player.getMap();
        Integer mobVacUserId = activeMapInstances.get(currentMap);
        
        // 检查当前地图是否正在使用吸怪功能
        if (mobVacUserId != null) {
            handlePlayerEnterMap(player);
        }
    }
    
    /**
     * 格式化持续时间显示
     * @param seconds 总秒数
     * @return 格式化后的时间字符串
     */
    private String formatDuration(int seconds) {
        int days = seconds / 86400;
        int hours = (seconds % 86400) / 3600;
        int minutes = (seconds % 3600) / 60;
        
        StringBuilder sb = new StringBuilder();
        if (days > 0) sb.append(days).append("天");
        if (hours > 0) sb.append(hours).append("小时");
        if (minutes > 0) sb.append(minutes).append("分钟");
        // 如果没有任何时间单位，显示0分钟
        if (sb.length() == 0) sb.append("0分钟");
        return sb.toString();
    }
    /**
     * 检查指定地图是否开启了吸怪功能
     * @param map 地图实例
     * @return true表示开启了，false表示未开启
     */
    public static boolean isMobVacActiveInMap(MapleMap map) {
        return activeMapInstances.containsKey(map);
    }
}