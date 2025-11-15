package org.gms.cheat.plugin;

import lombok.Getter;
import lombok.Setter;
import org.gms.cheat.core.BaseCheatPlugin;
import org.gms.client.Character;
import org.gms.client.inventory.Pet;
import org.gms.config.GameConfig;
import org.gms.server.TimerManager;
import org.gms.server.maps.MapItem;
import org.gms.server.maps.MapObject;
import org.gms.server.maps.MapObjectType;

import java.awt.*;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ScheduledFuture;


@Getter
@Setter
public class ItemVacPlugin extends BaseCheatPlugin {
    /** 宠吸功能总开关 */
    private boolean enable = true;
    /** 是否允许在事件地图中使用宠吸功能，false=当检测到事件地图出现BOSS则关闭宠吸 */
    private boolean allowInEvent = false;
    /** 是否在界面上展示参数提示信息 */
    private boolean showParams = true;
    /** 最大拾取半径限制 */
    private double maxRadius = 15000;
    /** 当前拾取半径，默认无穷大表示无限制 */
    private double radius = Double.POSITIVE_INFINITY;
    /** 上一次执行拾取操作的时间戳 */
    private long pickupTime = currentServerTime();
    /** 拾取状态标志，true表示正在拾取中，避免重复操作 */
    private boolean pickuping = false;
    /** 最小拾取间隔时间（毫秒） */
    private int minInterval = 200;
    /** 最大拾取间隔时间（毫秒） */
    private int maxInterval = 5 * 1000;
    /** 是否自动计算拾取范围和间隔 */
    private boolean autoCalc = true;
    /** 当前使用的拾取间隔时间（毫秒） */
    private int sleep = maxInterval;
    /** 宠吸功能支持的最高宠物等级 */
    private int maxLevel = 20;
    /** 击杀BOSS时间 */
    private long killBossTime = -1;
    
    private ScheduledFuture<?> itemVacTask;
    
    public ItemVacPlugin() {
        super();
    }
    
    @Override
    public String getName() {
        return "ItemVac";
    }
    
    @Override
    public String getDescription() {
        return "物品自动拾取功能";
    }
    
    @Override
    public void initialize(Character player) {
        super.initialize(player);
    }
    
    @Override
    public void updateConfig() {
        // 读取配置参数（集中管理）
        loadCommonConfig();
        
        // ==== 控制逻辑 ====
        if (!enable) {
            resetValues();
        }
    }
    
    /**
     * 更新配置并返回是否启用状态
     * @return 是否启用
     */
    public boolean updateConfigAndCheck() {
        updateConfig();
        return enable;
    }
    
    public boolean updatePetVacParam() {
        // 读取配置参数（集中管理）
        loadCommonConfig();

        // ==== 控制逻辑 ====
        if (!enable) {
            resetValues();
            return false;
        }

        // ==== 控制逻辑 ====
        if (player == null || !player.isLoggedInWorld()) {
            resetValues();
            return false;
        }

        // ==== 自动计算开关处理 ====
        if (!autoCalc) {
            setMaxValues();
            return true;
        }

        // ==== 宠物状态检查 ====
        Pet pet = getValidPet();
        if (pet == null) {
            resetValues();
            return false;
        }

        // ==== 核心公式计算 ====
        calculateParams(pet);
        return true;
    }
    
    /**
     * 检查是否应该执行物品拾取
     * @return 是否应该拾取
     */
    private boolean shouldPickupItems() {
        return !(pickuping || radius <= 0 || currentServerTime() - pickupTime < sleep || player == null || !player.isLoggedInWorld());
    }

    private void calculateParams(Pet pet) {
        // 参数预处理（保持原有缩放逻辑）
        double scaledMaxRadius = maxRadius * ((maxRadius <= 1000) ? 100 : (maxRadius <= 10000) ? 10 : 1);

        final int petLevel = Math.min(pet.getLevel(), maxLevel);
        final double levelProgress = petLevel / (double) maxLevel;
        final double fullness = pet.getFullness() / 100.0;  //饱食度百分比
        final int tameness = pet.getTameness(); //亲密度

        // ==== 修正关键系数 ====
        // 半径系数：0.6 → 1.4（饱食度越高越大）
        // 间隔系数：0.6 → 1.4（饱食度越高越大）

        // ==== 半径计算（保持不变） ====
        double baseRadius = scaledMaxRadius * levelProgress;
        this.radius = Math.min(baseRadius, scaledMaxRadius) * fullness;

        // ==== 间隔计算（修正逻辑） ====
        // 饱食度越高 → intervalFactor越大 → 减少量越多 → 最终间隔越小
        double intervalReduction = Math.max(maxInterval - (tameness * fullness), minInterval); // 使用修正后的系数
        this.sleep = (int) Math.max(minInterval, intervalReduction);
    }

    /**
     * 加载通用配置参数
     */
    private void loadCommonConfig() {
        enable = GameConfig.getServerBoolean("cheat_pet_itemvac_switch");
        allowInEvent = GameConfig.getServerBoolean("cheat_pet_itemvac_allow_in_event");
        showParams = GameConfig.getServerBoolean("cheat_pet_itemvac_show_params");
        maxLevel = GameConfig.getServerInt("cheat_pet_itemvac_max_level");
        maxRadius = GameConfig.getServerDouble("cheat_pet_itemvac_radius_max");
        minInterval = Math.max(GameConfig.getServerInt("cheat_pet_itemvac_sleep_min"), 200);
        maxInterval = GameConfig.getServerInt("cheat_pet_itemvac_sleep_max");
        autoCalc = GameConfig.getServerBoolean("cheat_pet_itemvac_radius_auto");
    }

    // ==== 辅助方法 ====
    private Pet getValidPet() {
        Pet pet = player.getPet(0);
        return (pet != null && pet.getLevel() > 0) ? pet : null;
    }

    private void resetValues() {
        this.radius = 0;
        this.sleep = 0;
    }

    private void setMaxValues() {
        this.radius = maxRadius;
        this.sleep = maxInterval;
    }

    /**
     * 人物范围吸物
     */
    public void pickupItem() {
        pickupItem((byte) -1);
    }

    public void pickupItem(byte petIndex, boolean update) {
        if (update) {
            updatePetVacParam();
        }
        pickupItem(petIndex);
    }
    
    /**
     * 检查玩家姿态是否允许拾取物品
     * @param stance 玩家姿态
     * @return 是否允许拾取
     */
    private boolean isStanceAllowPickup(int stance) {
        // 14~17 = 上下爬绳子、梯子；20 = 坐下
        return !((stance >= 14 && stance <= 17) || stance == 20);
    }
    
    /**
     * 范围吸物
     *
     * @param petIndex -1:玩家，0~3: 携带的宠物
     */
    public void pickupItem(byte petIndex) {
        // 检查角色是否为空，是否在线，是否拾取中，拾取范围是否小于0，拾取冷却时间(防止频繁调用)
        if (!shouldPickupItems()) return;
        Point Pos = null;
        if (petIndex >= 0) {
            Pet pet = player.getPet(petIndex);
            if (pet != null) Pos = pet.getPos();   //指定索引的宠物存在则使用该宠物的坐标
        } else {
            Pos = player.getPosition();   //获取玩家坐标
            petIndex = -1;
        }
        pickupItem(Pos, radius, sleep, petIndex);
    }

    public void pickupItem(Point Pos, double radius, int sleep, byte petIndex) {
        // 检查角色是否为空，是否在线，是否拾取中，拾取范围是否小于0，拾取冷却时间(防止频繁调用)
        if (player == null || Pos == null || !player.isLoggedInWorld() || pickuping || radius <= 0 || currentServerTime() - pickupTime < sleep) {
            if (player != null && player.isLoggedInWorld()) player.enableActions();
            return;
        }
        
        int stance = player.getStance();    //获取角色姿态，14~17 = 上下爬绳子、梯子；20 = 坐下
        if (!isStanceAllowPickup(stance)) {//爬绳和坐下不拾取
            return;
        }
        
        // 检测条件并记录时间
        updateKillBossTime();
        
        // 如果在限制时间内，不进行捡取操作
        if (killBossTime != -1 && currentServerTime() - killBossTime < 30000) { 
            return;
        }

        pickuping = true;

        List<MapObject> items = player.getMap().getMapObjectsInRange(
                Pos,    //基点坐标
                radius, //拾取半径
                Collections.singletonList(MapObjectType.ITEM) // 优化为单例列表
        );

        // 预计算玩家ID和过滤列表(减少循环内重复调用)
        Set<Integer> excludedItems = player.getExcludedItems();         //获取过滤列表
        boolean hasExclusions = !excludedItems.isEmpty();               //过滤列表不为空
        boolean ignoreItems = player.isEquippedPetItemIgnore();         //检查是否启用道具过滤
        boolean isEquippedMesoMagnet = player.isEquippedMesoMagnet();   //装备了宠物磁铁
        boolean isEquippedItemPouch = player.isEquippedItemPouch();     //装备了宠物捡取袋
        boolean isEquippedPetItemScales = player.isEquippedPetItemScales();     //装备了魔法天平

        // 遍历所有可拾取物品
        for (MapObject item : items) {
            try {
                if (!player.isLoggedInWorld()) return;  //不在线直接返回
                MapItem mapItem = (MapItem) item;
                boolean shouldPickup = true;

                // 检查是否为玩家自己丢弃的物品(不拾取)
                if (mapItem.isPlayerDrop()) { //玩家丢弃的一概不拾取
                    shouldPickup = false;
                } else if (petIndex >= 0 && player.getPet(petIndex) != null) {//如果是宠物并且已召唤
                    //判断是否装备了特定宠物装备和是否在过滤列表里
                    if (mapItem.getMeso() > 0) {
                        shouldPickup = isEquippedMesoMagnet &&  (!ignoreItems || !hasExclusions || !excludedItems.contains(Integer.MAX_VALUE));
                    } else {
                        shouldPickup = isEquippedItemPouch && (!ignoreItems || !hasExclusions || !excludedItems.contains(mapItem.getItemId()));
                    }
                }
                
                if (shouldPickup && player.isLoggedInWorld()) { //再次判定角色是否在线
                    //如果拥有拾取权 或者 装备了魔法天平 并且掉落时间超过1000ms，避免未落地先拾取
                    if ((mapItem.canBePickedBy(player) || isEquippedPetItemScales) && currentServerTime() - mapItem.getDropTime() > 1000) { 
                        player.pickupItem(item, petIndex, false);  //执行拾取
                    }
                }
            } catch (NullPointerException | ClassCastException ignored) {}
        }
        pickuping = false;
        pickupTime = currentServerTime();
    }
    
    @Override
    protected void onStart() {
        // 启动定时任务
        startItemVacTask();
    }
    
    @Override
    protected void onStop() {
        // 停止定时任务
        stopItemVacTask();
    }
    
    private void startItemVacTask() {
        stopItemVacTask(); // 确保之前的任务已停止
        
        if (!updatePetVacParam() || !isEnable()) {
            return;
        }
        
        int delay = getSleep();
        if (delay <= 0) {
            return;
        }
        
        itemVacTask = TimerManager.getInstance().register(() -> {
            try {
                // 条件检查
                if (!player.isLoggedInWorld() || player.getPet(0) == null || !updateConfigAndCheck() || !isEnable()) {
                    stop();
                    return;
                }

                // 执行吸物操作
                pickupItem((byte) 0);

                // 检查间隔变化
                int currentDelay = getSleep();
                if (currentDelay != delay) {
                    // 重新启动任务以使用新间隔
                    startItemVacTask();
                }
            } catch (Exception ex) {
                stop();
            }
        }, delay, 1000);
    }
    
    private void stopItemVacTask() {
        if (itemVacTask != null) {
            itemVacTask.cancel(true);
            itemVacTask = null;
        }
    }
    
    /**
     * 更新击杀BOSS时间逻辑
     */
    private void updateKillBossTime() {
        if (!allowInEvent && player.getEventInstance() != null && player.getMap().countBosses() > 0 && player.getMap().getPlayers().size() > 1) {
            // 条件满足：不允许在事件中使用、角色在事件中、BOSS数量>0、地图人数>1，记录当前时间
            killBossTime = currentServerTime();
        } else if (player.getMap().getPlayers().size() == 1) {
            // 地图人数=1时，重置时间为-1
            killBossTime = -1;
        } else if (player.getMap().getPlayers().size() > 1 && player.getMap().countBosses() == 0) {
            // 地图人数>1且BOSS数量=0时
            if (killBossTime != -1) {
                if (currentServerTime() - killBossTime < 30000) { // 30秒 = 30000毫秒
                    // 时间差小于30秒，不进行捡取操作
                    // 这里不再直接返回，而是通过调用方处理
                } else {
                    // 时间差超过30秒，重置时间为-1
                    killBossTime = -1;
                }
            }
        } else if (killBossTime != -1) {
            killBossTime = -1;
        }
    }
}