/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.gms.client.autoban;

import org.apache.logging.log4j.message.MapMessage;
import org.gms.client.*;
import org.gms.client.Character;
import org.gms.client.cheatsystem.plugin.MobVacPlugin;
import org.gms.config.GameConfig;
import org.gms.constants.skills.*;
import org.gms.server.logging.LogAction;
import org.gms.net.server.Server;
import org.gms.server.StatEffect;
import org.gms.server.life.MobSkillFactory;
import org.gms.server.life.MobSkillType;
import org.gms.server.life.Monster;
import org.gms.server.maps.MapleMap;
import org.gms.util.PacketCreator;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicIntegerArray;
import java.util.concurrent.atomic.AtomicLongArray;

/**
 * 自动封禁管理器
 * 负责管理玩家的违规行为检测和封禁处理
 * 采用点数累计系统，不同类型的违规行为有不同的点数和过期时间
 *
 * @author kevintjuh93
 */
public class AutobanManager {

    // 惩罚基础持续时间（毫秒）
    private static final int PUNISHMENT_DURATION_BASE = 10000;

    // 排除检测的技能ID集合
    private static final Set<Integer> EXCLUDED_SKILLS = new HashSet<>();
    // 终极武器技能集合
    private static final Set<Integer> FINAL_ATTACK_SKILLS = new HashSet<>();

    // 初始化排除检测的技能ID集合
    static {
        EXCLUDED_SKILLS.add(WindArcher.HURRICANE);
        EXCLUDED_SKILLS.add(Bowmaster.HURRICANE);
        EXCLUDED_SKILLS.add(Corsair.RAPID_FIRE);

        // 初始化终极武器技能集合
        FINAL_ATTACK_SKILLS.add(Fighter.FINAL_ATTACK_SWORD);
        FINAL_ATTACK_SKILLS.add(Fighter.FINAL_ATTACK_AXE);
        FINAL_ATTACK_SKILLS.add(Page.FINAL_ATTACK_BW);
        FINAL_ATTACK_SKILLS.add(Page.FINAL_ATTACK_SWORD);
        FINAL_ATTACK_SKILLS.add(Spearman.FINAL_ATTACK_SPEAR);
        FINAL_ATTACK_SKILLS.add(Spearman.FINAL_ATTACK_POLEARM);
        FINAL_ATTACK_SKILLS.add(Hunter.FINAL_ATTACK);
        FINAL_ATTACK_SKILLS.add(Crossbowman.FINAL_ATTACK);
        FINAL_ATTACK_SKILLS.add(WindArcher.FINAL_ATTACK);
        FINAL_ATTACK_SKILLS.add(DawnWarrior.FINAL_ATTACK);
    }

    private final Character chr; // 关联的玩家角色
    private final Map<AutobanFactory, Integer> punishPoints = new ConcurrentHashMap<>(); // 惩罚点数存储
    private final Map<AutobanFactory, Integer> banPoints = new ConcurrentHashMap<>(); // 封号点数存储
    private final Map<AutobanFactory, Long> lastTime = new ConcurrentHashMap<>(); // 最后一次违规时间
    private final AtomicInteger misses = new AtomicInteger(0); // 未命中计数
    private final AtomicInteger lastmisses = new AtomicInteger(0); // 上一次的未命中计数
    private final AtomicInteger samemisscount = new AtomicInteger(0); // 相同未命中计数次数
    private final AtomicLongArray spam = new AtomicLongArray(20); // 频繁操作时间记录数组
    private final AtomicIntegerArray timestamp = new AtomicIntegerArray(20); // 时间戳记录数组
    private final AtomicIntegerArray timestampcounter = new AtomicIntegerArray(20); // 时间戳计数器
    private final ConcurrentLinkedQueue<MonsterVacSample> landMonsterVacSamples = new ConcurrentLinkedQueue<>();    // 陆地怪物采样集合
    private final ConcurrentLinkedQueue<MonsterVacSample> flyMonsterVacSamples = new ConcurrentLinkedQueue<>();     // 飞行怪物采样集合
    private final ConcurrentLinkedQueue<MonsterVacSample> otherMonsterVacSamples = new ConcurrentLinkedQueue<>();    // 其他类型怪物采样集合
    private static class MonsterVacSample { int oid; int x; int y; long ts; }

    /**
     * 构造函数
     * @param chr 关联的玩家角色
     */
    public AutobanManager(Character chr) {
        this.chr = chr;
    }

    /**
     * 是否使用自动封禁功能
     * @return true-使用自动封禁, false-不使用自动封禁
     */
    public boolean useAutoBan() {
        return GameConfig.getServerBoolean("use_auto_ban");
    }

    /**
     * 是否使用自动封禁日志
     * @return true-使用自动封禁日志, false-不使用自动封禁日志
     */
    public boolean useAutoBanLog () {
        return GameConfig.getServerBoolean("use_auto_ban_log");
    }

    /**
     * 是否启用反作弊自动检测
     * @return true-启用自动检测, false-不启用自动检测
     */
    public boolean useAntiCheat() {
        return GameConfig.getServerBoolean("anti_cheat_auto_detection");
    }
    /**
     * 是否启用反作弊自动断开连接
     * @return true-启用自动断开, false-不启用自动断开
     */
    public boolean useAntiCheatDisconnect() {
        return GameConfig.getServerBoolean("anti_cheat_auto_disconnect");
    }

    /**
     * 是否启用反作弊自动扣除HP/MP
     * @return true-启用自动扣除, false-不启用自动扣除
     */
    public boolean useAntiCheatLoseHpMp() {
        return GameConfig.getServerBoolean("anti_cheat_auto_losehpmp");
    }

    public int addPoint(AutobanFactory fac, String reason) {
        return addPoint(fac, reason, null);
    }

    /**
     * 添加违规点数
     * 当惩罚点数达到阈值时清零惩罚点数并增加封号点数
     * 当封号点数达到阈值时执行封号操作
     *
     * @param fac 违规类型工厂
     * @param reason 违规原因描述
     * @param extraData 额外数据 (如怪物信息)
     * @return 1-已封号, 0-需要惩罚, -1-未触发任何操作
     */
    public int addPoint(AutobanFactory fac, String reason, MapMessage extraData) {
        if (!useAntiCheat()) return -1;
        // GM或已被封禁的玩家不处理
        if (chr.gmLevel() >= 4 || chr.isBanned()) {
            return -1;
        }

        // 检查是否超过过期时间，超过则惩罚点数减半
        if (lastTime.containsKey(fac)) {
            if (lastTime.get(fac) <= (Server.getInstance().getCurrentTime() - fac.getExpire())) {
                punishPoints.put(fac, punishPoints.get(fac) / 2);
            }
        }

        // 记录本次违规时间
        if (fac.getExpire() != -1) {
            lastTime.put(fac, Server.getInstance().getCurrentTime());
        }

        // 增加惩罚点数
        int currentPunishPoints = punishPoints.getOrDefault(fac, 0) + 1;
        punishPoints.put(fac, currentPunishPoints);

        // 在接近阈值时记录警告日志
        if (useAutoBanLog() && (fac != AutobanFactory.FAST_ATTACK && currentPunishPoints >= (fac.getMaximum() * 0.90))) {
            MapMessage logData = new MapMessage(extraData.getData()).with("points", currentPunishPoints);
            AutobanLogger.log(chr, fac, LogAction.CHEAT_WARNING, reason, logData);
        }

        // 惩罚点数达到最大值时增加封号点数并清零惩罚点数
        if (currentPunishPoints >= fac.getMaximum()) {
            // 清零惩罚点数
            punishPoints.put(fac, 0);

            // 增加封号点数
            int currentBanPoints = banPoints.getOrDefault(fac, 0) + 1;
            banPoints.put(fac, currentBanPoints);

            // 封号点数达到阈值时执行封号
            if (currentBanPoints >= 3) {
                // 清零封号点数
                banPoints.put(fac, 0);
                if (useAutoBan()) {
                    fac.autoban(chr, reason); // autoban内部已包含日志记录
                    return 1; // 已封号
                } else if (useAntiCheatDisconnect()) {
                    chr.getClient().disconnect(false,false);
                    Server.getInstance().broadcastGMMessage(chr.getWorld(), PacketCreator.sendYellowTip("[异常触发] 玩家 " + chr.getName() + " 在地图 " + chr.getMap().getMapName() + "(" + chr.getMapId() + ") 因触发 " + fac.getName() + " 而被断开连接"));
                    AutobanLogger.log(chr, fac, LogAction.CHEAT_DISCONNECT, reason, extraData);
                    return 1;
                } else if (useAutoBanLog()) {
                    // 记录日志但不执行封号
                    Server.getInstance().broadcastGMMessage(chr.getWorld(), PacketCreator.sendYellowTip("[异常触发] 玩家 " + chr.getName() + " 在地图 " + chr.getMap().getMapName() + "(" + chr.getMapId() + ") 因触发 " + fac.getName() + " 但未启用自动封禁，因此无事发生。"));
                    MapMessage logData = new MapMessage(extraData.getData()).with("msg", "未启用封禁");
                    AutobanLogger.log(chr, fac, LogAction.CHEAT_DETECTED, reason, logData);
                }
            } else {
                // 记录日志
                if (useAutoBanLog()) {
                    Server.getInstance().broadcastGMMessage(chr.getWorld(), PacketCreator.sendYellowTip("[异常触发] 玩家 " + chr.getName() + " 在地图 " + chr.getMap().getMapName() + "(" + chr.getMapId() + ") 触发 " + fac.getName() + " - " + reason));
                    MapMessage logData = new MapMessage(extraData.getData())
                        .with("points", fac.getMaximum())
                        .with("banPoints", currentBanPoints)
                        .with("msg", "增加封号点数");
                    AutobanLogger.log(chr, fac, LogAction.CHEAT_DETECTED, reason, logData);
                }
            }
            return 0; // 需要惩罚但未达到封号条件
        }
        return -1; // 未触发任何操作
    }

    /**
     * 自动扣除HP和MP惩罚
     * 当玩家触发违规时自动扣除一定量的HP和MP
     * 扣除量不会超过玩家当前的HP和MP上限
     *
     * @param hpToLose 要扣除的HP值
     * @param mpToLose 要扣除的MP值
     */
    public void applyLoseHpMp(int hpToLose, int mpToLose) {
        if (!useAntiCheatLoseHpMp() || chr == null || chr.gmLevel() >= 4) {
            if (chr.gmLevel() >= 4) {
                MapMessage logData = new MapMessage().with("reason", "GM等级>=4");
                AutobanLogger.log(chr, AutobanFactory.GENERAL, LogAction.CHEAT_ALERT, "跳过HP/MP扣除惩罚", logData);
            }
            return;
        }

        // 限制扣除的HP不超过角色最大HP
        int actualHpLoss = Math.min(hpToLose, chr.getMaxHp());
        // 限制扣除的MP不超过角色最大MP
        int actualMpLoss = Math.min(mpToLose, chr.getMaxMp());

        // 使用addMPHP同时扣除HP和MP
        chr.addMPHP(actualHpLoss, actualMpLoss);

        // 记录日志
        if (useAutoBanLog()) {
            MapMessage logData = new MapMessage().with("hpLoss", actualHpLoss).with("mpLoss", actualMpLoss);
            AutobanLogger.log(chr, AutobanFactory.GENERAL, LogAction.CHEAT_PENALTY, "扣除HP/MP惩罚", logData);
        }
    }

    /**
     * 自动扣除HP和MP惩罚（带消息提示）
     * 当玩家触发违规时自动扣除一定量的HP和MP
     * 扣除量不会超过玩家当前的HP和MP上限
     *
     * @param hpToLose 要扣除的HP值
     * @param mpToLose 要扣除的MP值
     * @param msg 提示消息
     */
    public void applyLoseHpMp(int hpToLose, int mpToLose, String msg) {
        if (!useAntiCheatLoseHpMp() || chr == null) return;
        // 调用原有的applyLoseHpMp方法处理HP/MP扣除逻辑
        applyLoseHpMp(hpToLose, mpToLose);

        // 如果消息不为空，则发送封包
        if (msg != null && !msg.isEmpty()) {
            chr.sendPacket(PacketCreator.earnTitleMessage(msg + " 超出部分对你自身造成 " + hpToLose + " 伤害"));
        }
    }
    /**
     * 施加debuff惩罚
     * @param duration 惩罚持续时间（毫秒）
     */
    public void applyDebuffPunishment(int duration) {
        if (chr == null || chr.gmLevel() >= 4) return;
        // 给玩家施加惩罚buff（眩晕，封印，致盲），防止客户端高频发包。
        MobSkillFactory.getMobSkill(MobSkillType.STUN, 7).ifPresent(skill -> chr.giveDebuff(Disease.STUN, skill, duration));
        MobSkillFactory.getMobSkill(MobSkillType.SEAL, 1).ifPresent(skill -> chr.giveDebuff(Disease.SEAL, skill, duration));
        MobSkillFactory.getMobSkill(MobSkillType.DARKNESS, 1).ifPresent(skill -> chr.giveDebuff(Disease.DARKNESS, skill, duration));
        if (useAutoBanLog()) {
            MapMessage logData = new MapMessage().with("duration", duration);
            AutobanLogger.log(chr, AutobanFactory.GENERAL, LogAction.CHEAT_PENALTY, "施加Debuff惩罚", logData);
        }
    }

    /**
     * 处理快速攻击检测
     * 根据点数系统进行惩罚或封号
     * @return true-触发了惩罚或封号, false-未触发任何操作
     */
    public boolean Detection_FastAttack(int skill, int skilllevel) {
        int minAttackInterval = GameConfig.getServerInt("anti_cheat_fast_attack_interval");
        if (minAttackInterval <= 0) {
            return false;
        }
        long currentTime = Server.getInstance().getCurrentTime();
        long lastAttackTime = getLastSpam(8);

        // 如果是第一次攻击，记录时间并返回
        if (lastAttackTime == 0) {
            spam(8);
            return false;
        }

        // 计算攻击间隔
        long timeBetweenAttacks = currentTime - lastAttackTime;

        // 更新攻击时间和技能
        spam(8);

        // 检查攻击间隔是否小于最小允许间隔，且为相同技能，暴风箭雨/金属风暴 不做检测
        // 使用Set存储排除检测的技能ID，提高查找效率
        if (!EXCLUDED_SKILLS.contains(skill) && timeBetweenAttacks < minAttackInterval) {
            // 构建违规原因描述，使用StringBuilder优化字符串拼接
            StringBuilder reasonBuilder = new StringBuilder();
            if (skill > 0) {
                reasonBuilder.append("技能: ").append(SkillFactory.getSkillName(skill))
                    .append("[Lv.").append(skilllevel).append("](").append(skill).append(")");
            } else {
                reasonBuilder.append("普通攻击");
            }
            reasonBuilder.append(" 频率异常，间隔: ").append(timeBetweenAttacks)
                .append("ms (最低允许: ").append(minAttackInterval).append("ms)");

            // 使用点数系统处理
            int result = addPoint(AutobanFactory.FAST_ATTACK, reasonBuilder.toString());

            if (result == 0) {
                // 需要惩罚，设置惩罚间隔
                int banPoints = getBanPoints(AutobanFactory.FAST_ATTACK);
                if (banPoints > 1) {//降低误报的概率
                    int punishmentDuration = banPoints * PUNISHMENT_DURATION_BASE; // 惩罚间隔至少10秒
                    applyDebuffPunishment(punishmentDuration);
                    chr.sendPacket(PacketCreator.earnTitleMessage("由于攻速过快，还需等待 " + (punishmentDuration / 1000f) + " 秒后才能恢复攻击。"));
                }
            }
            return getPunishPoints(AutobanFactory.FAST_ATTACK) > 3;
        }
        return false;
    }

    /**
     * 增加未命中计数
     * 用于检测miss无敌模式外挂
     */
    public void addMiss() {
        this.misses.incrementAndGet();
    }

    /**
     * 重置未命中计数并检测miss无敌模式
     * 连续多次出现相同的高miss计数时判定为使用外挂
     */
    public void resetMisses() {
        // 检测是否连续出现相同的高miss计数
        if (lastmisses.get() == misses.get() && misses.get() > 6) {
            samemisscount.incrementAndGet();
        }

        // 连续多次相同高miss，使用点数系统处理
        if (samemisscount.get() > 4) {
            int result = addPoint(AutobanFactory.MISS_HACK, "连续高miss计数: " + samemisscount.get());
            if (result == 0 || result == 1) {
                chr.sendPolice("您将因miss无敌模式而被断开连接。");
            }
            samemisscount.set(0); // 重置计数
        } else if (samemisscount.get() > 0) {
            this.lastmisses.set(misses.get());
        }
        this.misses.set(0);
    }

    /**
     * 记录频繁操作时间
     * @param type 操作类型
     */
    public void spam(int type) {
        this.spam.set(type, Server.getInstance().getCurrentTime());
    }

    /**
     * 记录频繁操作时间（指定时间戳）
     * @param type 操作类型
     * @param timestamp 时间戳
     */
    public void spam(int type, long timestamp) {
        this.spam.set(type, timestamp);
    }

    /**
     * 获取最后一次频繁操作时间
     * @param type 操作类型
     * @return 最后一次操作的时间戳
     */
    public long getLastSpam(int type) {
        return spam.get(type);
    }

    /**
     * 时间戳检查器
     * <code>type</code> 类型说明:<br>
     * 1: 宠物食品<br>
     * 2: 背包合并<br>
     * 3: 背包排序<br>
     * 4: 特殊移动<br>
     * 5: 使用捕捉道具<br>
     * 6: 物品丢弃<br>
     * 7: 聊天<br>
     * 8: 持续回复HP<br>
     * 9: 持续回复MP<br>
     * @param type 操作类型
     * @param time 当前时间戳
     * @param times 允许的最大次数
     */
    public void setTimestamp(int type, int time, int times) {
        if (this.timestamp.get(type) == time) {
            int currentCount = this.timestampcounter.incrementAndGet(type);
            if (currentCount >= times) {
                if (useAutoBan()) {
                    chr.getClient().disconnect(false, false);
                    AutobanLogger.log(chr, AutobanFactory.GENERAL, LogAction.CHEAT_DISCONNECT, "频繁操作断开连接", new MapMessage().with("type", type));
                }
            }
        } else {
            this.timestamp.set(type, time);
            this.timestampcounter.set(type, 0);
        }
    }

    /**
     * 获取指定违规类型的当前惩罚点数
     * @param fac 违规类型
     * @return 当前惩罚点数
     */
    public int getPunishPoints(AutobanFactory fac) {
        return punishPoints.getOrDefault(fac, 0);
    }

    /**
     * 获取指定违规类型的当前封号点数
     * @param fac 违规类型
     * @return 当前封号点数
     */
    public int getBanPoints(AutobanFactory fac) {
        return banPoints.getOrDefault(fac, 0);
    }

    /**
     * 移除指定违规类型的惩罚点数
     * @param fac 违规类型
     */
    public void removePunishPoint(AutobanFactory fac) {
        if (punishPoints.containsKey(fac)) {
            int currentPoints = punishPoints.get(fac);
            if (currentPoints > 0) {
                punishPoints.put(fac, currentPoints - 1);
            }
        }
    }

    /**
     * 重置指定违规类型的惩罚点数
     * @param fac 违规类型
     */
    public void resetPunishPoints(AutobanFactory fac) {
        punishPoints.put(fac, 0);
        lastTime.remove(fac);
    }

    /**
     * 重置指定违规类型的封号点数
     * @param fac 违规类型
     */
    public void resetBanPoints(AutobanFactory fac) {
        banPoints.put(fac, 0);
    }

    /**
     * 检测怪物吸怪外挂
     *
     * 功能说明：
     * 通过分析怪物坐标的一致性来判断玩家是否使用吸怪外挂。
     * 该函数会收集怪物位置样本，当90%以上的怪物都在70像素范围内时，
     * 判定为吸怪行为并执行相应的惩罚措施。
     *
     * 检测逻辑：
     * 1. 基础安全检查（反作弊启用、玩家和怪物对象有效）
     * 2. 地图状态检查（跳过已启用合法聚集功能的地图）
     * 3. 清理过期采样数据
     * 4. 收集新的怪物位置样本
     * 5. 当样本数量足够时进行一致性分析
     * 6. 如果90%以上怪物位置一致，执行惩罚措施
     *
     * @param monster 要检测的怪物对象，包含位置坐标信息
     * @return boolean 如果检测到吸怪行为返回true，否则返回false
     * @see MonsterVacSample 怪物位置采样数据结构
     * @see AutobanFactory#MONSTER_VAC 反作弊配置工厂
     * @since 1.0.0
     */
    public boolean detectMonsterVac(Monster monster) {
        if (!useAntiCheat() || chr == null || monster == null || monster.isBoss()) return false; // 基础安全检查：反作弊启用且对象有效
        MapleMap map = chr.getMap(); // 获取玩家所在地图
        if (map == null || MobVacPlugin.isMobVacActiveInMap(map)) { // 检查地图状态：跳过已启用合法聚集功能的地图
            return false; // 地图无效或已启用合法聚集功能，跳过检测
        }

        // 获取怪物移动类型
        int movetype = monster.getStats().getMovetype(); // 获取怪物移动类型

        // 根据移动类型选择对应的采样集合
        ConcurrentLinkedQueue<MonsterVacSample> currentSamples;
        if (movetype == 0) { // 陆地类型
            currentSamples = landMonsterVacSamples;
        } else if (movetype == 1) { // 飞行类型
            currentSamples = flyMonsterVacSamples;
        } else { // 其它类型
            currentSamples = otherMonsterVacSamples;
        }

        long now = Server.getInstance().getCurrentTime(); // 获取当前服务器时间
        long expire = AutobanFactory.MONSTER_VAC.getExpire(); // 获取怪物吸怪检测的过期时间配置

        // 清理过期的采样数据
        while (!currentSamples.isEmpty() && currentSamples.peek().ts <= now - expire) {
            currentSamples.poll(); // 移除过期记录
        }

        // 移除已存在的相同OID的样本，确保每个怪物只保留最新的位置信息
        int oid = monster.getObjectId();
        currentSamples.removeIf(sample -> sample.oid == oid);

        MonsterVacSample s = new MonsterVacSample(); // 创建新的怪物位置采样
        s.oid = oid; // 记录怪物OID
        s.x = (int) monster.getPosition().getX(); // 怪物X坐标
        s.y = (int) monster.getPosition().getY(); // 怪物Y坐标
        s.ts = now; // 采样时间戳

        // 将新采样添加到对应的队列末尾
        currentSamples.add(s);

        int maxSize = AutobanFactory.MONSTER_VAC.getMaximum(); // 获取最大采样数量配置

        // 保持采样队列在最大容量范围内
        while (currentSamples.size() > maxSize) {
            currentSamples.poll(); // 移除最旧的采样
        }

        // 当采样数量达到最大值时开始检测
        if (currentSamples.size() >= maxSize) {
            // 根据移动类型设置不同的检测参数
            int pixelRange = 60; // 默认采样范围
            double consistencyThreshold = 0.95; // 默认相似率阈值

            // 根据移动类型设置参数：1=陆地，2=飞行，其它=未知
            if (movetype == 1) { // 陆地类型
                pixelRange = 125; // 采样范围125像素点
                consistencyThreshold = 0.95; // 相似率98%
            } else if (movetype == 2) { // 飞行类型
                pixelRange = 50; // 采样范围50像素点
                consistencyThreshold = 0.98; // 相似率98%
            } else { // 其它类型
                pixelRange = 80; // 采样范围80像素点
                consistencyThreshold = 0.90; // 相似率90%
            }

            int consistentCount = 0; // 统计在相近位置的怪物数量
            for (MonsterVacSample sample : currentSamples) { // 遍历当前类型的所有采样，检查位置一致性
                if (Math.abs(sample.x - s.x) <= pixelRange && Math.abs(sample.y - s.y) <= pixelRange) { // 使用动态计算的像素范围
                    consistentCount++; // 一致位置计数增加
                }
            }

            double consistencyRatio = consistentCount * 1.0 / currentSamples.size(); // 计算一致位置比例

            if (consistencyRatio >= consistencyThreshold) { // 使用动态计算的相似率阈值
                // 二次校验：检查聚集的怪物占全图怪物的比例
                List<Monster> mapMonsters = map.getAllMonsters();
                int totalTypeMonsters = 0;
                int nearbyTypeCount = 0;

                for (Monster m : mapMonsters) {
                    // 只统计相同移动类型的怪物
                    if (m.getStats().getMovetype() == movetype) {
                        totalTypeMonsters++;
                        // 检查该同类型怪物是否在样本点附近
                        if (Math.abs(m.getPosition().x - s.x) <= pixelRange &&
                            Math.abs(m.getPosition().y - s.y) <= pixelRange) {
                            nearbyTypeCount++;
                        }
                    }
                }

                // 防止除以零（虽然理论上当前怪物存在，总数至少为1）
                if (totalTypeMonsters == 0) return false;

                double mapRatio = (double) nearbyTypeCount / totalTypeMonsters;

                // 如果该类型的怪物聚集比例低于 90%，则认为是误报（例如玩家拉怪）
                if (mapRatio < 0.85) {
                     return false;
                }

                String reason = "坐标: (" + s.x + "," + s.y + ") 附近一致性检测 " + consistentCount + "/" + currentSamples.size() +
                                " 同类占比: " + nearbyTypeCount + "/" + totalTypeMonsters + " (" + String.format("%.2f", mapRatio*100) + "%)" +
                                " (移动类型: " + (movetype == 0 ? "陆地" : (movetype == 1 ? "飞行" : "未知")) + ")"; // 构建违规原因描述
                int ret = addPoint(AutobanFactory.MONSTER_VAC, reason); // 添加到反作弊积分系统
                if (ret >= 1) { // 如果积分达到阈值，执行惩罚措施
                    map.killAllMonsters(); // 击杀所有怪物
                    map.restoreMapSpawnPoints(); // 恢复地图出生点
                }
                return true; // 检测到吸怪行为
            }
        }
        return false; // 未检测到吸怪行为
    }

    /**
     * 检测玩家MP消耗是否正常
     * @param attackEffect 攻击效果
     * @param skillId 技能ID
     * @param skillLevel 技能等级
     * @return 如果MP不足则返回true，否则返回false
     */
    public boolean checkMpCon(StatEffect attackEffect, int skillId, int skillLevel) {
        if (!useAntiCheat()) return false;
        if (chr.getMp() < attackEffect.getMpCon()) {
            addPoint(AutobanFactory.MPCON,
                " 尝试使用: " + SkillFactory.getSkillName(skillId) + "[Lv." + skillLevel + "](" + skillId + ")" +
                " 所需MP: " + attackEffect.getMpCon() + " 当前MP: " + chr.getMp() + " 已作废"
            );
            return true;
        }
        return false;
    }

    /**
     * 检测玩家攻击的怪物数量是否超过技能上限
     * @param attackEffect 攻击效果
     * @param numAttacked 攻击的怪物数量
     * @param skillId 技能ID
     * @param skillLevel 技能等级
     * @return 如果超过上限则返回true，否则返回false
     */
    public boolean checkMobCount(StatEffect attackEffect, int numAttacked, int skillId, int skillLevel) {
        if (!useAntiCheat()) return false;
        int maxMobCount = attackEffect.getMobCount();

        // 终极武器技能（终极剑、终极弓等）的攻击数量上限应以上一个技能为准
        if (FINAL_ATTACK_SKILLS.contains(skillId)) {
            maxMobCount = numAttacked;
        }

        if (numAttacked > maxMobCount) {
            addPoint(AutobanFactory.MOB_COUNT, "尝试使用: " + SkillFactory.getSkillName(skillId) + "[Lv." + skillLevel + "](" + skillId + ")" + " 目标数量: " + numAttacked + " 上限: " + maxMobCount + " 已作废");
            return true;
        }
        return false;
    }

    /**
     * 检测玩家攻击距离是否过远
     * @param monster 怪物
     * @param attackInfo 攻击信息
     * @return 如果距离过远则返回true，否则返回false
     */
    public boolean checkDistanceHack(Monster monster, org.gms.net.server.channel.handlers.AbstractDealDamageHandler.AttackInfo attackInfo) {
        if (!useAntiCheat()) return false;

        int distance = (int) chr.getPosition().distanceSq(monster.getPosition());
        int distanceToDetect = 200000;

        if (attackInfo.ranged) {
            distanceToDetect += 400000;
        }
        if (attackInfo.magic) {
            distanceToDetect += 250000;
        }
        if (chr.getJob().isA(Job.ARAN1)) {
            distanceToDetect += 200000; // Arans have extra range over normal warriors.
        }

        if ((monster.getId() >= 8800000 && monster.getId() <= 8800010) ||    //扎昆
                (monster.getId() >= 8810000 && monster.getId() <= 8810026)  //暗黑龙王
        ) { //某些组合怪物的模型比较大，需要增加攻击距离。
            distanceToDetect += 100000;
        }

        if (attackInfo.skill == Aran.COMBO_SMASH || attackInfo.skill == Aran.BODY_PRESSURE) {
            distanceToDetect += 40000;
        } else if (attackInfo.skill == Bishop.GENESIS || attackInfo.skill == ILArchMage.BLIZZARD || attackInfo.skill == FPArchMage.METEOR_SHOWER) {//圣光普照、落霜冰破、天降落星
            distanceToDetect += 350000;
        } else if (attackInfo.skill == Hero.BRANDISH || attackInfo.skill == DragonKnight.SPEAR_CRUSHER || attackInfo.skill == DragonKnight.POLE_ARM_CRUSHER || attackInfo.skill == DawnWarrior.BRANDISH) {
            distanceToDetect += 100000;
        } else if (attackInfo.skill == DragonKnight.DRAGON_ROAR || attackInfo.skill == SuperGM.SUPER_DRAGON_ROAR || attackInfo.skill == Crusader.SHOUT) { //龙咆哮 、 GM龙咆哮 、 虎咆哮
            distanceToDetect += 350000;
        } else if (attackInfo.skill == Shadower.BOOMERANG_STEP) { //一出双击
            distanceToDetect += 200000;
        } else if (attackInfo.skill == ILArchMage.CHAIN_LIGHTNING) { //链环闪电
            distanceToDetect += attackInfo.numAttacked * 85000;
        } else if (attackInfo.skill == ChiefBandit.ASSAULTER || attackInfo.skill == Corsair.AERIAL_STRIKE) { //落叶斩 、 地毯式空袭
            distanceToDetect += 80000;
        } else if (attackInfo.skill == ChiefBandit.BAND_OF_THIEVES) { //分身术
            distanceToDetect += 150000;
        }

        if (distance > distanceToDetect * 1.15) {
            MapMessage extra = new MapMessage();
            if (monster != null) {
                extra.with("mob", monster.getId())
                     .with("mobName", monster.getName());
            }
            addPoint(AutobanFactory.DISTANCE_HACK,
                    " 尝试使用: " + (attackInfo.skill > 0 ? SkillFactory.getSkillName(attackInfo.skill) + "[Lv." + attackInfo.skilllevel + "](" + attackInfo.skill + ")" : "普通攻击") +
                    " 对怪物：" + (monster != null ? monster.getName() + "[Lv."+monster.getLevel()+"]("+monster.getId()+")" : "null")+
                    " 距离：" + distance + " 上限：" + distanceToDetect + " 已作废", extra);
            monster.refreshMobPosition();
            return true;
        }
        return false;
    }

    /**
     * 检测固定伤害技能的伤害值是否正确
     * @param totDamageToOneMonster 对单个怪物的总伤害
     * @param attackEffect 攻击效果
     * @param skillId 技能ID
     * @param skillLevel 技能等级
     * @param monster 怪物
     * @return 如果伤害值不正确则返回true，否则返回false
     */
    public boolean checkFixedDamage(int totDamageToOneMonster, StatEffect attackEffect, int skillId, int skillLevel, Monster monster) {
        if (!useAntiCheat()) return false;
        if (attackEffect.getFixDamage() != -1 && totDamageToOneMonster != attackEffect.getFixDamage() && totDamageToOneMonster != 0) {
            MapMessage extra = new MapMessage();
            if (monster != null) {
                extra.with("mob", monster.getId())
                     .with("mobName", monster.getName());
            }
            int retban = addPoint(AutobanFactory.DAMAGE_FIX,
                    "尝试使用: " + SkillFactory.getSkillName(skillId) + "[Lv." + skillLevel + "](" + skillId + ")" +
                            " 对怪物" + (monster != null ? monster.getName() + "[Lv." + monster.getLevel() + "](" + monster.getId() + ")" : "null") +
                            " 造成固定伤害 " + totDamageToOneMonster + " 已作废", extra
            );
            if (retban == 0) {
                applyLoseHpMp(totDamageToOneMonster, totDamageToOneMonster, "检测到固定伤害，");
            }
            return true;
        }
        return false;
    }

    /**
     * 检测技能伤害段数是否正确
     * @param numDamage 实际伤害段数
     * @param maxAttack 技能最大伤害段数
     * @param skillId 技能ID
     * @param skillLevel 技能等级
     * @param monster 怪物
     * @return 修正后的伤害段数
     */
    public int checkDamageSegmentsHack(int numDamage, int maxAttack, int skillId, int skillLevel, Monster monster) {
        if (!useAntiCheat() || numDamage <= maxAttack) {
            return numDamage;
        }
        MapMessage extra = new MapMessage();
        if (monster != null) {
            extra.with("mob", monster.getId())
                 .with("mobName", monster.getName());
        }
        addPoint(AutobanFactory.DAMAGE_SEGMENTS_HACK,
                (skillId > 0 ? "技能: " + SkillFactory.getSkillName(skillId) + "[Lv." + skillLevel + "](" + skillId + ")" : "普通攻击: ") +
                " 怪物: " + (monster != null ? monster.getName() + "[Lv."+monster.getLevel()+"]("+monster.getId()+")" : "null") +
                " 段数: " + numDamage + " 上限: " + maxAttack + " 已纠正: " + maxAttack, extra
        );
        return maxAttack;
    }

    /**
     * 检测并处理过高的伤害值
     * @param damage 原始伤害
     * @param maxWithCrit 暴击时的最大伤害
     * @param skillId 技能ID
     * @param skillLevel 技能等级
     * @param monster 怪物
     * @return 修正后的伤害值
     */
    public long checkDamageHack(long damage, long maxWithCrit, int skillId, int skillLevel, Monster monster) {
        if (!useAntiCheat()) {
            return damage;
        }

        // 如果伤害超过我们计算值的2.00倍，则添加一个自动封禁点数，并将伤害调整为上限值。
        if (damage < 0 || damage > maxWithCrit * 1.6) {
            MapMessage extra = new MapMessage();
            if (monster != null) {
                extra.with("mob", monster.getId())
                     .with("mobName", monster.getName());
            }
            int tmpretban = addPoint(AutobanFactory.DAMAGE_HACK,
                    (skillId > 0 ? "技能: " + SkillFactory.getSkillName(skillId) + "[Lv." + skillLevel + "](" + skillId + ")" : "普通攻击: ") +
                    " 怪物: " + (monster != null ? monster.getName() + "[Lv."+monster.getLevel()+"]("+monster.getId()+")" : "null") +
                    " 伤害: " + damage + " 预警: " + maxWithCrit * 1.6 + " 已取消", extra
            );
            if (tmpretban == 0) {
                int tmpdamge = (int) Math.min(damage - maxWithCrit, Integer.MAX_VALUE);
                applyLoseHpMp(tmpdamge, tmpdamge, "检测到使用倍攻，");
            }
            damage = 0; //负数伤害 或者 伤害过高，基本可以确定是开了倍攻，直接置零完事。
        }

        // 如果伤害超过我们计算值的1.5倍，则发出警告。
        if (damage > maxWithCrit * 1.3) {
            AutobanFactory.DAMAGE_HACK.alert(chr,
                    (skillId > 0 ? "技能: " + SkillFactory.getSkillName(skillId) + "[Lv." + skillLevel + "](" + skillId + ")" : "普通攻击: ") +
                    " 怪物: " + (monster != null ? monster.getName() + "[Lv."+monster.getLevel()+"]("+monster.getId()+")" : "null") +
                    " 伤害: " + damage + " 上限: " + maxWithCrit + " 已纠正: " + maxWithCrit
            );
            damage =  maxWithCrit;
        }
        return damage;
    }
}
