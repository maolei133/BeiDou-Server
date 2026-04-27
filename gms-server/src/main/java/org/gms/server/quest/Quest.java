/*
 * 本文件是 OdinMS Maple Story 服务器的一部分
 * 版权所有 (C) 2008 Patrick Huy <patrick.huy@frz.cc>
 *             Matthias Butz <matze@odinms.de>
 *             Jan Christian Meyer <vimes@odinms.de>
 *
 * 本程序是自由软件：您可以根据自由软件基金会发布的 GNU Affero 通用公共许可证的条款重新分发和/或修改它。
 * 您不得在 GNU Affero 通用公共许可证的任何其他版本下使用、修改或分发本程序。
 *
 * 本程序的发布希望能对您有所帮助，但没有任何担保；甚至没有对适销性或特定用途适用性的默示担保。
 * 有关更多详细信息，请参阅 GNU Affero 通用公共许可证。
 *
 * 您应该已经随本程序收到一份 GNU Affero 通用公共许可证的副本。如果没有，请参阅 <http://www.gnu.org/licenses/>。
 */
package org.gms.server.quest;

import lombok.extern.slf4j.Slf4j;
import org.gms.client.Character;
import org.gms.client.QuestStatus;
import org.gms.client.QuestStatus.Status;
import org.gms.config.GameConfig;
import org.gms.constants.game.DelayedQuestUpdate;
import org.gms.provider.Data;
import org.gms.provider.DataProvider;
import org.gms.provider.DataProviderFactory;
import org.gms.provider.DataTool;
import org.gms.provider.wz.WZFiles;
import org.gms.server.quest.actions.*;
import org.gms.server.quest.requirements.*;
import org.gms.util.PacketCreator;
import org.gms.util.StringUtil;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * 任务数据和逻辑处理类
 * @author Matze
 * @author Ronan - 增加了对勋章任务的支持
 */
@Slf4j
public class Quest {
    // 由于改为全量加载，这些Map在启动时就会被完全填充
    private static final Map<Integer, Quest> quests = new ConcurrentHashMap<>();
    private static final Map<Integer, Integer> infoNumberQuests = new ConcurrentHashMap<>();
    private static final Map<Short, Integer> medals = new ConcurrentHashMap<>();
    private static final Set<Short> exploitableQuests = new HashSet<>();

    // WZ数据提供者，保持静态以供所有任务实例共享
    private final static DataProvider questData;
    private final static Data questInfo;
    private final static Data questAct;
    private final static Data questReq;

    // 静态初始化块，用于加载和校验核心WZ数据
    static {
        questData = DataProviderFactory.getDataProvider(WZFiles.QUEST);
        if (questData == null) {
            throw new IllegalStateException("加载任务失败：无法找到或读取 Quest.wz 文件。");
        }
        questInfo = questData.getData("QuestInfo.img");
        if (questInfo == null) {
            throw new IllegalStateException("加载任务失败：在 Quest.wz 中找不到 QuestInfo.img 节点。");
        }
        questAct = questData.getData("Act.img");
        if (questAct == null) {
            throw new IllegalStateException("加载任务失败：在 Quest.wz 中找不到 Act.img 节点。");
        }
        questReq = questData.getData("Check.img");
        if (questReq == null) {
            throw new IllegalStateException("加载任务失败：在 Quest.wz 中找不到 Check.img 节点。");
        }

        // 填充一些硬编码的数据
        exploitableQuests.add((short) 2338);
        exploitableQuests.add((short) 3637);
        exploitableQuests.add((short) 3714);
        exploitableQuests.add((short) 21752);
    }

    protected short id;
    protected int timeLimit, timeLimit2;
    protected Map<QuestRequirementType, AbstractQuestRequirement> startReqs = new EnumMap<>(QuestRequirementType.class);
    protected Map<QuestRequirementType, AbstractQuestRequirement> completeReqs = new EnumMap<>(QuestRequirementType.class);
    protected Map<QuestActionType, AbstractQuestAction> startActs = new EnumMap<>(QuestActionType.class);
    protected Map<QuestActionType, AbstractQuestAction> completeActs = new EnumMap<>(QuestActionType.class);
    protected List<Integer> relevantMobs = new LinkedList<>();
    private boolean autoStart;
    private boolean autoPreComplete, autoComplete;
    private boolean repeatable = false;
    private String name = "", parent = "";

    /**
     * 私有构造函数，用于加载单个任务的数据。
     * @param id 任务ID
     */
    private Quest(int id) {
        this.id = (short) id;

        // 修正懒加载问题：即使任务在Check.img中没有需求节点，也必须继续加载QuestInfo和Act中的数据。
        // 不能因为reqData为null就提前返回，否则纯脚本任务或只有奖励的任务会加载失败。

        // 1. 加载任务基本信息 (QuestInfo.img)
        var reqInfo = questInfo.getChildByPath(String.valueOf(id));
        if (reqInfo != null) {
            name = DataTool.getString("name", reqInfo, "");
            parent = DataTool.getString("parent", reqInfo, "");

            timeLimit = DataTool.getInt("timeLimit", reqInfo, 0);
            timeLimit2 = DataTool.getInt("timeLimit2", reqInfo, 0);
            autoStart = DataTool.getInt("autoStart", reqInfo, 0) == 1;
            autoPreComplete = DataTool.getInt("autoPreComplete", reqInfo, 0) == 1;
            autoComplete = DataTool.getInt("autoComplete", reqInfo, 0) == 1;

            var medalid = DataTool.getInt("viewMedalItem", reqInfo, 0);
            if (medalid != 0) {
                medals.put(this.id, medalid);
            }
        } else {
            log.error("在 QuestInfo.img 中找不到ID为 {} 的任务数据", id);
        }

        // 2. 加载任务需求 (Check.img)，如果存在
        var reqData = questReq.getChildByPath(String.valueOf(id));
        if (reqData != null) {
            var startReqData = reqData.getChildByPath("0");
            if (startReqData != null) {
                for (var startReq : startReqData.getChildren()) {
                    var type = QuestRequirementType.getByWZName(startReq.getName());
                    if (type == null) continue;
                    
                    // 注解：使用增强型 switch 语句 (Java 14+)
                    switch (type) {
                        case INTERVAL -> repeatable = true;
                        case MOB -> {
                            for (var mob : startReq.getChildren()) {
                                relevantMobs.add(DataTool.getInt(mob.getChildByPath("id")));
                            }
                        }
                        default -> {
                            // 其他情况不做处理
                        }
                    }

                    var req = this.getRequirement(type, startReq);
                    if (req != null) {
                        startReqs.put(type, req);
                    }
                }
            }

            var completeReqData = reqData.getChildByPath("1");
            if (completeReqData != null) {
                for (var completeReq : completeReqData.getChildren()) {
                    var type = QuestRequirementType.getByWZName(completeReq.getName());
                    if (type == null) continue;

                    var req = this.getRequirement(type, completeReq);
                    if (req == null) {
                        continue;
                    }

                    if (type.equals(QuestRequirementType.MOB)) {
                        for (var mob : completeReq.getChildren()) {
                            relevantMobs.add(DataTool.getInt(mob.getChildByPath("id")));
                        }
                    }
                    completeReqs.put(type, req);
                }
            }
        }

        // 3. 加载任务动作/奖励 (Act.img)，如果存在
        var actData = questAct.getChildByPath(String.valueOf(id));
        if (actData != null) {
            final var startActData = actData.getChildByPath("0");
            if (startActData != null) {
                for (var startAct : startActData.getChildren()) {
                    var questActionType = QuestActionType.getByWZName(startAct.getName());
                    if (questActionType == null) continue;
                    var act = this.getAction(questActionType, startAct);

                    if (act != null) {
                        startActs.put(questActionType, act);
                    }
                }
            }
            var completeActData = actData.getChildByPath("1");
            if (completeActData != null) {
                for (var completeAct : completeActData.getChildren()) {
                    var questActionType = QuestActionType.getByWZName(completeAct.getName());
                    if (questActionType == null) continue;
                    var act = this.getAction(questActionType, completeAct);

                    if (act != null) {
                        completeActs.put(questActionType, act);
                    }
                }
            }
        }
    }

    public boolean isAutoComplete() {
        return autoPreComplete || autoComplete;
    }

    public boolean isAutoStart() {
        return autoStart;
    }

    /**
     * 获取任务实例的唯一入口。
     * 使用 ConcurrentHashMap 的 computeIfAbsent 方法确保线程安全，并保证永不返回null。
     * 在全量加载模式下，此方法通常会直接命中缓存。
     * 如果请求一个不存在的ID（例如，来自数据库的脏数据），它会动态创建一个空Quest对象以确保向后兼容。
     * @param id 任务ID
     * @return 任务实例，永不为null
     */
    public static Quest getInstance(int id) {
        return quests.computeIfAbsent(id, Quest::new);
    }

    /**
     * 全量加载所有任务数据到缓存中。
     * 此方法由 Server.java 在启动时通过虚拟线程调用。
     * 同时填充 infoNumber -> questID 的映射。
     */
    public static void loadAllQuests() {
        var startTime = System.currentTimeMillis();
        // 1. 遍历QuestInfo.img中的所有任务ID，触发加载并填充缓存
        for (var quest : questInfo.getChildren()) {
            var questID = Integer.parseInt(quest.getName());
            getInstance(questID); // 使用getInstance来加载，确保缓存被填充
        }
        log.info("任务加载完成，总共 {} 个任务，耗时：{} 毫秒", quests.size(), System.currentTimeMillis() - startTime);

        // 2. 填充 infoNumber -> QuestID 的映射表
        var mapStartTime = System.currentTimeMillis();
        for (var q : quests.values()) {
            int infoNumber;
            infoNumber = q.getInfoNumber(Status.STARTED);
            if (infoNumber > 0) {
                infoNumberQuests.put(infoNumber, (int) q.getId());
            }

            infoNumber = q.getInfoNumber(Status.COMPLETED);
            if (infoNumber > 0) {
                infoNumberQuests.put(infoNumber, (int) q.getId());
            }
        }
        log.info("任务映射表加载完成 infoNumber -> QuestID，耗时：{} 毫秒", System.currentTimeMillis() - mapStartTime);
    }


    public static Quest getInstanceFromInfoNumber(int infoNumber) {
        // 注解：使用 getOrDefault 简化代码
        var id = infoNumberQuests.getOrDefault(infoNumber, infoNumber);
        // 统一使用getInstance获取，确保健壮性
        return getInstance(id);
    }

    public boolean isSameDayRepeatable() {
        if (!repeatable) {
            return false;
        }

        var req = startReqs.get(QuestRequirementType.INTERVAL);
        // 注解：使用 instanceof 模式匹配 (Java 16+)
        if (req instanceof IntervalRequirement ir) {
            return ir.getInterval() < HOURS.toMillis(GameConfig.getServerLong("quest_point_repeatable_interval"));
        }
        return false;
    }

    public boolean canStartQuestByStatus(Character chr) {
        var mqs = chr.getQuest(this);
        return !(!mqs.getStatus().equals(Status.NOT_STARTED) && !(mqs.getStatus().equals(Status.COMPLETED) && repeatable));
    }

    public boolean canQuestByInfoProgress(Character chr) {
        var mqs = chr.getQuest(this);
        var ix = mqs.getInfoEx();
        if (!ix.isEmpty()) {
            short questid = mqs.getQuestID();
            short infoNumber = mqs.getInfoNumber();
            if (infoNumber <= 0) {
                infoNumber = questid;  // 默认情况下，infoNumber 与 questid 相同
            }

            var ixSize = ix.size();
            for (int i = 0; i < ixSize; i++) {
                var progress = chr.getAbstractPlayerInteraction().getQuestProgress(infoNumber, i);
                var ixProgress = ix.get(i);

                if (!progress.contentEquals(ixProgress)) {
                    return false;
                }
            }
        }

        return true;
    }

    public boolean canStart(Character chr, int npcid) {
        if (!canStartQuestByStatus(chr)) {
            return false;
        }

        for (var r : startReqs.values()) {
            if (!r.check(chr, npcid)) {
                return false;
            }
        }

        return canQuestByInfoProgress(chr);
    }

    public boolean canComplete(Character chr, Integer npcid) {
        var mqs = chr.getQuest(this);
        if (!mqs.getStatus().equals(Status.STARTED)) {
            return false;
        }

        for (var r : completeReqs.values()) {
            if (!r.check(chr, npcid)) {
                return false;
            }
        }

        return canQuestByInfoProgress(chr);
    }

    public void start(Character chr, int npc) {
        if (autoStart || canStart(chr, npc)) {
            var acts = startActs.values();
            for (var a : acts) {
                if (!a.check(chr, null)) { // null 是否合适？
                    return;
                }
            }
            for (var a : acts) {
                a.run(chr, null);
            }
            forceStart(chr, npc);
        }
    }

    public void complete(Character chr, int npc) {
        complete(chr, npc, null);
    }

    public void complete(Character chr, int npc, Integer selection) {
        if (autoPreComplete || canComplete(chr, npc)) {
            var acts = completeActs.values();
            for (var a : acts) {
                if (!a.check(chr, selection)) {
                    return;
                }
            }
            forceComplete(chr, npc);
            for (var a : acts) {
                a.run(chr, selection);
            }
            if (!this.hasNextQuestAction()) {
                chr.announceUpdateQuest(DelayedQuestUpdate.INFO, chr.getQuest(this));
            }
        }
    }

    public void reset(Character chr) {
        var newStatus = new QuestStatus(this, QuestStatus.Status.NOT_STARTED);
        chr.updateQuestStatus(newStatus);
    }

    public boolean forfeit(Character chr) {
        if (!chr.getQuest(this).getStatus().equals(Status.STARTED)) {
            return false;
        }
        if (timeLimit > 0) {
            chr.sendPacket(PacketCreator.removeQuestTimeLimit(id));
        }
        var newStatus = new QuestStatus(this, QuestStatus.Status.NOT_STARTED);
        newStatus.setForfeited(chr.getQuest(this).getForfeited() + 1);
        chr.updateQuestStatus(newStatus);
        return true;
    }

    public boolean forceStart(Character chr, int npc) {
        var newStatus = new QuestStatus(this, QuestStatus.Status.STARTED, npc);

        var oldStatus = chr.getQuest(this.getId());
        for (var e : oldStatus.getProgress().entrySet()) {
            newStatus.setProgress(e.getKey(), e.getValue());
        }

        if (id / 100 == 35 && GameConfig.getServerInt("tot_mob_quest_requirement") > 0) {
            int setProg = 999 - Math.min(999, GameConfig.getServerInt("tot_mob_quest_requirement"));

            for (var pid : newStatus.getProgress().keySet()) {
                if (pid >= 8200000 && pid <= 8200012) {
                    var pr = StringUtil.getLeftPaddedStr(Integer.toString(setProg), '0', 3);
                    newStatus.setProgress(pid, pr);
                }
            }
        }

        newStatus.setForfeited(chr.getQuest(this).getForfeited());
        newStatus.setCompleted(chr.getQuest(this).getCompleted());

        if (timeLimit > 0) {
            newStatus.setExpirationTime(System.currentTimeMillis() + SECONDS.toMillis(timeLimit));
            chr.questTimeLimit(this, timeLimit);
        }
        if (timeLimit2 > 0) {
            newStatus.setExpirationTime(System.currentTimeMillis() + timeLimit2);
            chr.questTimeLimit2(this, newStatus.getExpirationTime());
        }

        chr.updateQuestStatus(newStatus);

        return true;
    }

    public boolean forceComplete(Character chr, int npc) {
        if (timeLimit > 0) {
            chr.sendPacket(PacketCreator.removeQuestTimeLimit(id));
        }

        var newStatus = new QuestStatus(this, QuestStatus.Status.COMPLETED, npc);
        newStatus.setForfeited(chr.getQuest(this).getForfeited());
        newStatus.setCompleted(chr.getQuest(this).getCompleted());
        newStatus.setCompletionTime(System.currentTimeMillis());
        chr.updateQuestStatus(newStatus);

        chr.sendPacket(PacketCreator.showSpecialEffect(9)); // 任务完成特效
        chr.getMap().broadcastMessage(chr, PacketCreator.showForeignEffect(chr.getId(), 9), false); // 对其他玩家广播特效
        return true;
    }

    public short getId() {
        return id;
    }

    public List<Integer> getRelevantMobs() {
        return relevantMobs;
    }

    public int getStartItemAmountNeeded(int itemid) {
        var req = startReqs.get(QuestRequirementType.ITEM);
        if (req instanceof ItemRequirement ireq) {
            return ireq.getItemAmountNeeded(itemid, false);
        }
        return Integer.MIN_VALUE;
    }

    public int getCompleteItemAmountNeeded(int itemid) {
        var req = completeReqs.get(QuestRequirementType.ITEM);
        if (req instanceof ItemRequirement ireq) {
            return ireq.getItemAmountNeeded(itemid, true);
        }
        return Integer.MAX_VALUE;
    }

    public int getMobAmountNeeded(int mid) {
        var req = completeReqs.get(QuestRequirementType.MOB);
        if (req instanceof MobRequirement mreq) {
            return mreq.getRequiredMobCount(mid);
        }
        return 0;
    }

    public short getInfoNumber(Status qs) {
        var checkEnd = qs.equals(Status.STARTED);
        var reqs = !checkEnd ? startReqs : completeReqs;

        var req = reqs.get(QuestRequirementType.INFO_NUMBER);
        if (req instanceof InfoNumberRequirement inReq) {
            return inReq.getInfoNumber();
        }
        return 0;
    }

    public String getInfoEx(Status qs, int index) {
        var checkEnd = qs.equals(Status.STARTED);
        var reqs = !checkEnd ? startReqs : completeReqs;
        try {
            var req = reqs.get(QuestRequirementType.INFO_EX);
            if (req instanceof InfoExRequirement ixReq) {
                return ixReq.getInfo().get(index);
            }
        } catch (Exception e) { // 注解：使用未命名变量 (Java 21+)
            return "";
        }
        return "";
    }

    public List<String> getInfoEx(Status qs) {
        var checkEnd = qs.equals(Status.STARTED);
        var reqs = !checkEnd ? startReqs : completeReqs;
        try {
            var req = reqs.get(QuestRequirementType.INFO_EX);
            if (req instanceof InfoExRequirement ixReq) {
                return ixReq.getInfo();
            }
        } catch (Exception e) { // 注解：使用未命名变量 (Java 21+)
            return Collections.emptyList();
        }
        // 注解：使用 Collections.emptyList() 替代 new LinkedList<>()，以提高性能
        return Collections.emptyList();
    }

    public int getTimeLimit() {
        return timeLimit;
    }

    /**
     * 按ID清除单个任务的缓存。
     * 主要用于热重载或调试。
     * @param questId 要清除的任务ID
     */
    public static void clearCache(int questId) {
        quests.remove(questId);
        // 注意：此操作不会自动更新 infoNumberQuests 映射，可能需要重新加载所有任务来重建映射。
    }

    /**
     * 清除所有任务缓存。
     * 主要用于热重载或调试。
     */
    public static void clearCache() {
        quests.clear();
        infoNumberQuests.clear();
    }

    private AbstractQuestRequirement getRequirement(QuestRequirementType type, Data data) {
        // 注解：使用 switch 表达式 (Java 14+)
        return switch (type) {
            case END_DATE -> new EndDateRequirement(this, data);
            case JOB -> new JobRequirement(this, data);
            case QUEST -> new QuestRequirement(this, data);
            case FIELD_ENTER -> new FieldEnterRequirement(this, data);
            case INFO_NUMBER -> new InfoNumberRequirement(this, data);
            case INFO_EX -> new InfoExRequirement(this, data);
            case INTERVAL -> new IntervalRequirement(this, data);
            case COMPLETED_QUEST -> new CompletedQuestRequirement(this, data);
            case ITEM -> new ItemRequirement(this, data);
            case MAX_LEVEL -> new MaxLevelRequirement(this, data);
            case MESO -> new MesoRequirement(this, data);
            case MIN_LEVEL -> new MinLevelRequirement(this, data);
            case MIN_PET_TAMENESS -> new MinTamenessRequirement(this, data);
            case MOB -> new MobRequirement(this, data);
            case MONSTER_BOOK -> new MonsterBookCountRequirement(this, data);
            case NPC -> new NpcRequirement(this, data);
            case PET -> new PetRequirement(this, data);
            case BUFF -> new BuffRequirement(this, data);
            case EXCEPT_BUFF -> new BuffExceptRequirement(this, data);
            case SCRIPT -> new ScriptRequirement(this, data);
            case NORMAL_AUTO_START, START, END -> null;
            default -> null;
        };
    }

    private AbstractQuestAction getAction(QuestActionType type, Data data) {
        // 注解：使用 switch 表达式 (Java 14+)
        return switch (type) {
            case BUFF -> new BuffAction(this, data);
            case EXP -> new ExpAction(this, data);
            case FAME -> new FameAction(this, data);
            case ITEM -> new ItemAction(this, data);
            case MESO -> new MesoAction(this, data);
            case NEXTQUEST -> new NextQuestAction(this, data);
            case PETSKILL -> new PetSkillAction(this, data);
            case QUEST -> new QuestAction(this, data);
            case SKILL -> new SkillAction(this, data);
            case PETTAMENESS -> new PetTamenessAction(this, data);
            case PETSPEED -> new PetSpeedAction(this, data);
            case INFO -> new InfoAction(this, data);
            default -> null;
        };
    }

    public boolean restoreLostItem(Character chr, int itemid) {
        if (chr.getQuest(this).getStatus().equals(QuestStatus.Status.STARTED)) {
            var itemAct = startActs.get(QuestActionType.ITEM);
            if (itemAct instanceof ItemAction ia) {
                return ia.restoreLostItem(chr, itemid);
            }
        }

        return false;
    }

    public int getMedalRequirement() {
        return medals.getOrDefault(id, -1);
    }

    public int getNpcRequirement(boolean checkEnd) {
        var reqs = !checkEnd ? startReqs : completeReqs;
        var mqr = reqs.get(QuestRequirementType.NPC);
        if (mqr instanceof NpcRequirement nr) {
            return nr.get();
        }
        return -1;
    }

    public boolean hasScriptRequirement(boolean checkEnd) {
        var reqs = !checkEnd ? startReqs : completeReqs;
        var mqr = reqs.get(QuestRequirementType.SCRIPT);
        if (mqr instanceof ScriptRequirement sr) {
            return sr.get();
        }
        return false;
    }

    public boolean hasNextQuestAction() {
        return completeActs.containsKey(QuestActionType.NEXTQUEST);
    }

    public String getName() {
        return name;
    }

    public String getParentName() {
        return parent;
    }

    public static boolean isExploitableQuest(short questid) {
        return exploitableQuests.contains(questid);
    }

    public static List<Quest> getMatchedQuests(String search) {
        // 注解：使用 ArrayList 替代 LinkedList，并使用 var
        var ret = new ArrayList<Quest>();
        var lowerCaseSearch = search.toLowerCase();
        // 由于是全量加载，可以直接遍历
        for (var mq : quests.values()) {
            if (mq.name.toLowerCase().contains(lowerCaseSearch) || mq.parent.toLowerCase().contains(lowerCaseSearch)) {
                ret.add(mq);
            }
        }

        return ret;
    }

    public void expireQuest(Character chr) {
        if (forfeit(chr)) {
            chr.sendPacket(PacketCreator.questExpire(getId()));
        }
    }
}
