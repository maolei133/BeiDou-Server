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
import java.util.Map.Entry;
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
    // 使用 ConcurrentHashMap 实现线程安全的懒加载缓存
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
        Data reqInfo = questInfo.getChildByPath(String.valueOf(id));
        if (reqInfo != null) {
            name = DataTool.getString("name", reqInfo, "");
            parent = DataTool.getString("parent", reqInfo, "");

            timeLimit = DataTool.getInt("timeLimit", reqInfo, 0);
            timeLimit2 = DataTool.getInt("timeLimit2", reqInfo, 0);
            autoStart = DataTool.getInt("autoStart", reqInfo, 0) == 1;
            autoPreComplete = DataTool.getInt("autoPreComplete", reqInfo, 0) == 1;
            autoComplete = DataTool.getInt("autoComplete", reqInfo, 0) == 1;

            int medalid = DataTool.getInt("viewMedalItem", reqInfo, 0);
            if (medalid != 0) {
                medals.put(this.id, medalid);
            }
        } else {
            log.error("在 QuestInfo.img 中找不到ID为 {} 的任务数据", id);
        }

        // 2. 加载任务需求 (Check.img)，如果存在
        Data reqData = questReq.getChildByPath(String.valueOf(id));
        if (reqData != null) {
            Data startReqData = reqData.getChildByPath("0");
            if (startReqData != null) {
                for (Data startReq : startReqData.getChildren()) {
                    QuestRequirementType type = QuestRequirementType.getByWZName(startReq.getName());
                    if (type == null) continue;
                    switch (type) {
                        case INTERVAL:
                            repeatable = true;
                            break;
                        case MOB:
                            for (Data mob : startReq.getChildren()) {
                                relevantMobs.add(DataTool.getInt(mob.getChildByPath("id")));
                            }
                            break;
                    }

                    AbstractQuestRequirement req = this.getRequirement(type, startReq);
                    if (req == null) {
                        continue;
                    }

                    startReqs.put(type, req);
                }
            }

            Data completeReqData = reqData.getChildByPath("1");
            if (completeReqData != null) {
                for (Data completeReq : completeReqData.getChildren()) {
                    QuestRequirementType type = QuestRequirementType.getByWZName(completeReq.getName());
                    if (type == null) continue;

                    AbstractQuestRequirement req = this.getRequirement(type, completeReq);
                    if (req == null) {
                        continue;
                    }

                    if (type.equals(QuestRequirementType.MOB)) {
                        for (Data mob : completeReq.getChildren()) {
                            relevantMobs.add(DataTool.getInt(mob.getChildByPath("id")));
                        }
                    }
                    completeReqs.put(type, req);
                }
            }
        }

        // 3. 加载任务动作/奖励 (Act.img)，如果存在
        Data actData = questAct.getChildByPath(String.valueOf(id));
        if (actData != null) {
            final Data startActData = actData.getChildByPath("0");
            if (startActData != null) {
                for (Data startAct : startActData.getChildren()) {
                    QuestActionType questActionType = QuestActionType.getByWZName(startAct.getName());
                    if (questActionType == null) continue;
                    AbstractQuestAction act = this.getAction(questActionType, startAct);

                    if (act == null) {
                        continue;
                    }

                    startActs.put(questActionType, act);
                }
            }
            Data completeActData = actData.getChildByPath("1");
            if (completeActData != null) {
                for (Data completeAct : completeActData.getChildren()) {
                    QuestActionType questActionType = QuestActionType.getByWZName(completeAct.getName());
                    if (questActionType == null) continue;
                    AbstractQuestAction act = this.getAction(questActionType, completeAct);

                    if (act == null) {
                        continue;
                    }

                    completeActs.put(questActionType, act);
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
     * 使用 ConcurrentHashMap 的 computeIfAbsent 方法实现线程安全的懒加载。
     * @param id 任务ID
     * @return 任务实例
     */
    public static Quest getInstance(int id) {
        return quests.computeIfAbsent(id, questId -> {
//            log.info("懒加载任务: {}", questId);
            return new Quest(questId);
        });
    }

    /**
     * 懒加载 infoNumber 到 questID 的映射。
     */
    private static void lazyLoadInfoNumberMap() {
        // 双重检查锁定，确保只加载一次
        if (infoNumberQuests.isEmpty()) {
            synchronized (infoNumberQuests) {
                if (infoNumberQuests.isEmpty()) {
                    long startTime = System.currentTimeMillis();
                    for (Data quest : questInfo.getChildren()) {
                        int questID = Integer.parseInt(quest.getName());
                        Quest q = getInstance(questID); // 复用懒加载

                        int infoNumber;
                        infoNumber = q.getInfoNumber(Status.STARTED);
                        if (infoNumber > 0) {
                            infoNumberQuests.put(infoNumber, questID);
                        }

                        infoNumber = q.getInfoNumber(Status.COMPLETED);
                        if (infoNumber > 0) {
                            infoNumberQuests.put(infoNumber, questID);
                        }
                    }
                    log.info("任务映射表加载完成 infoNumber -> QuestID，耗时：{} 毫秒", System.currentTimeMillis() - startTime);
                }
            }
        }
    }

    public static Quest getInstanceFromInfoNumber(int infoNumber) {
        lazyLoadInfoNumberMap(); // 确保映射表已加载
        Integer id = infoNumberQuests.get(infoNumber);
        if (id == null) {
            id = infoNumber;
        }
        return getInstance(id);
    }

    public boolean isSameDayRepeatable() {
        if (!repeatable) {
            return false;
        }

        IntervalRequirement ir = (IntervalRequirement) startReqs.get(QuestRequirementType.INTERVAL);
        return ir.getInterval() < HOURS.toMillis(GameConfig.getServerLong("quest_point_repeatable_interval"));
    }

    public boolean canStartQuestByStatus(Character chr) {
        QuestStatus mqs = chr.getQuest(this);
        return !(!mqs.getStatus().equals(Status.NOT_STARTED) && !(mqs.getStatus().equals(Status.COMPLETED) && repeatable));
    }

    public boolean canQuestByInfoProgress(Character chr) {
        QuestStatus mqs = chr.getQuest(this);
        List<String> ix = mqs.getInfoEx();
        if (!ix.isEmpty()) {
            short questid = mqs.getQuestID();
            short infoNumber = mqs.getInfoNumber();
            if (infoNumber <= 0) {
                infoNumber = questid;  // 默认情况下，infoNumber 与 questid 相同
            }

            int ixSize = ix.size();
            for (int i = 0; i < ixSize; i++) {
                String progress = chr.getAbstractPlayerInteraction().getQuestProgress(infoNumber, i);
                String ixProgress = ix.get(i);

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

        for (AbstractQuestRequirement r : startReqs.values()) {
            if (!r.check(chr, npcid)) {
                return false;
            }
        }

        return canQuestByInfoProgress(chr);
    }

    public boolean canComplete(Character chr, Integer npcid) {
        QuestStatus mqs = chr.getQuest(this);
        if (!mqs.getStatus().equals(Status.STARTED)) {
            return false;
        }

        for (AbstractQuestRequirement r : completeReqs.values()) {
            if (!r.check(chr, npcid)) {
                return false;
            }
        }

        return canQuestByInfoProgress(chr);
    }

    public void start(Character chr, int npc) {
        if (autoStart || canStart(chr, npc)) {
            Collection<AbstractQuestAction> acts = startActs.values();
            for (AbstractQuestAction a : acts) {
                if (!a.check(chr, null)) { // null 是否合适？
                    return;
                }
            }
            for (AbstractQuestAction a : acts) {
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
            Collection<AbstractQuestAction> acts = completeActs.values();
            for (AbstractQuestAction a : acts) {
                if (!a.check(chr, selection)) {
                    return;
                }
            }
            forceComplete(chr, npc);
            for (AbstractQuestAction a : acts) {
                a.run(chr, selection);
            }
            if (!this.hasNextQuestAction()) {
                chr.announceUpdateQuest(DelayedQuestUpdate.INFO, chr.getQuest(this));
            }
        }
    }

    public void reset(Character chr) {
        QuestStatus newStatus = new QuestStatus(this, QuestStatus.Status.NOT_STARTED);
        chr.updateQuestStatus(newStatus);
    }

    public boolean forfeit(Character chr) {
        if (!chr.getQuest(this).getStatus().equals(Status.STARTED)) {
            return false;
        }
        if (timeLimit > 0) {
            chr.sendPacket(PacketCreator.removeQuestTimeLimit(id));
        }
        QuestStatus newStatus = new QuestStatus(this, QuestStatus.Status.NOT_STARTED);
        newStatus.setForfeited(chr.getQuest(this).getForfeited() + 1);
        chr.updateQuestStatus(newStatus);
        return true;
    }

    public boolean forceStart(Character chr, int npc) {
        QuestStatus newStatus = new QuestStatus(this, QuestStatus.Status.STARTED, npc);

        QuestStatus oldStatus = chr.getQuest(this.getId());
        for (Entry<Integer, String> e : oldStatus.getProgress().entrySet()) {
            newStatus.setProgress(e.getKey(), e.getValue());
        }

        if (id / 100 == 35 && GameConfig.getServerInt("tot_mob_quest_requirement") > 0) {
            int setProg = 999 - Math.min(999, GameConfig.getServerInt("tot_mob_quest_requirement"));

            for (Integer pid : newStatus.getProgress().keySet()) {
                if (pid >= 8200000 && pid <= 8200012) {
                    String pr = StringUtil.getLeftPaddedStr(Integer.toString(setProg), '0', 3);
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

        QuestStatus newStatus = new QuestStatus(this, QuestStatus.Status.COMPLETED, npc);
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
        AbstractQuestRequirement req = startReqs.get(QuestRequirementType.ITEM);
        if (req == null) {
            return Integer.MIN_VALUE;
        }

        ItemRequirement ireq = (ItemRequirement) req;
        return ireq.getItemAmountNeeded(itemid, false);
    }

    public int getCompleteItemAmountNeeded(int itemid) {
        AbstractQuestRequirement req = completeReqs.get(QuestRequirementType.ITEM);
        if (req == null) {
            return Integer.MAX_VALUE;
        }

        ItemRequirement ireq = (ItemRequirement) req;
        return ireq.getItemAmountNeeded(itemid, true);
    }

    public int getMobAmountNeeded(int mid) {
        AbstractQuestRequirement req = completeReqs.get(QuestRequirementType.MOB);
        if (req == null) {
            return 0;
        }

        MobRequirement mreq = (MobRequirement) req;

        return mreq.getRequiredMobCount(mid);
    }

    public short getInfoNumber(Status qs) {
        boolean checkEnd = qs.equals(Status.STARTED);
        Map<QuestRequirementType, AbstractQuestRequirement> reqs = !checkEnd ? startReqs : completeReqs;

        AbstractQuestRequirement req = reqs.get(QuestRequirementType.INFO_NUMBER);
        if (req != null) {
            InfoNumberRequirement inReq = (InfoNumberRequirement) req;
            return inReq.getInfoNumber();
        } else {
            return 0;
        }
    }

    public String getInfoEx(Status qs, int index) {
        boolean checkEnd = qs.equals(Status.STARTED);
        Map<QuestRequirementType, AbstractQuestRequirement> reqs = !checkEnd ? startReqs : completeReqs;
        try {
            AbstractQuestRequirement req = reqs.get(QuestRequirementType.INFO_EX);
            InfoExRequirement ixReq = (InfoExRequirement) req;
            return ixReq.getInfo().get(index);
        } catch (Exception e) {
            return "";
        }
    }

    public List<String> getInfoEx(Status qs) {
        boolean checkEnd = qs.equals(Status.STARTED);
        Map<QuestRequirementType, AbstractQuestRequirement> reqs = !checkEnd ? startReqs : completeReqs;
        try {
            AbstractQuestRequirement req = reqs.get(QuestRequirementType.INFO_EX);
            InfoExRequirement ixReq = (InfoExRequirement) req;
            return ixReq.getInfo();
        } catch (Exception e) {
            return new LinkedList<>();
        }
    }

    public int getTimeLimit() {
        return timeLimit;
    }

    public static void clearCache(int quest) {
        quests.remove(quest);
    }

    public static void clearCache() {
        quests.clear();
    }

    private AbstractQuestRequirement getRequirement(QuestRequirementType type, Data data) {
        AbstractQuestRequirement ret = null;
        switch (type) {
            case END_DATE:
                ret = new EndDateRequirement(this, data);
                break;
            case JOB:
                ret = new JobRequirement(this, data);
                break;
            case QUEST:
                ret = new QuestRequirement(this, data);
                break;
            case FIELD_ENTER:
                ret = new FieldEnterRequirement(this, data);
                break;
            case INFO_NUMBER:
                ret = new InfoNumberRequirement(this, data);
                break;
            case INFO_EX:
                ret = new InfoExRequirement(this, data);
                break;
            case INTERVAL:
                ret = new IntervalRequirement(this, data);
                break;
            case COMPLETED_QUEST:
                ret = new CompletedQuestRequirement(this, data);
                break;
            case ITEM:
                ret = new ItemRequirement(this, data);
                break;
            case MAX_LEVEL:
                ret = new MaxLevelRequirement(this, data);
                break;
            case MESO:
                ret = new MesoRequirement(this, data);
                break;
            case MIN_LEVEL:
                ret = new MinLevelRequirement(this, data);
                break;
            case MIN_PET_TAMENESS:
                ret = new MinTamenessRequirement(this, data);
                break;
            case MOB:
                ret = new MobRequirement(this, data);
                break;
            case MONSTER_BOOK:
                ret = new MonsterBookCountRequirement(this, data);
                break;
            case NPC:
                ret = new NpcRequirement(this, data);
                break;
            case PET:
                ret = new PetRequirement(this, data);
                break;
            case BUFF:
                ret = new BuffRequirement(this, data);
                break;
            case EXCEPT_BUFF:
                ret = new BuffExceptRequirement(this, data);
                break;
            case SCRIPT:
                ret = new ScriptRequirement(this, data);
                break;
            case NORMAL_AUTO_START:
            case START:
            case END:
                break;
            default:
                break;
        }
        return ret;
    }

    private AbstractQuestAction getAction(QuestActionType type, Data data) {
        AbstractQuestAction ret = null;
        switch (type) {
            case BUFF:
                ret = new BuffAction(this, data);
                break;
            case EXP:
                ret = new ExpAction(this, data);
                break;
            case FAME:
                ret = new FameAction(this, data);
                break;
            case ITEM:
                ret = new ItemAction(this, data);
                break;
            case MESO:
                ret = new MesoAction(this, data);
                break;
            case NEXTQUEST:
                ret = new NextQuestAction(this, data);
                break;
            case PETSKILL:
                ret = new PetSkillAction(this, data);
                break;
            case QUEST:
                ret = new QuestAction(this, data);
                break;
            case SKILL:
                ret = new SkillAction(this, data);
                break;
            case PETTAMENESS:
                ret = new PetTamenessAction(this, data);
                break;
            case PETSPEED:
                ret = new PetSpeedAction(this, data);
                break;
            case INFO:
                ret = new InfoAction(this, data);
                break;
            default:
                break;
        }
        return ret;
    }

    public boolean restoreLostItem(Character chr, int itemid) {
        if (chr.getQuest(this).getStatus().equals(QuestStatus.Status.STARTED)) {
            ItemAction itemAct = (ItemAction) startActs.get(QuestActionType.ITEM);
            if (itemAct != null) {
                return itemAct.restoreLostItem(chr, itemid);
            }
        }

        return false;
    }

    public int getMedalRequirement() {
        Integer medalid = medals.get(id);
        return medalid != null ? medalid : -1;
    }

    public int getNpcRequirement(boolean checkEnd) {
        Map<QuestRequirementType, AbstractQuestRequirement> reqs = !checkEnd ? startReqs : completeReqs;
        AbstractQuestRequirement mqr = reqs.get(QuestRequirementType.NPC);
        if (mqr != null) {
            return ((NpcRequirement) mqr).get();
        } else {
            return -1;
        }
    }

    public boolean hasScriptRequirement(boolean checkEnd) {
        Map<QuestRequirementType, AbstractQuestRequirement> reqs = !checkEnd ? startReqs : completeReqs;
        AbstractQuestRequirement mqr = reqs.get(QuestRequirementType.SCRIPT);

        if (mqr != null) {
            return ((ScriptRequirement) mqr).get();
        } else {
            return false;
        }
    }

    public boolean hasNextQuestAction() {
        Map<QuestActionType, AbstractQuestAction> acts = completeActs;
        AbstractQuestAction mqa = acts.get(QuestActionType.NEXTQUEST);

        return mqa != null;
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
        List<Quest> ret = new LinkedList<>();

        search = search.toLowerCase();
        // 注意：这里遍历 quests.values() 会触发所有任务的加载，这是一个高成本操作。
        // 在懒加载模式下，应谨慎使用或寻找替代方案。
        for (Quest mq : quests.values()) {
            if (mq.name.toLowerCase().contains(search) || mq.parent.toLowerCase().contains(search)) {
                ret.add(mq);
            }
        }

        return ret;
    }

    /**
     * 全量加载所有任务数据到缓存中。
     * 用于预加载模式。
     */
    public static void loadAllQuests() {
        // 遍历QuestInfo.img中的所有任务ID，触发加载
        long start = System.currentTimeMillis();
        for (Data quest : questInfo.getChildren()) {
            int questID = Integer.parseInt(quest.getName());
            getInstance(questID);
        }
        log.info("任务加载完成，总共 {} 个任务，耗时：{} 毫秒", quests.size(), System.currentTimeMillis() - start);

        // 确保infoNumber映射也被完全加载
        lazyLoadInfoNumberMap();
    }

    public void expireQuest(Character chr) {
        if (forfeit(chr)) {
            chr.sendPacket(PacketCreator.questExpire(getId()));
        }
    }
}
