package org.gms.service;

import com.mybatisflex.core.query.QueryWrapper;
import lombok.AllArgsConstructor;
import org.gms.client.QuestStatus;
import org.gms.dao.entity.MedalmapsDO;
import org.gms.dao.entity.QuestprogressDO;
import org.gms.dao.entity.QueststatusDO;
import org.gms.dao.mapper.MedalmapsMapper;
import org.gms.dao.mapper.QuestprogressMapper;
import org.gms.dao.mapper.QueststatusMapper;
import org.gms.server.quest.Quest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.gms.dao.entity.table.MedalmapsDOTableDef.MEDALMAPS_DO;
import static org.gms.dao.entity.table.QuestprogressDOTableDef.QUESTPROGRESS_DO;
import static org.gms.dao.entity.table.QueststatusDOTableDef.QUESTSTATUS_DO;

@Service
@AllArgsConstructor
public class QuestService {
    private final MedalmapsMapper medalmapsMapper;
    private final QuestprogressMapper questprogressMapper;
    private final QueststatusMapper queststatusMapper;

    /**
     * 删除指定角色所有任务的进度、勋章地图和任务状态记录。
     * 主要用于角色删除或重置所有任务时。
     * @param cid 角色ID
     */
    @Transactional(rollbackFor = Exception.class)
    public void deleteQuestProgressByCharacter(int cid) {
        medalmapsMapper.deleteByQuery(QueryWrapper.create().where(MEDALMAPS_DO.CHARACTERID.eq(cid)));
        questprogressMapper.deleteByQuery(QueryWrapper.create().where(QUESTPROGRESS_DO.CHARACTERID.eq(cid)));
        queststatusMapper.deleteByQuery(QueryWrapper.create().where(QUESTSTATUS_DO.CHARACTERID.eq(cid)));
    }

    /**
     * 同步指定角色的所有任务状态到数据库。
     * 该方法会比较内存中的任务列表与数据库中的任务列表，进行增量更新（新增、修改、删除）。
     * 适用于角色下线或需要全面同步任务状态的场景。
     *
     * @param cid 角色ID
     * @param newQuestStatusList 内存中最新的任务状态列表
     */
    @Transactional(rollbackFor = Exception.class)
    public void syncCharacterQuests(int cid, List<QuestStatus> newQuestStatusList) {
        // 1. 从数据库加载旧的任务状态
        List<QuestStatus> oldQuestStatusList = getQuestStatusByCharacter(cid);
        Map<Integer, QuestStatus> oldQuestMap = oldQuestStatusList.stream()
                .collect(Collectors.toMap(qs -> (int) qs.getQuest().getId(), Function.identity()));
        Map<Integer, QuestStatus> newQuestMap = newQuestStatusList.stream()
                .collect(Collectors.toMap(qs -> (int) qs.getQuest().getId(), Function.identity()));

        // 2. 识别需要删除的任务
        List<Integer> questsToDelete = oldQuestMap.keySet().stream()
                .filter(questId -> !newQuestMap.containsKey(questId))
                .toList();
        if (!questsToDelete.isEmpty()) {
            for (Integer questId : questsToDelete) {
                deleteQuestStatus(cid, questId.shortValue());
            }
        }

        // 3. 识别需要新增和更新的任务
        for (QuestStatus newQs : newQuestStatusList) {
            QuestStatus oldQs = oldQuestMap.get((int) newQs.getQuest().getId());
            if (oldQs == null) {
                // 新增任务
                insertQuestStatus(cid, newQs);
            } else if (!isQuestStatusEqual(newQs, oldQs)) {
                // 更新任务
                updateQuestStatus(cid, newQs); // 调用新的单个任务更新方法
            }
        }
    }

    /**
     * 插入单个任务状态到数据库。
     *
     * @param cid 角色ID
     * @param qs 待插入的任务状态对象
     */
    @Transactional(rollbackFor = Exception.class)
    public void insertQuestStatus(int cid, QuestStatus qs) {
        QueststatusDO queststatusDO = new QueststatusDO();
        queststatusDO.setCharacterid(cid);
        queststatusDO.setQuest((int) qs.getQuest().getId());
        queststatusDO.setStatus(qs.getStatus().getId());
        queststatusDO.setTime((int) (qs.getCompletionTime() / 1000));
        queststatusDO.setExpires(qs.getExpirationTime());
        queststatusDO.setForfeited(qs.getForfeited());
        queststatusDO.setCompleted(qs.getCompleted());
        queststatusDO.setInfo(qs.getNpc());
        queststatusMapper.insert(queststatusDO); // 插入以获取ID

        long questStatusId = queststatusDO.getQueststatusid();

        List<QuestprogressDO> questprogressDOList = new ArrayList<>();
        for (Map.Entry<Integer, String> entry : qs.getProgress().entrySet()) {
            QuestprogressDO questprogressDO = new QuestprogressDO();
            questprogressDO.setCharacterid(cid);
            questprogressDO.setQueststatusid(questStatusId);
            questprogressDO.setProgressid(entry.getKey());
            questprogressDO.setProgress(entry.getValue());
            questprogressDOList.add(questprogressDO);
        }
        if (!questprogressDOList.isEmpty()) {
            questprogressMapper.insertBatch(questprogressDOList);
        }

        List<MedalmapsDO> medalmapsDOList = new ArrayList<>();
        for (int mapId : qs.getMedalMaps()) {
            MedalmapsDO medalmapsDO = new MedalmapsDO();
            medalmapsDO.setCharacterid(cid);
            medalmapsDO.setQueststatusid(questStatusId);
            medalmapsDO.setMapid(mapId);
            medalmapsDOList.add(medalmapsDO);
        }
        if (!medalmapsDOList.isEmpty()) {
            medalmapsMapper.insertBatch(medalmapsDOList);
        }
    }

    /**
     * 更新单个任务状态到数据库。
     * 该方法会查找指定角色的指定任务，并更新其主记录及级联的进度和勋章地图记录。
     *
     * @param cid 角色ID
     * @param qs 待更新的任务状态对象
     */
    @Transactional(rollbackFor = Exception.class)
    public void updateQuestStatus(int cid, QuestStatus qs) {
        // 找到对应的 QueststatusDO
        QueststatusDO queststatusDO = queststatusMapper.selectOneByQuery(QueryWrapper.create()
                .where(QUESTSTATUS_DO.CHARACTERID.eq(cid))
                .and(QUESTSTATUS_DO.QUEST.eq((int) qs.getQuest().getId())));

        if (queststatusDO == null) {
            // 如果找不到，说明是新任务，直接插入
            insertQuestStatus(cid, qs);
            return;
        }

        // 更新主表
        queststatusDO.setStatus(qs.getStatus().getId());
        queststatusDO.setTime((int) (qs.getCompletionTime() / 1000));
        queststatusDO.setExpires(qs.getExpirationTime());
        queststatusDO.setForfeited(qs.getForfeited());
        queststatusDO.setCompleted(qs.getCompleted());
        queststatusDO.setInfo(qs.getNpc());
        queststatusMapper.update(queststatusDO);

        long questStatusId = queststatusDO.getQueststatusid();

        // 更新子表：先删除旧的，再插入新的（对于子表，这种方式通常比逐条比较更简单高效）
        questprogressMapper.deleteByQuery(QueryWrapper.create().where(QUESTPROGRESS_DO.QUESTSTATUSID.eq(questStatusId)));
        medalmapsMapper.deleteByQuery(QueryWrapper.create().where(MEDALMAPS_DO.QUESTSTATUSID.eq(questStatusId)));

        List<QuestprogressDO> questprogressDOList = new ArrayList<>();
        for (Map.Entry<Integer, String> entry : qs.getProgress().entrySet()) {
            QuestprogressDO questprogressDO = new QuestprogressDO();
            questprogressDO.setCharacterid(cid);
            questprogressDO.setQueststatusid(questStatusId);
            questprogressDO.setProgressid(entry.getKey());
            questprogressDO.setProgress(entry.getValue());
            questprogressDOList.add(questprogressDO);
        }
        if (!questprogressDOList.isEmpty()) {
            questprogressMapper.insertBatch(questprogressDOList);
        }

        List<MedalmapsDO> medalmapsDOList = new ArrayList<>();
        for (int mapId : qs.getMedalMaps()) {
            MedalmapsDO medalmapsDO = new MedalmapsDO();
            medalmapsDO.setCharacterid(cid);
            medalmapsDO.setQueststatusid(questStatusId);
            medalmapsDO.setMapid(mapId);
            medalmapsDOList.add(medalmapsDO);
        }
        if (!medalmapsDOList.isEmpty()) {
            medalmapsMapper.insertBatch(medalmapsDOList);
        }
    }

    /**
     * 删除指定角色的单个任务的所有相关记录。
     *
     * @param cid 角色ID
     * @param questId 任务ID
     */
    @Transactional(rollbackFor = Exception.class)
    public void deleteQuestStatus(int cid, short questId) {
        QueryWrapper query = QueryWrapper.create()
                .where(QUESTSTATUS_DO.CHARACTERID.eq(cid))
                .and(QUESTSTATUS_DO.QUEST.eq((int) questId));

        List<QueststatusDO> questStatusToDelete = queststatusMapper.selectListByQuery(query);
        if (!questStatusToDelete.isEmpty()) {
            List<Long> questStatusIdsToDelete = questStatusToDelete.stream().map(QueststatusDO::getQueststatusid).toList();
            questprogressMapper.deleteByQuery(QueryWrapper.create().where(QUESTPROGRESS_DO.QUESTSTATUSID.in(questStatusIdsToDelete)));
            medalmapsMapper.deleteByQuery(QueryWrapper.create().where(MEDALMAPS_DO.QUESTSTATUSID.in(questStatusIdsToDelete)));
            queststatusMapper.deleteByQuery(query);
        }
    }

    /**
     * 比较两个任务状态对象是否相等。
     *
     * @param qs1 任务状态对象1
     * @param qs2 任务状态对象2
     * @return 如果所有关键字段都相等则返回true，否则返回false
     */
    private boolean isQuestStatusEqual(QuestStatus qs1, QuestStatus qs2) {
        if (qs1.getStatus() != qs2.getStatus() ||
                qs1.getForfeited() != qs2.getForfeited() ||
                qs1.getCompleted() != qs2.getCompleted() ||
                qs1.getNpc() != qs2.getNpc() ||
                qs1.getCompletionTime() != qs2.getCompletionTime() ||
                qs1.getExpirationTime() != qs2.getExpirationTime()) {
            return false;
        }
        if (!qs1.getProgress().equals(qs2.getProgress())) {
            return false;
        }
        return qs1.getMedalMaps().equals(qs2.getMedalMaps());
    }

    /**
     * 旧的保存任务状态方法，已废弃，请使用 syncCharacterQuests 或 updateQuestStatus。
     *
     * @param cid 角色ID
     * @param questStatusList 任务状态列表
     */
    @Deprecated
    @Transactional(rollbackFor = Exception.class)
    public void saveQuestStatus_old(int cid, List<QuestStatus> questStatusList) {
        deleteQuestProgressByCharacter(cid);

        if (questStatusList == null || questStatusList.isEmpty()) {
            return;
        }

        List<QueststatusDO> queststatusDOList = new ArrayList<>();
        List<QuestprogressDO> questprogressDOList = new ArrayList<>();
        List<MedalmapsDO> medalmapsDOList = new ArrayList<>();

        for (QuestStatus qs : questStatusList) {
            QueststatusDO queststatusDO = new QueststatusDO();
            queststatusDO.setCharacterid(cid);
            queststatusDO.setQuest((int) qs.getQuest().getId());
            queststatusDO.setStatus(qs.getStatus().getId());
            queststatusDO.setTime((int) (qs.getCompletionTime() / 1000));
            queststatusDO.setExpires(qs.getExpirationTime());
            queststatusDO.setForfeited(qs.getForfeited());
            queststatusDO.setCompleted(qs.getCompleted());
            queststatusDO.setInfo(qs.getNpc());
            queststatusMapper.insert(queststatusDO); // Insert to get ID

            long questStatusId = queststatusDO.getQueststatusid();

            for (Map.Entry<Integer, String> entry : qs.getProgress().entrySet()) {
                QuestprogressDO questprogressDO = new QuestprogressDO();
                questprogressDO.setCharacterid(cid);
                questprogressDO.setQueststatusid(questStatusId);
                questprogressDO.setProgressid(entry.getKey());
                questprogressDO.setProgress(entry.getValue());
                questprogressDOList.add(questprogressDO);
            }

            for (int mapId : qs.getMedalMaps()) {
                MedalmapsDO medalmapsDO = new MedalmapsDO();
                medalmapsDO.setCharacterid(cid);
                medalmapsDO.setQueststatusid(questStatusId);
                medalmapsDO.setMapid(mapId);
                medalmapsDOList.add(medalmapsDO);
            }
        }

        if (!questprogressDOList.isEmpty()) {
            questprogressMapper.insertBatch(questprogressDOList);
        }
        if (!medalmapsDOList.isEmpty()) {
            medalmapsMapper.insertBatch(medalmapsDOList);
        }
    }

    /**
     * 从数据库加载指定角色的所有任务状态。
     *
     * @param cid 角色ID
     * @return 任务状态列表
     */
    public List<QuestStatus> getQuestStatusByCharacter(int cid) {
        List<QueststatusDO> queststatusDOList = queststatusMapper.selectListByQuery(QueryWrapper.create().where(QUESTSTATUS_DO.CHARACTERID.eq(cid)));
        List<QuestprogressDO> questprogressDOList = questprogressMapper.selectListByQuery(QueryWrapper.create().where(QUESTPROGRESS_DO.CHARACTERID.eq(cid)));
        List<MedalmapsDO> medalmapsDOList = medalmapsMapper.selectListByQuery(QueryWrapper.create().where(MEDALMAPS_DO.CHARACTERID.eq(cid)));

        return queststatusDOList.stream().map(queststatusDO -> {
            Quest quest = Quest.getInstance(queststatusDO.getQuest());
            QuestStatus questStatus = new QuestStatus(quest, QuestStatus.Status.getById(queststatusDO.getStatus()));
            if (queststatusDO.getTime() > -1) {
                questStatus.setCompletionTime(TimeUnit.SECONDS.toMillis(queststatusDO.getTime()));
            }
            if (queststatusDO.getExpires() > 0) {
                questStatus.setExpirationTime(queststatusDO.getExpires());
            }
            questStatus.setForfeited(queststatusDO.getForfeited());
            questStatus.setCompleted(queststatusDO.getCompleted());
            questStatus.setNpc(queststatusDO.getInfo());
            questprogressDOList.stream()
                    .filter(questprogressDO -> Objects.equals(queststatusDO.getQueststatusid(), questprogressDO.getQueststatusid()))
                    .forEach(questprogressDO -> questStatus.setProgress(questprogressDO.getProgressid(), String.valueOf(questprogressDO.getProgress())));
            medalmapsDOList.stream()
                    .filter(medalmapsDO -> Objects.equals(queststatusDO.getQueststatusid(), medalmapsDO.getQueststatusid()))
                    .forEach(medalmapsDO -> questStatus.addMedalMap(medalmapsDO.getMapid()));
            return questStatus;
        }).toList();
    }
}