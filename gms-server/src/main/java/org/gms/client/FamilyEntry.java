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
package org.gms.client;

import com.mybatisflex.core.query.QueryWrapper;
import com.mybatisflex.core.update.UpdateChain;
import org.gms.dao.entity.CharactersDO;
import org.gms.dao.entity.FamilyCharacterDO;
import org.gms.dao.entity.FamilyEntitlementDO;
import org.gms.dao.mapper.FamilyEntitlementMapper;
import org.gms.net.packet.Packet;
import org.gms.net.server.Server;
import org.gms.util.SpringContextUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.gms.util.PacketCreator;
import org.gms.util.Pair;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * @author Ubaware
 */

public class FamilyEntry {
    private static final Logger log = LoggerFactory.getLogger(FamilyEntry.class);

    private final int characterID;
    private volatile Family family;
    private volatile Character character;

    private volatile FamilyEntry senior;
    private final FamilyEntry[] juniors = new FamilyEntry[2];
    private final int[] entitlements = new int[11];
    private volatile int reputation, totalReputation;
    private volatile int todaysRep, repsToSenior; // 都是每日值
    private volatile int totalJuniors, totalSeniors;

    private volatile int generation;

    private volatile boolean repChanged; // 用于忽略保存未更改的声望值

    // 离线玩家的缓存值
    private String charName;
    private int level;
    private Job job;

    public FamilyEntry(Family family, int characterID, String charName, int level, Job job) {
        this.family = family;
        this.characterID = characterID;
        this.charName = charName;
        this.level = level;
        this.job = job;
    }

    public Character getChr() {
        return character;
    }

    public void setCharacter(Character newCharacter) {
        if (newCharacter == null) {
            cacheOffline(newCharacter);
        } else {
            newCharacter.setFamilyEntry(this);
        }
        this.character = newCharacter;
    }

    private void cacheOffline(Character chr) {
        if (chr != null) {
            charName = chr.getName();
            level = chr.getLevel();
            job = chr.getJob();
        }
    }

    public synchronized void join(FamilyEntry senior) {
        if (senior == null || getSenior() != null) {
            return;
        }
        Family oldFamily = getFamily();
        Family newFamily = senior.getFamily();

        // DB 事务前置——成功后才改内存（防止事务失败导致内存/DB 失同步）
        TransactionTemplate transactionTemplate = SpringContextUtil.getBean(TransactionTemplate.class);
        try {
            transactionTemplate.executeWithoutResult(status -> {
                try {
                    // 清除旧学院训言
                    UpdateChain.of(FamilyCharacterDO.class)
                            .set(FamilyCharacterDO::getPrecepts, (String) null)
                            .where(FamilyCharacterDO::getCid).eq(oldFamily.getLeader().getChrId())
                            .update();

                    boolean success = updateDBChangeFamily(getChrId(), newFamily.getID(), senior.getChrId());
                    for (FamilyEntry junior : juniors) {
                        if (junior != null) {
                            if (!junior.updateNewFamilyDB(newFamily.getID())) {
                                success = false;
                                break;
                            }
                        }
                    }
                    if (!success) {
                        status.setRollbackOnly();
                    }
                } catch (Exception e) {
                    status.setRollbackOnly();
                }
            });
        } catch (Exception e) {
            log.error("合并学院时无法连接到数据库", e);
            return;
        }

        // DB 事务成功——安全修改内存
        oldFamily.setMessage(null, false);
        setSenior(senior, false);
        addSeniorCount(newFamily.getTotalGenerations(), newFamily);
        newFamily.getLeader().doFullCount();
        newFamily.addEntryTree(this);
        Server.getInstance().getWorld(oldFamily.getWorld()).removeFamily(oldFamily.getID());
    }

    public synchronized void fork() {
        Family oldFamily = getFamily();
        FamilyEntry oldSenior = getSenior();

        // 先生成新学院 ID，再执行 DB 事务，成功后才改内存（防止事务失败导致内存/DB 失同步）
        Family newFamily = new Family(-1, oldFamily.getWorld());
        TransactionTemplate transactionTemplate = SpringContextUtil.getBean(TransactionTemplate.class);
        try {
            transactionTemplate.executeWithoutResult(status -> {
                try {
                    boolean success = updateDBChangeFamily(getChrId(), newFamily.getID(), 0);
                    for (FamilyEntry junior : juniors) {
                        if (junior != null) {
                            if (!junior.updateNewFamilyDB(newFamily.getID())) {
                                success = false;
                                break;
                            }
                        }
                    }
                    if (!success) {
                        status.setRollbackOnly();
                    }
                } catch (Exception e) {
                    status.setRollbackOnly();
                }
            });
        } catch (Exception e) {
            log.error("分离学院时无法连接到数据库", e);
            return;
        }

        // DB 事务成功——安全修改内存
        family = newFamily;
        Server.getInstance().getWorld(family.getWorld()).addFamily(family.getID(), family);
        if (character != null) {
            character.setFamilyId(family.getID());
        }
        setSenior(null, false);
        family.setLeader(this);
        addSeniorCount(-getTotalSeniors(), family);
        setTotalSeniors(0);
        if (oldSenior != null) {
            oldSenior.addJuniorCount(-getTotalJuniors());
            oldSenior.removeJunior(this);
            oldFamily.getLeader().doFullCount();
        }
        oldFamily.removeEntryBranch(this);
        family.addEntryTree(this);
        this.repsToSenior = 0;
        this.repChanged = true;
        family.setMessage("", true);
        doFullCount();
    }

    private synchronized boolean updateNewFamilyDB() {
        return updateNewFamilyDB(getFamily().getID());
    }

    private synchronized boolean updateNewFamilyDB(int newFamilyId) {
        if (!updateFamilyEntryDB(getChrId(), newFamilyId)) {
            return false;
        }
        if (!updateCharacterFamilyDB(getChrId(), newFamilyId, true)) {
            return false;
        }

        for (FamilyEntry junior : juniors) {
            if (junior != null) {
                if (!junior.updateNewFamilyDB(newFamilyId)) {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean updateFamilyEntryDB(int cid, int familyid) {
        try {
            UpdateChain.of(FamilyCharacterDO.class)
                    .set(FamilyCharacterDO::getFamilyid, familyid)
                    .where(FamilyCharacterDO::getCid).eq(cid)
                    .update();
        } catch (Exception e) {
            log.error("无法更新角色ID {} 在 'family_character' 表中的学院ID。(分离)", cid, e);
            return false;
        }
        return true;
    }

    private synchronized void addSeniorCount(int seniorCount, Family newFamily) { // 遍历树并减去老师数并更新学院
        if (newFamily != null) {
            this.family = newFamily;
        }
        setTotalSeniors(getTotalSeniors() + seniorCount);
        this.generation += seniorCount;
        for (FamilyEntry junior : juniors) {
            if (junior != null) {
                junior.addSeniorCount(seniorCount, newFamily);
            }
        }
    }

    public synchronized void addJuniorCount(int juniorCount) { // 爬树并增加晚辈计数
        setTotalJuniors(getTotalJuniors() + juniorCount);
        FamilyEntry senior = getSenior();
        if (senior != null) {
            senior.addJuniorCount(juniorCount);
        }
    }

    public Family getFamily() {
        return family;
    }

    public int getChrId() {
        return characterID;
    }

    public String getName() {
        Character chr = character;
        if (chr != null) {
            return chr.getName();
        } else {
            return charName;
        }
    }

    public int getLevel() {
        Character chr = character;
        if (chr != null) {
            return chr.getLevel();
        } else {
            return level;
        }
    }

    public Job getJob() {
        Character chr = character;
        if (chr != null) {
            return chr.getJob();
        } else {
            return job;
        }
    }

    public int getReputation() {
        return reputation;
    }

    public int getTodaysRep() {
        return todaysRep;
    }

    public void setReputation(int reputation) {
        if (reputation != this.reputation) {
            this.repChanged = true;
        }
        this.reputation = reputation;
    }

    public void setTodaysRep(int today) {
        if (today != todaysRep) {
            this.repChanged = true;
        }
        this.todaysRep = today;
    }

    public int getRepsToSenior() {
        return repsToSenior;
    }

    public void setRepsToSenior(int reputation) {
        if (reputation != this.repsToSenior) {
            this.repChanged = true;
        }
        this.repsToSenior = reputation;
    }

    public void gainReputation(int gain, boolean countTowardsTotal) {
        gainReputation(gain, countTowardsTotal, this);
    }

    private void gainReputation(int gain, boolean countTowardsTotal, FamilyEntry from) {
        if (gain != 0) {
            repChanged = true;
        }
        this.reputation += gain;
        this.todaysRep += gain;
        if (gain > 0 && countTowardsTotal) {
            this.totalReputation += gain;
        }
        Character chr = getChr();
        if (chr != null) {
            chr.sendPacket(PacketCreator.sendGainRep(gain, from != null ? from.getName() : ""));
        }
    }

    public void giveReputationToSenior(int gain, boolean includeSuperSenior) {
        int actualGain = gain;
        FamilyEntry senior = getSenior();
        if (senior != null && senior.getLevel() < getLevel() && gain > 0) {
            actualGain /= 2; // 不要减半负值
        }
        if (senior != null) {
            senior.gainReputation(actualGain, true, this);
            if (actualGain > 0) {
                this.repsToSenior += actualGain;
                this.repChanged = true;
            }
            if (includeSuperSenior) {
                senior = senior.getSenior();
                if (senior != null) {
                    senior.gainReputation(actualGain, true, this);
                }
            }
        }
    }

    public int getTotalReputation() {
        return totalReputation;
    }

    public void setTotalReputation(int totalReputation) {
        if (totalReputation != this.totalReputation) {
            this.repChanged = true;
        }
        this.totalReputation = totalReputation;
    }

    public FamilyEntry getSenior() {
        return senior;
    }

    private boolean isDescendant(FamilyEntry entry) {
        for (FamilyEntry junior : juniors) {
            if (junior != null) {
                if (junior == entry || junior.isDescendant(entry)) {
                    return true;
                }
            }
        }
        return false;
    }

    public synchronized boolean setSenior(FamilyEntry senior, boolean save) {
        if (this.senior == senior) {
            return false;
        }
        if (senior != null && (senior == this || isDescendant(senior))) {
            log.warn("检测到学院树循环: {} 不能成为 {} 的老师", senior.getName(), getName());
            return false;
        }
        FamilyEntry oldSenior = this.senior;
        this.senior = senior;
        if (senior != null) {
            if (senior.addJunior(this)) {
                if (save) {
                    updateDBChangeFamily(getChrId(), senior.getFamily().getID(), senior.getChrId());
                }
                if (this.repsToSenior != 0) {
                    this.repChanged = true;
                }
                this.repsToSenior = 0;
                this.addSeniorCount(1, null);
                this.setTotalSeniors(senior.getTotalSeniors() + 1);
                return true;
            }
        } else {
            if (oldSenior != null) {
                oldSenior.removeJunior(this);
            }
        }
        return false;
    }

    private static boolean updateDBChangeFamily(int cid, int familyid, int seniorid) {
        try {
            UpdateChain.of(FamilyCharacterDO.class)
                    .set(FamilyCharacterDO::getFamilyid, familyid)
                    .set(FamilyCharacterDO::getSeniorid, seniorid)
                    .set(FamilyCharacterDO::getReptosenior, 0)
                    .where(FamilyCharacterDO::getCid).eq(cid)
                    .update();
        } catch (Exception e) {
            log.error("无法更新角色ID {} 在 'family_character' 表中的老师ID", cid, e);
            return false;
        }
        return updateCharacterFamilyDB(cid, familyid, false);
    }

    private static boolean updateCharacterFamilyDB(int charid, int familyid, boolean fork) {
        try {
            UpdateChain.of(CharactersDO.class)
                    .set(CharactersDO::getFamilyId, familyid)
                    .where(CharactersDO::getId).eq(charid)
                    .update();
        } catch (Exception e) {
            log.error("更改学院时无法更新角色ID {} 在 'characters' 表中的学院ID。{}", charid, fork ? "(分离)" : "", e);
            return false;
        }
        return true;
    }

    public List<FamilyEntry> getJuniors() {
        return Collections.unmodifiableList(Arrays.asList(juniors));
    }

    public FamilyEntry getOtherJunior(FamilyEntry junior) {
        if (juniors[0] == junior) {
            return juniors[1];
        } else if (juniors[1] == junior) {
            return juniors[0];
        }
        return null;
    }

    public int getJuniorCount() { // 足够接近，对于多线程相对一致（结果并不重要）
        int juniorCount = 0;
        if (juniors[0] != null) {
            juniorCount++;
        }
        if (juniors[1] != null) {
            juniorCount++;
        }
        return juniorCount;
    }

    public synchronized boolean addJunior(FamilyEntry newJunior) {
        for (int i = 0; i < juniors.length; i++) {
            if (juniors[i] == null) { // 成功添加新晚辈到学院
                juniors[i] = newJunior;
                addJuniorCount(1);
                getFamily().addEntry(newJunior);
                return true;
            }
        }
        return false;
    }

    public synchronized boolean isJunior(FamilyEntry entry) { // 需要锁定，因为结果准确性至关重要
        if (juniors[0] == entry) {
            return true;
        } else {
            return juniors[1] == entry;
        }
    }

    public synchronized boolean removeJunior(FamilyEntry junior) {
        for (int i = 0; i < juniors.length; i++) {
            if (juniors[i] == junior) {
                juniors[i] = null;
                return true;
            }
        }
        return false;
    }

    public int getTotalSeniors() {
        return totalSeniors;
    }

    public void setTotalSeniors(int totalSeniors) {
        this.totalSeniors = totalSeniors;
    }

    public int getTotalJuniors() {
        return totalJuniors;
    }

    public void setTotalJuniors(int totalJuniors) {
        this.totalJuniors = totalJuniors;
    }

    public void announceToSenior(Packet packet, boolean includeSuperSenior) {
        FamilyEntry senior = getSenior();
        if (senior != null) {
            Character seniorChr = senior.getChr();
            if (seniorChr != null) {
                seniorChr.sendPacket(packet);
            }
            senior = senior.getSenior();
            if (includeSuperSenior && senior != null) {
                seniorChr = senior.getChr();
                if (seniorChr != null) {
                    seniorChr.sendPacket(packet);
                }
            }
        }
    }

    public void updateSeniorFamilyInfo(boolean includeSuperSenior) {
        FamilyEntry senior = getSenior();
        if (senior != null) {
            Character seniorChr = senior.getChr();
            if (seniorChr != null) {
                seniorChr.sendPacket(PacketCreator.getFamilyInfo(senior));
            }
            senior = senior.getSenior();
            if (includeSuperSenior && senior != null) {
                seniorChr = senior.getChr();
                if (seniorChr != null) {
                    seniorChr.sendPacket(PacketCreator.getFamilyInfo(senior));
                }
            }
        }
    }

    /**
     * 遍历整个学院树以更新老师/晚辈计数。在院长上调用。
     */
    public synchronized void doFullCount() {
        Pair<Integer, Integer> counts = this.traverseAndUpdateCounts(0);
        getFamily().setTotalGenerations(counts.getLeft() + 1);
    }

    private Pair<Integer, Integer> traverseAndUpdateCounts(int seniors) { // 递归可能会限制学院大小，但它应该能处理几千的深度
        setTotalSeniors(seniors);
        this.generation = seniors;
        int juniorCount = 0;
        int highestGeneration = this.generation;
        for (FamilyEntry entry : juniors) {
            if (entry != null) {
                Pair<Integer, Integer> counts = entry.traverseAndUpdateCounts(seniors + 1);
                juniorCount += counts.getRight(); // 总晚辈数
                if (counts.getLeft() > highestGeneration) {
                    highestGeneration = counts.getLeft();
                }
            }
        }
        setTotalJuniors(juniorCount);
        return new Pair<>(highestGeneration, juniorCount); // 创建新对象返回有点低效，但比打包成 long 更干净
    }

    public boolean useEntitlement(FamilyEntitlement entitlement) {
        int id = entitlement.ordinal();
        if (entitlements[id] >= 1) {
            return false;
        }
        FamilyEntitlementMapper mapper = SpringContextUtil.getBean(FamilyEntitlementMapper.class);
        FamilyEntitlementDO ent = new FamilyEntitlementDO();
        ent.setEntitlementid(id);
        ent.setCharid(getChrId());
        ent.setTimestamp(System.currentTimeMillis());
        if (mapper.insert(ent, true) > 0) {
            entitlements[id]++;
            return true;
        } else {
            log.error("无法为角色 {} 在 'family_entitlement' 表中插入新行", getName());
            return false;
        }
    }

    public boolean refundEntitlement(FamilyEntitlement entitlement) {
        int id = entitlement.ordinal();
        FamilyEntitlementMapper mapper = SpringContextUtil.getBean(FamilyEntitlementMapper.class);
        QueryWrapper query = QueryWrapper.create()
                .where(FamilyEntitlementDO::getEntitlementid).eq(id)
                .and(FamilyEntitlementDO::getCharid).eq(getChrId());
        if (mapper.deleteByQuery(query) > 0) {
            entitlements[id] = 0;
            return true;
        } else {
            log.error("无法为角色 {} 退还学院特权 \"{}\"", getName(), entitlement.getName());
            return false;
        }
    }

    public boolean isEntitlementUsed(FamilyEntitlement entitlement) {
        return entitlements[entitlement.ordinal()] >= 1;
    }

    public int getEntitlementUsageCount(FamilyEntitlement entitlement) {
        return entitlements[entitlement.ordinal()];
    }

    public void setEntitlementUsed(int id) {
        entitlements[id]++;
    }

    public void resetEntitlementUsages() {
        for (FamilyEntitlement entitlement : FamilyEntitlement.values()) {
            entitlements[entitlement.ordinal()] = 0;
        }
    }

    public boolean saveReputation() {
        if (!repChanged) {
            return true;
        }
        try {
            UpdateChain.of(FamilyCharacterDO.class)
                    .set(FamilyCharacterDO::getReputation, getReputation())
                    .set(FamilyCharacterDO::getTodaysrep, getTodaysRep())
                    .set(FamilyCharacterDO::getTotalreputation, getTotalReputation())
                    .set(FamilyCharacterDO::getReptosenior, getRepsToSenior())
                    .where(FamilyCharacterDO::getCid).eq(getChrId())
                    .update();
        } catch (Exception e) {
            log.error("无法自动保存角色ID {} 的声望到 'family_character' 表", getChrId(), e);
            return false;
        }
        return true;
    }

    public void savedSuccessfully() {
        this.repChanged = false;
    }
}
