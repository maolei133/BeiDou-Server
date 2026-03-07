package org.gms.service;

import com.mybatisflex.core.query.QueryWrapper;
import lombok.AllArgsConstructor;
import org.gms.client.Family;
import org.gms.client.FamilyEntry;
import org.gms.client.Job;
import org.gms.dao.entity.CharactersDO;
import org.gms.dao.entity.FamilyCharacterDO;
import org.gms.dao.entity.FamilyEntitlementDO;
import org.gms.dao.mapper.FamilyCharacterMapper;
import org.gms.dao.mapper.FamilyEntitlementMapper;
import org.gms.net.server.Server;
import org.gms.net.server.world.World;
import org.gms.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

import static org.gms.dao.entity.table.FamilyEntitlementDOTableDef.FAMILY_ENTITLEMENT_D_O;

@Service
@AllArgsConstructor
public class FamilyService {
    private static final Logger log = LoggerFactory.getLogger(FamilyService.class);

    private final FamilyCharacterMapper familyCharacterMapper;
    private final FamilyEntitlementMapper familyEntitlementMapper;
    private final CharacterService characterService;

    public void loadAllFamilies() {
        List<FamilyCharacterDO> familyCharacterDOList = familyCharacterMapper.selectAll();
        List<Pair<Integer, FamilyEntry>> unmatchedJuniors = new ArrayList<>(); // <<world, seniorid> familyEntry>
        for (FamilyCharacterDO familyCharacterDO : familyCharacterDOList) {
            CharactersDO charactersDO = characterService.findById(familyCharacterDO.getCid());
            if (charactersDO == null) {
                continue;
            }
            World world = Server.getInstance().getWorld(charactersDO.getWorld());
            if (world == null) {
                continue;
            }
            Family family = world.getFamily(familyCharacterDO.getFamilyid());
            if (family == null) {
                family = new Family(familyCharacterDO.getFamilyid(), charactersDO.getWorld());
                world.addFamily(familyCharacterDO.getFamilyid(), family);
            }
            FamilyEntry familyEntry = new FamilyEntry(family, charactersDO.getId(), charactersDO.getName(),
                    charactersDO.getLevel(), Job.getById(charactersDO.getJob()));
            familyEntry.setReputation(familyCharacterDO.getReputation());
            familyEntry.setTodaysRep(familyCharacterDO.getTodaysrep());
            familyEntry.setTotalReputation(familyCharacterDO.getTotalreputation());
            familyEntry.setRepsToSenior(familyCharacterDO.getReptosenior());
            family.addEntry(familyEntry);
            if (familyCharacterDO.getSeniorid() <= 0) {
                family.setLeader(familyEntry);
                family.setMessage(familyCharacterDO.getPrecepts(), false);
            }
            FamilyEntry senior = family.getEntryByID(familyCharacterDO.getSeniorid());
            if (senior != null) {
                familyEntry.setSenior(senior, false);
            } else if (familyCharacterDO.getSeniorid() > 0) {
                unmatchedJuniors.add(new Pair<>(familyCharacterDO.getSeniorid(), familyEntry));
            }
            List<FamilyEntitlementDO> familyEntitlementDOList = familyEntitlementMapper.selectListByQuery(QueryWrapper.create()
                    .select(FAMILY_ENTITLEMENT_D_O.ENTITLEMENTID)
                    .from(FAMILY_ENTITLEMENT_D_O)
                    .where(FAMILY_ENTITLEMENT_D_O.CHARID.eq(charactersDO.getId())));
            familyEntitlementDOList.forEach(familyEntitlementDO -> familyEntry.setEntitlementUsed(familyEntitlementDO.getEntitlementid()));
        }
        for (Pair<Integer, FamilyEntry> unmatchedJunior : unmatchedJuniors) {
            FamilyEntry senior = Server.getInstance()
                    .getWorld(unmatchedJunior.getRight().getFamily().getWorld())
                    .getFamily(unmatchedJunior.getRight().getFamily().getID())
                    .getEntryByID(unmatchedJunior.getLeft());
            if (senior != null) {
                unmatchedJunior.getRight().setSenior(senior, false);
            }
        }
        for (World world : Server.getInstance().getWorlds()) {
            for (Family family : world.getFamilies()) {
                // 如果学院没有院长(领袖)，并且学院里有成员
                if (family.getLeader() == null && !family.getMembers().isEmpty()) {
                    // 将第一位成员设为新院长
                    FamilyEntry newLeader = family.getMembers().iterator().next();
                    family.setLeader(newLeader);

                    // 更新数据库，将新院长的seniorid设为0
                    FamilyCharacterDO newLeaderDO = new FamilyCharacterDO();
                    newLeaderDO.setCid(newLeader.getChrId());
                    newLeaderDO.setSeniorid(0);
                    familyCharacterMapper.update(newLeaderDO, true);
                    
                    log.info("学院 {} 没有院长，已自动指派 {} 为新院长。", family.getID(), newLeader.getName());
                }

                if (family.getLeader() != null) {
                    family.getLeader().doFullCount();
                }
            }
        }
    }
}
