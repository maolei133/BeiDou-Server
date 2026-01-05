package org.gms.service;

import com.mybatisflex.core.query.QueryWrapper;
import lombok.AllArgsConstructor;
import org.gms.dao.entity.MarriagesDO;
import org.gms.dao.entity.PlayernpcsFieldDO;
import org.gms.dao.mapper.MarriagesMapper;
import org.gms.dao.mapper.PlayernpcsFieldMapper;
import org.gms.util.Pair;
import org.springframework.stereotype.Service;

import static org.gms.dao.entity.table.MarriagesDOTableDef.MARRIAGES_D_O;
import static org.gms.dao.entity.table.PlayernpcsFieldDOTableDef.PLAYERNPCS_FIELD_D_O;

@Service
@AllArgsConstructor
public class WorldService {

    private final MarriagesMapper marriagesMapper;
    private final PlayernpcsFieldMapper playernpcsFieldMapper;

    public Pair<Integer, Pair<Integer, Integer>> getRelationshipCoupleFromDb(int id, boolean usingMarriageId) {
        QueryWrapper queryWrapper = QueryWrapper.create().from(MARRIAGES_D_O);
        if (usingMarriageId) {
            queryWrapper.where(MARRIAGES_D_O.MARRIAGEID.eq(id));
        } else {
            queryWrapper.where(MARRIAGES_D_O.HUSBANDID.eq(id)).or(MARRIAGES_D_O.WIFEID.eq(id));
        }
        MarriagesDO marriagesDO = marriagesMapper.selectOneByQuery(queryWrapper);
        if (marriagesDO == null) {
            return null;
        }
        return new Pair<>(marriagesDO.getMarriageid(), new Pair<>(marriagesDO.getHusbandid(), marriagesDO.getWifeid()));
    }

    public int addRelationshipToDb(int groomId, int brideId) {
        MarriagesDO marriagesDO = new MarriagesDO();
        marriagesDO.setHusbandid(groomId);
        marriagesDO.setWifeid(brideId);
        marriagesMapper.insert(marriagesDO);
        return marriagesDO.getMarriageid();
    }

    public void deleteRelationshipFromDb(int marriageId) {
        marriagesMapper.deleteById(marriageId);
    }

    public void executePlayerNpcMapDataUpdate(boolean isPodium, boolean exists, int value, int worldId, int mapId) {
        PlayernpcsFieldDO playernpcsFieldDO = new PlayernpcsFieldDO();
        if (isPodium) {
            playernpcsFieldDO.setPodium(value);
        } else {
            playernpcsFieldDO.setStep(value);
        }

        if (exists) {
            QueryWrapper queryWrapper = QueryWrapper.create()
                    .from(PLAYERNPCS_FIELD_D_O)
                    .where(PLAYERNPCS_FIELD_D_O.WORLD.eq(worldId))
                    .and(PLAYERNPCS_FIELD_D_O.MAP.eq(mapId));
            playernpcsFieldMapper.updateByQuery(playernpcsFieldDO, queryWrapper);
        } else {
            playernpcsFieldDO.setWorld(worldId);
            playernpcsFieldDO.setMap(mapId);
            if (!isPodium) { // podium has a default value
                playernpcsFieldDO.setPodium(1);
            }
            playernpcsFieldMapper.insert(playernpcsFieldDO);
        }
    }
}
