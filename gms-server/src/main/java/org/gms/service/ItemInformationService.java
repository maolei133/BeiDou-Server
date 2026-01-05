package org.gms.service;

import com.mybatisflex.core.query.QueryWrapper;
import lombok.AllArgsConstructor;
import org.gms.dao.entity.DropDataDO;
import org.gms.dao.entity.MakercreatedataDO;
import org.gms.dao.entity.MakerreagentdataDO;
import org.gms.dao.entity.MakerrecipedataDO;
import org.gms.dao.entity.MonstercarddataDO;
import org.gms.dao.mapper.DropDataMapper;
import org.gms.dao.mapper.MakercreatedataMapper;
import org.gms.dao.mapper.MakerreagentdataMapper;
import org.gms.dao.mapper.MakerrecipedataMapper;
import org.gms.dao.mapper.MonstercarddataMapper;
import org.gms.util.Pair;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.gms.dao.entity.table.DropDataDOTableDef.DROP_DATA_D_O;
import static org.gms.dao.entity.table.MakercreatedataDOTableDef.MAKERCREATEDATA_D_O;
import static org.gms.dao.entity.table.MakerreagentdataDOTableDef.MAKERREAGENTDATA_D_O;
import static org.gms.dao.entity.table.MakerrecipedataDOTableDef.MAKERRECIPEDATA_D_O;
import static org.gms.dao.entity.table.MonstercarddataDOTableDef.MONSTERCARDDATA_D_O;

@Service
@AllArgsConstructor
public class ItemInformationService {

    private final MonstercarddataMapper monstercarddataMapper;
    private final MakerreagentdataMapper makerreagentdataMapper;
    private final DropDataMapper dropDataMapper;
    private final MakercreatedataMapper makercreatedataMapper;
    private final MakerrecipedataMapper makerrecipedataMapper;

    public Map<Integer, Integer> loadCardIdData() {
        Map<Integer, Integer> monsterBookID = new HashMap<>();
        List<MonstercarddataDO> list = monstercarddataMapper.selectListByQuery(QueryWrapper.create().select(MONSTERCARDDATA_D_O.CARDID, MONSTERCARDDATA_D_O.MOBID));
        for (MonstercarddataDO data : list) {
            monsterBookID.put(data.getCardid(), data.getMobid());
        }
        return monsterBookID;
    }

    public Pair<String, Integer> getMakerReagentStatUpgrade(int itemId) {
        MakerreagentdataDO data = makerreagentdataMapper.selectOneByQuery(QueryWrapper.create()
                .select(MAKERREAGENTDATA_D_O.STAT, MAKERREAGENTDATA_D_O.VALUE)
                .where(MAKERREAGENTDATA_D_O.ITEMID.eq(itemId)));
        if (data != null) {
            return new Pair<>(data.getStat(), data.getValue());
        }
        return null;
    }

    public List<Integer> getMakerCrystalFromLeftover(int leftoverId) {
        return dropDataMapper.selectListByQueryAs(QueryWrapper.create()
                .select(DROP_DATA_D_O.DROPPERID)
                .where(DROP_DATA_D_O.ITEMID.eq(leftoverId))
                .orderBy(DROP_DATA_D_O.DROPPERID.asc()), Integer.class);
    }

    public MakercreatedataDO getMakerItemEntry(int toCreate) {
        return makercreatedataMapper.selectOneByQuery(QueryWrapper.create()
                .select(MAKERCREATEDATA_D_O.REQ_LEVEL, MAKERCREATEDATA_D_O.REQ_MAKER_LEVEL, MAKERCREATEDATA_D_O.REQ_MESO, MAKERCREATEDATA_D_O.QUANTITY)
                .where(MAKERCREATEDATA_D_O.ITEMID.eq(toCreate)));
    }

    public List<Pair<Integer, Integer>> getMakerItemRecipe(int toCreate) {
        List<MakerrecipedataDO> list = makerrecipedataMapper.selectListByQuery(QueryWrapper.create()
                .select(MAKERRECIPEDATA_D_O.REQ_ITEM, MAKERRECIPEDATA_D_O.COUNT)
                .where(MAKERRECIPEDATA_D_O.ITEMID.eq(toCreate)));
        List<Pair<Integer, Integer>> result = new LinkedList<>();
        for (MakerrecipedataDO data : list) {
            result.add(new Pair<>(data.getReqItem(), data.getCount()));
        }
        return result;
    }

    public List<Pair<Integer, Integer>> getMakerDisassembledItems(int itemId) {
        List<MakerrecipedataDO> list = makerrecipedataMapper.selectListByQuery(QueryWrapper.create()
                .select(MAKERRECIPEDATA_D_O.REQ_ITEM, MAKERRECIPEDATA_D_O.COUNT)
                .where(MAKERRECIPEDATA_D_O.ITEMID.eq(itemId))
                .and(MAKERRECIPEDATA_D_O.REQ_ITEM.ge(4260000))
                .and(MAKERRECIPEDATA_D_O.REQ_ITEM.lt(4270000)));
        List<Pair<Integer, Integer>> result = new LinkedList<>();
        for (MakerrecipedataDO data : list) {
            result.add(new Pair<>(data.getReqItem(), data.getCount() / 2));
        }
        return result;
    }

    public Integer getMakerDisassembledFee(int itemId) {
        MakercreatedataDO data = makercreatedataMapper.selectOneByQuery(QueryWrapper.create()
                .select(MAKERCREATEDATA_D_O.REQ_MESO)
                .where(MAKERCREATEDATA_D_O.ITEMID.eq(itemId)));
        if (data != null) {
            return data.getReqMeso();
        }
        return null;
    }

    public List<Integer> getWhoDrops(int itemId) {
        return dropDataMapper.selectListByQueryAs(QueryWrapper.create()
                .select(DROP_DATA_D_O.DROPPERID)
                .where(DROP_DATA_D_O.ITEMID.eq(itemId))
                .limit(50), Integer.class);
    }
}
