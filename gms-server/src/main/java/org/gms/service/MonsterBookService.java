package org.gms.service;

import com.mybatisflex.core.query.QueryWrapper;
import lombok.AllArgsConstructor;
import org.gms.dao.entity.MonsterbookDO;
import org.gms.dao.entity.MonstercarddataDO;
import org.gms.dao.mapper.MonsterbookMapper;
import org.gms.dao.mapper.MonstercarddataMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.mybatisflex.core.query.QueryMethods.count;
import static com.mybatisflex.core.query.QueryMethods.floor;
import static org.gms.dao.entity.table.MonsterbookDOTableDef.MONSTERBOOK_D_O;
import static org.gms.dao.entity.table.MonstercarddataDOTableDef.MONSTERCARDDATA_D_O;

@Service
@AllArgsConstructor
public class MonsterBookService {
    private final MonsterbookMapper monsterbookMapper;
    private final MonstercarddataMapper monstercarddataMapper;

    public List<MonsterbookDO> getByCharacterId(int cid) {
        return monsterbookMapper.selectListByQuery(QueryWrapper.create().where(MONSTERBOOK_D_O.CHARID.eq(cid)).orderBy(MONSTERBOOK_D_O.CHARID, true));
    }

    @Transactional
    public void saveCards(int chrId, Map<Integer, Integer> cards) {
        // 先删除该角色的所有卡片，然后批量插入
        monsterbookMapper.deleteByQuery(QueryWrapper.create().where(MONSTERBOOK_D_O.CHARID.eq(chrId)));

        List<MonsterbookDO> list = new ArrayList<>();
        for (Map.Entry<Integer, Integer> entry : cards.entrySet()) {
            MonsterbookDO entity = new MonsterbookDO();
            entity.setCharid(chrId);
            entity.setCardid(entry.getKey());
            entity.setLevel(entry.getValue());
            list.add(entity);
        }
        if (!list.isEmpty()) {
            monsterbookMapper.insertBatch(list);
        }
    }

    public int[] getCardTierSize() {
        // SELECT COUNT(*) FROM monstercarddata GROUP BY floor(cardid / 1000);
        QueryWrapper query = QueryWrapper.create()
                .select(count(MONSTERCARDDATA_D_O.ID))
                .from(MONSTERCARDDATA_D_O)
                .groupBy(floor(MONSTERCARDDATA_D_O.CARDID.divide(1000)));
        
        List<Integer> counts = monstercarddataMapper.selectObjectListByQueryAs(query, Integer.class);
        
        int[] tierSizes = new int[counts.size()];
        for (int i = 0; i < counts.size(); i++) {
            tierSizes[i] = counts.get(i);
        }
        return tierSizes;
    }
}
