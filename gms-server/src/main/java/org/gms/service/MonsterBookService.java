package org.gms.service;

import com.mybatisflex.core.query.QueryWrapper;
import lombok.AllArgsConstructor;
import org.gms.dao.entity.MonsterbookDO;
import org.gms.dao.mapper.MonsterbookMapper;
import org.springframework.stereotype.Service;

import java.util.List;

import static org.gms.dao.entity.table.MonsterbookDOTableDef.MONSTERBOOK_DO;

@Service
@AllArgsConstructor
public class MonsterBookService {
    private final MonsterbookMapper monsterbookMapper;

    public List<MonsterbookDO> getByCharacterId(int cid) {
        return monsterbookMapper.selectListByQuery(QueryWrapper.create().where(MONSTERBOOK_DO.CHARID.eq(cid)).orderBy(MONSTERBOOK_DO.CHARID, true));
    }
}
