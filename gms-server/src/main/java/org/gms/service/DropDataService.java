package org.gms.service;

import com.mybatisflex.core.query.QueryWrapper;
import lombok.AllArgsConstructor;
import org.gms.dao.entity.DropDataDO;
import org.gms.dao.mapper.DropDataMapper;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

import static org.gms.dao.entity.table.DropDataDOTableDef.DROP_DATA_DO;

@Service
@AllArgsConstructor
public class DropDataService {

    private final DropDataMapper dropDataMapper;

    public List<Integer> getWhoDrops(int itemId) {
        QueryWrapper queryWrapper = QueryWrapper.create()
                .select(DROP_DATA_DO.DROPPERID)
                .from(DROP_DATA_DO)
                .where(DROP_DATA_DO.ITEMID.eq(itemId))
                .limit(50);
        return dropDataMapper.selectListByQueryAs(queryWrapper, Integer.class);
    }
}
