package org.gms.service;

import com.mybatisflex.core.paginate.Page;
import com.mybatisflex.core.query.QueryWrapper;
import lombok.AllArgsConstructor;
import org.gms.client.Character;
import org.gms.dao.entity.MonsterbookDO;
import org.gms.dao.mapper.MonsterbookMapper;
import org.gms.dao.mapper.MonstercarddataMapper;
import org.gms.model.dto.*;
import org.gms.net.server.Server;
import org.gms.net.server.world.World;
import org.gms.server.life.MonsterInformationProvider;
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

    public Page<MonsterBookRtnDTO> search(MonsterBookSearchReqDTO req) {
        // 1. 尝试从在线玩家中获取数据
        if (req.getCharIds() != null && req.getCharIds().size() == 1) {
            int charId = req.getCharIds().get(0);
            Character onlineChr = null;
            for (World world : Server.getInstance().getWorlds()) {
                onlineChr = world.getPlayerStorage().getCharacterById(charId);
                if (onlineChr != null) break;
            }

            if (onlineChr != null) {
                // 构造内存数据分页
                Map<Integer, Integer> cards = onlineChr.getMonsterBook().getCards();
                List<MonsterBookRtnDTO> list = new ArrayList<>();
                for (Map.Entry<Integer, Integer> entry : cards.entrySet()) {
                    MonsterBookRtnDTO dto = new MonsterBookRtnDTO();
                    dto.setCharid(charId);
                    dto.setCardid(entry.getKey());
                    dto.setLevel(entry.getValue());
                    list.add(dto);
                }
                
                // 内存分页处理
                int pageNo = req.getPageNo() != null ? req.getPageNo() : 1;
                int pageSize = req.getPageSize() != null ? req.getPageSize() : 10;
                int total = list.size();
                int fromIndex = (pageNo - 1) * pageSize;
                int toIndex = Math.min(fromIndex + pageSize, total);
                
                List<MonsterBookRtnDTO> pageList = new ArrayList<>();
                if (fromIndex < total) {
                    pageList = list.subList(fromIndex, toIndex);
                }
                
                // 填充名称
                fillCardNames(pageList);
                
                return new Page<>(pageList, pageNo, pageSize, total);
            }
        }

        // 2. 离线查询或批量查询
        QueryWrapper query = QueryWrapper.create();
        if (req.getCharIds() != null && !req.getCharIds().isEmpty()) {
            query.where(MONSTERBOOK_D_O.CHARID.in(req.getCharIds()));
        }
        query.orderBy(MONSTERBOOK_D_O.CHARID, true);
        
        int pageNo = req.getPageNo() != null ? req.getPageNo() : 1;
        int pageSize = req.getPageSize() != null ? req.getPageSize() : 10;
        
        Page<MonsterBookRtnDTO> page = monsterbookMapper.paginateAs(Page.of(pageNo, pageSize), query, MonsterBookRtnDTO.class);
        
        if (page.getRecords() != null) {
            fillCardNames(page.getRecords());
        }
        
        return page;
    }
    
    private void fillCardNames(List<MonsterBookRtnDTO> list) {
        for (MonsterBookRtnDTO record : list) {
            int cardId = record.getCardid();
            Integer mobId = MonsterInformationProvider.getInstance().getMobByCardId(cardId);
            if (mobId != null && mobId > 0) {
                String mobName = MonsterInformationProvider.getInstance().getMobNameFromId(mobId);
                record.setCardName(mobName);
            } else {
                record.setCardName("Unknown Card (" + cardId + ")");
            }
        }
    }

    @Transactional
    public void batchDelete(MonsterBookBatchDeleteReqDTO req) {
        if (req.getItems() == null || req.getItems().isEmpty()) {
            return;
        }
        for (MonsterbookDO item : req.getItems()) {
            Character chr = null;
            for (World world : Server.getInstance().getWorlds()) {
                chr = world.getPlayerStorage().getCharacterById(item.getCharid());
                if (chr != null) break;
            }
            
            if (chr != null) {
                chr.getMonsterBook().modifyCard(chr.getClient(), item.getCardid(), 0);
            } else {
                monsterbookMapper.deleteByQuery(QueryWrapper.create()
                        .where(MONSTERBOOK_D_O.CHARID.eq(item.getCharid()))
                        .and(MONSTERBOOK_D_O.CARDID.eq(item.getCardid())));
            }
        }
    }

    @Transactional
    public void batchAdd(MonsterBookBatchAddReqDTO req) {
        if (req.getItems() == null || req.getItems().isEmpty()) {
            return;
        }
        for (MonsterbookDO item : req.getItems()) {
            Character chr = null;
            for (World world : Server.getInstance().getWorlds()) {
                chr = world.getPlayerStorage().getCharacterById(item.getCharid());
                if (chr != null) break;
            }

            if (chr != null) {
                chr.getMonsterBook().modifyCard(chr.getClient(), item.getCardid(), item.getLevel());
            } else {
                // 离线：检查是否存在，存在则更新，不存在则插入
                MonsterbookDO existing = monsterbookMapper.selectOneByQuery(QueryWrapper.create()
                        .where(MONSTERBOOK_D_O.CHARID.eq(item.getCharid()))
                        .and(MONSTERBOOK_D_O.CARDID.eq(item.getCardid())));
                
                if (existing != null) {
                    existing.setLevel(item.getLevel());
                    monsterbookMapper.update(existing);
                } else {
                    monsterbookMapper.insert(item);
                }
            }
        }
    }

    @Transactional
    public void batchUpdate(MonsterBookBatchUpdateReqDTO req) {
        if (req.getItems() == null || req.getItems().isEmpty()) {
            return;
        }
        for (MonsterBookUpdateItemDTO item : req.getItems()) {
            Character chr = null;
            for (World world : Server.getInstance().getWorlds()) {
                chr = world.getPlayerStorage().getCharacterById(item.getOldCharId());
                if (chr != null) break;
            }

            if (chr != null) {
                // 在线更新：先删除旧的（如果卡片ID变了），再添加新的
                if (!item.getOldCardId().equals(item.getNewCardId())) {
                    chr.getMonsterBook().modifyCard(chr.getClient(), item.getOldCardId(), 0);
                }
                chr.getMonsterBook().modifyCard(chr.getClient(), item.getNewCardId(), item.getNewLevel());
            } else {
                // 离线更新
                // 如果卡片ID变了，先删除旧的
                if (!item.getOldCardId().equals(item.getNewCardId())) {
                    monsterbookMapper.deleteByQuery(QueryWrapper.create()
                            .where(MONSTERBOOK_D_O.CHARID.eq(item.getOldCharId()))
                            .and(MONSTERBOOK_D_O.CARDID.eq(item.getOldCardId())));
                }
                
                // 检查新卡片是否存在
                MonsterbookDO existing = monsterbookMapper.selectOneByQuery(QueryWrapper.create()
                        .where(MONSTERBOOK_D_O.CHARID.eq(item.getOldCharId()))
                        .and(MONSTERBOOK_D_O.CARDID.eq(item.getNewCardId())));

                if (existing != null) {
                    existing.setLevel(item.getNewLevel());
                    monsterbookMapper.update(existing);
                } else {
                    MonsterbookDO newItem = new MonsterbookDO();
                    newItem.setCharid(item.getOldCharId());
                    newItem.setCardid(item.getNewCardId());
                    newItem.setLevel(item.getNewLevel());
                    monsterbookMapper.insert(newItem);
                }
            }
        }
    }

    @Transactional
    public void transfer(MonsterBookTransferReqDTO req) {
        if (req.getItems() == null || req.getItems().isEmpty() || req.getNewCharId() == null) {
            return;
        }
        for (MonsterbookDO item : req.getItems()) {
            // 处理源角色（删除）
            Character srcChr = null;
            for (World world : Server.getInstance().getWorlds()) {
                srcChr = world.getPlayerStorage().getCharacterById(item.getCharid());
                if (srcChr != null) break;
            }

            if (srcChr != null) {
                srcChr.getMonsterBook().modifyCard(srcChr.getClient(), item.getCardid(), 0);
            } else {
                monsterbookMapper.deleteByQuery(QueryWrapper.create()
                        .where(MONSTERBOOK_D_O.CHARID.eq(item.getCharid()))
                        .and(MONSTERBOOK_D_O.CARDID.eq(item.getCardid())));
            }

            // 处理目标角色（添加）
            Character targetChr = null;
            for (World world : Server.getInstance().getWorlds()) {
                targetChr = world.getPlayerStorage().getCharacterById(req.getNewCharId());
                if (targetChr != null) break;
            }

            if (targetChr != null) {
                targetChr.getMonsterBook().modifyCard(targetChr.getClient(), item.getCardid(), item.getLevel());
            } else {
                // 离线：检查是否存在
                MonsterbookDO existing = monsterbookMapper.selectOneByQuery(QueryWrapper.create()
                        .where(MONSTERBOOK_D_O.CHARID.eq(req.getNewCharId()))
                        .and(MONSTERBOOK_D_O.CARDID.eq(item.getCardid())));

                if (existing != null) {
                    existing.setLevel(item.getLevel());
                    monsterbookMapper.update(existing);
                } else {
                    MonsterbookDO newItem = new MonsterbookDO();
                    newItem.setCharid(req.getNewCharId());
                    newItem.setCardid(item.getCardid());
                    newItem.setLevel(item.getLevel());
                    monsterbookMapper.insert(newItem);
                }
            }
        }
    }
}
