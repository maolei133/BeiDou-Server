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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

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
        // 1. 从数据库加载旧的卡片
        List<MonsterbookDO> dbCards = monsterbookMapper.selectListByQuery(
            QueryWrapper.create().where(MONSTERBOOK_D_O.CHARID.eq(chrId))
        );
        Map<Integer, MonsterbookDO> dbMap = dbCards.stream()
            .collect(Collectors.toMap(MonsterbookDO::getCardid, Function.identity()));

        List<MonsterbookDO> toInsert = new ArrayList<>();
        List<MonsterbookDO> toUpdate = new ArrayList<>();

        // 2. 比较并找出需要新增和更新的
        for (Map.Entry<Integer, Integer> entry : cards.entrySet()) {
            Integer cardId = entry.getKey();
            Integer level = entry.getValue();

            MonsterbookDO dbCard = dbMap.get(cardId);
            if (dbCard != null) {
                // 存在，检查是否需要更新
                if (!dbCard.getLevel().equals(level)) {
                    dbCard.setLevel(level);
                    toUpdate.add(dbCard);
                }
            } else {
                // 不存在，需要新增
                toInsert.add(MonsterbookDO.builder().charid(chrId).cardid(cardId).level(level).build());
            }
        }

        // 3. 找出需要删除的
        List<MonsterbookDO> toDelete = dbCards.stream()
            .filter(dbCard -> !cards.containsKey(dbCard.getCardid()))
            .collect(Collectors.toList());

        // 4. 执行数据库操作
        if (!toDelete.isEmpty()) {
            // 因为是复合主键，循环删除是当前最稳妥的方式
            for (MonsterbookDO item : toDelete) {
                monsterbookMapper.delete(item);
            }
        }

        if (!toUpdate.isEmpty()) {
            // 改回循环单次更新，这是最直接且不会出错的方式
            for (MonsterbookDO item : toUpdate) {
                monsterbookMapper.update(item);
            }
        }

        if (!toInsert.isEmpty()) {
            monsterbookMapper.insertBatch(toInsert);
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

    public Page<MonsterBookDTO.Rtn> search(MonsterBookDTO.SearchReq req) {
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
                List<MonsterBookDTO.Rtn> list = new ArrayList<>();
                for (Map.Entry<Integer, Integer> entry : cards.entrySet()) {
                    MonsterBookDTO.Rtn dto = new MonsterBookDTO.Rtn();
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
                
                List<MonsterBookDTO.Rtn> pageList = new ArrayList<>();
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
        
        Page<MonsterBookDTO.Rtn> page = monsterbookMapper.paginateAs(Page.of(pageNo, pageSize), query, MonsterBookDTO.Rtn.class);
        
        if (page.getRecords() != null) {
            fillCardNames(page.getRecords());
        }
        
        return page;
    }
    
    private void fillCardNames(List<MonsterBookDTO.Rtn> list) {
        for (MonsterBookDTO.Rtn record : list) {
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
    public void batchDelete(MonsterBookDTO.BatchDeleteReq req) {
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
    public void batchAdd(MonsterBookDTO.BatchAddReq req) {
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
    public void batchUpdate(MonsterBookDTO.BatchUpdateReq req) {
        if (req.getItems() == null || req.getItems().isEmpty()) {
            return;
        }
        for (MonsterBookDTO.UpdateItem item : req.getItems()) {
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
    public void transfer(MonsterBookDTO.TransferReq req) {
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

    public Map<Integer, String> getCardNames(MonsterBookDTO.SearchReq req) {
        Map<Integer, String> result = new HashMap<>();
        if (req.getCardIds() == null || req.getCardIds().isEmpty()) {
            return result;
        }

        for (Integer cardId : req.getCardIds()) {
            Integer mobId = MonsterInformationProvider.getInstance().getMobByCardId(cardId);
            if (mobId != null && mobId > 0) {
                String mobName = MonsterInformationProvider.getInstance().getMobNameFromId(mobId);
                result.put(cardId, mobName);
            } else {
                result.put(cardId, "Unknown Card (" + cardId + ")");
            }
        }
        return result;
    }
}
