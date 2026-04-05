package org.gms.service;

import com.mybatisflex.core.query.QueryWrapper;
import com.mybatisflex.core.row.Db;
import com.mybatisflex.core.row.Row;
import lombok.AllArgsConstructor;
import org.gms.client.inventory.Equip;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.dao.entity.InventoryitemsDO;
import org.gms.dao.entity.InventoryequipmentDO;
import org.gms.dao.entity.InventorymerchantDO;
import org.gms.dao.mapper.InventoryequipmentMapper;
import org.gms.dao.mapper.InventoryitemsMapper;
import org.gms.dao.mapper.InventorymerchantMapper;
import org.gms.util.Pair;
import org.gms.util.SnowflakeIdGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

import static org.gms.dao.entity.table.CharactersDOTableDef.CHARACTERS_D_O;
import static org.gms.dao.entity.table.InventoryequipmentDOTableDef.INVENTORYEQUIPMENT_D_O;
import static org.gms.dao.entity.table.InventoryitemsDOTableDef.INVENTORYITEMS_D_O;
import static org.gms.dao.entity.table.InventorymerchantDOTableDef.INVENTORYMERCHANT_D_O;

@Service
@AllArgsConstructor
public class ItemFactoryService {
    private static final Logger log = LoggerFactory.getLogger(ItemFactoryService.class);
    private final InventoryitemsMapper inventoryitemsMapper;
    private final InventoryequipmentMapper inventoryequipmentMapper;
    private final InventorymerchantMapper inventorymerchantMapper;
    private final TraceabilityService traceabilityService;

    public List<Pair<Item, InventoryType>> loadItems(int typeValue, boolean isAccount, int id, boolean login) {
        QueryWrapper query = QueryWrapper.create()
                .select(INVENTORYITEMS_D_O.ALL_COLUMNS, INVENTORYEQUIPMENT_D_O.ALL_COLUMNS)
                .from(INVENTORYITEMS_D_O)
                .leftJoin(INVENTORYEQUIPMENT_D_O).on(INVENTORYITEMS_D_O.INVENTORYITEMID.eq(INVENTORYEQUIPMENT_D_O.INVENTORYITEMID))
                .where(INVENTORYITEMS_D_O.TYPE.eq(typeValue));

        if (isAccount) {
            query.and(INVENTORYITEMS_D_O.ACCOUNTID.eq(id));
        } else {
            query.and(INVENTORYITEMS_D_O.CHARACTERID.eq(id));
        }

        if (login) {
            query.and(INVENTORYITEMS_D_O.INVENTORYTYPE.eq(InventoryType.EQUIPPED.getType()));
        }

        List<Row> rows = inventoryitemsMapper.selectRowsByQuery(query);
        List<Pair<Item, InventoryType>> items = new ArrayList<>();

        for (Row row : rows) {
            InventoryType mit = InventoryType.getByType((byte) getInt(row, "inventorytype"));
            Item item;
            if (mit.equals(InventoryType.EQUIP) || mit.equals(InventoryType.EQUIPPED)) {
                item = loadEquipFromRow(row);
            } else {
                int petid = getInt(row, "petid", -1);
                item = new Item(getInt(row, "itemid"), (byte) getInt(row, "position"), getShort(row, "quantity"), petid);
                item.setOwner(getString(row, "owner"));
                item.setExpiration(getLong(row, "expiration"));
                item.setGiftFrom(getString(row, "giftFrom"));
                item.setFlag(getShort(row, "flag"));
            }
            
            // 加载 UID
            Long uid = row.getLong("uid");
            if (uid != null && uid > 0) {
                item.setUid(uid);
            } else {
                item.setUid(SnowflakeIdGenerator.getInstance().nextId());
            }

            // 设置数据库 ID
            Long dbId = row.getLong("inventoryitemid");
            if (dbId != null) {
                item.setInventoryItemId(dbId);
            }
            
            item.setDirty(false); // 从数据库加载的物品初始状态为非脏
            items.add(new Pair<>(item, mit));
        }
        return items;
    }

    public List<Pair<Item, InventoryType>> loadItemsMerchant(int typeValue, int charId, boolean login) {
        QueryWrapper query = QueryWrapper.create()
                .select(INVENTORYITEMS_D_O.ALL_COLUMNS, INVENTORYEQUIPMENT_D_O.ALL_COLUMNS, INVENTORYMERCHANT_D_O.BUNDLES)
                .from(INVENTORYITEMS_D_O)
                .leftJoin(INVENTORYEQUIPMENT_D_O).on(INVENTORYITEMS_D_O.INVENTORYITEMID.eq(INVENTORYEQUIPMENT_D_O.INVENTORYITEMID))
                .leftJoin(INVENTORYMERCHANT_D_O).on(INVENTORYITEMS_D_O.INVENTORYITEMID.eq(INVENTORYMERCHANT_D_O.INVENTORYITEMID))
                .where(INVENTORYITEMS_D_O.TYPE.eq(typeValue))
                .and(INVENTORYITEMS_D_O.CHARACTERID.eq(charId));

        if (login) {
            query.and(INVENTORYITEMS_D_O.INVENTORYTYPE.eq(InventoryType.EQUIPPED.getType()));
        }

        List<Row> rows = inventoryitemsMapper.selectRowsByQuery(query);
        List<Pair<Item, InventoryType>> items = new ArrayList<>();

        for (Row row : rows) {
            short bundles = (short) getInt(row, "bundles");
            InventoryType mit = InventoryType.getByType((byte) getInt(row, "inventorytype"));

            Item item = null;
            if (mit.equals(InventoryType.EQUIP) || mit.equals(InventoryType.EQUIPPED)) {
                item = loadEquipFromRow(row);
            } else {
                if (bundles > 0) {
                    int petid = getInt(row, "petid", -1);
                    item = new Item(getInt(row, "itemid"), (byte) getInt(row, "position"), (short) (bundles * getInt(row, "quantity")), petid);
                    item.setOwner(getString(row, "owner"));
                    item.setExpiration(getLong(row, "expiration"));
                    item.setGiftFrom(getString(row, "giftFrom"));
                    item.setFlag(getShort(row, "flag"));
                }
            }
            
            if (item != null) {
                Long uid = row.getLong("uid");
                if (uid != null && uid > 0) {
                    item.setUid(uid);
                } else {
                    item.setUid(SnowflakeIdGenerator.getInstance().nextId());
                }

                Long dbId = row.getLong("inventoryitemid");
                if (dbId != null) {
                    item.setInventoryItemId(dbId);
                }
                
                item.setDirty(false);
                items.add(new Pair<>(item, mit));
            }
        }
        return items;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void saveItems(int typeValue, boolean isAccount, List<Pair<Item, InventoryType>> items, int id) {
        saveItems(typeValue, isAccount, items, id, null);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void saveItems(int typeValue, boolean isAccount, List<Pair<Item, InventoryType>> items, int id, Set<InventoryType> targetTypes) {
        String ownerIdentifier = isAccount ? "账号ID: " + id : "角色ID: " + id;
        String targetTypesStr = targetTypes == null ? "所有" : targetTypes.stream().map(Enum::name).collect(Collectors.joining(", "));
        //log.info("开始保存物品. 归属: {}, 存储类型: {}, 目标背包: {}", ownerIdentifier, typeValue, targetTypesStr);

        QueryWrapper selectQuery = QueryWrapper.create()
                .select(INVENTORYITEMS_D_O.INVENTORYITEMID, INVENTORYITEMS_D_O.UID)
                .where(INVENTORYITEMS_D_O.TYPE.eq(typeValue));
        if (isAccount) {
            selectQuery.and(INVENTORYITEMS_D_O.ACCOUNTID.eq(id));
        } else {
            selectQuery.and(INVENTORYITEMS_D_O.CHARACTERID.eq(id));
        }

        if (targetTypes != null && !targetTypes.isEmpty()) {
            List<Integer> typeCodes = targetTypes.stream().map(InventoryType::getType).map(Byte::intValue).collect(Collectors.toList());
            selectQuery.and(INVENTORYITEMS_D_O.INVENTORYTYPE.in(typeCodes));
        }

        List<InventoryitemsDO> existingItems = inventoryitemsMapper.selectListByQuery(selectQuery);
        Map<Long, Long> dbUidToIdMap = new HashMap<>();
        Set<Long> dbIds = new HashSet<>();
        
        for (InventoryitemsDO doc : existingItems) {
            dbIds.add(doc.getInventoryitemid());
            if (doc.getUid() != null && doc.getUid() > 0) {
                dbUidToIdMap.put(doc.getUid(), doc.getInventoryitemid());
            }
        }
        //log.info("数据库中存在 {} 个相关物品. DB ID 数量: {}, UID->ID 映射数量: {}", existingItems.size(), dbIds.size(), dbUidToIdMap.size());

        Set<Long> processedIds = new HashSet<>();

        if (items != null) {
            for (Pair<Item, InventoryType> pair : items) {
                Item item = pair.getLeft();
                InventoryType mit = pair.getRight();
                
                if (targetTypes != null && !targetTypes.isEmpty() && !targetTypes.contains(mit)) {
                    continue;
                }

                Long targetDbId = item.getInventoryItemId();
                
                if (targetDbId == null && item.getUid() > 0) {
                    targetDbId = dbUidToIdMap.get(item.getUid());
                    if (targetDbId != null) {
                        item.setInventoryItemId(targetDbId);
                    }
                }

                if (targetDbId != null && dbIds.contains(targetDbId)) {
                    // 更新
                    processedIds.add(targetDbId);

                    if (!item.isDirty()) {
                        continue; // 如果物品不是脏的，则跳过更新
                    }
                    //log.info("更新脏物品: DB ID={}, UID={}, ItemID={}", targetDbId, item.getUid(), item.getItemId());

                    InventoryitemsDO itemDO = new InventoryitemsDO();
                    itemDO.setInventoryitemid(targetDbId);
                    itemDO.setInventorytype((int) mit.getType());
                    itemDO.setPosition((int) item.getPosition());
                    itemDO.setQuantity((int) item.getQuantity());
                    itemDO.setOwner(item.getOwner() == null ? "" : item.getOwner());
                    itemDO.setPetid(item.getPetId());
                    itemDO.setFlag((int) item.getFlag());
                    itemDO.setExpiration(item.getExpiration());
                    itemDO.setGiftFrom(item.getGiftFrom() == null ? "" : item.getGiftFrom());

                    inventoryitemsMapper.update(itemDO);

                    if (mit.equals(InventoryType.EQUIP) || mit.equals(InventoryType.EQUIPPED)) {
                        Equip equip = (Equip) item;
                        InventoryequipmentDO equipDO = new InventoryequipmentDO();
                        equipDO.setUpgradeslots((int) equip.getUpgradeSlots());
                        equipDO.setLevel((int) equip.getLevel());
                        equipDO.setStr((int) equip.getStr());
                        equipDO.setDex((int) equip.getDex());
                        equipDO.setInte((int) equip.getInt());
                        equipDO.setLuk((int) equip.getLuk());
                        equipDO.setHp((int) equip.getHp());
                        equipDO.setMp((int) equip.getMp());
                        equipDO.setWatk((int) equip.getWatk());
                        equipDO.setMatk((int) equip.getMatk());
                        equipDO.setWdef((int) equip.getWdef());
                        equipDO.setMdef((int) equip.getMdef());
                        equipDO.setAcc((int) equip.getAcc());
                        equipDO.setAvoid((int) equip.getAvoid());
                        equipDO.setHands((int) equip.getHands());
                        equipDO.setSpeed((int) equip.getSpeed());
                        equipDO.setJump((int) equip.getJump());
                        equipDO.setLocked(0);
                        equipDO.setVicious((int) equip.getVicious());
                        equipDO.setItemlevel((int) equip.getItemLevel());
                        equipDO.setItemexp(equip.getItemExp());
                        equipDO.setRingid(equip.getRingId());

                        inventoryequipmentMapper.updateByQuery(equipDO,
                                QueryWrapper.create().where(INVENTORYEQUIPMENT_D_O.INVENTORYITEMID.eq(targetDbId)));
                    }
                    item.setDirty(false); // 更新成功后，重置脏标记
                } else {
                    // 插入或更新类型（跨类型移动）
                    Long existingGlobalId = null;
                    // [核心修复] 只对装备（不可堆叠物品）进行全局UID检查，防止消耗品堆叠拆分后出现数据覆盖
                    if (item instanceof Equip && item.getUid() > 0) {
                        existingGlobalId = inventoryitemsMapper.selectOneByQueryAs(
                                QueryWrapper.create().select(INVENTORYITEMS_D_O.INVENTORYITEMID)
                                        .where(INVENTORYITEMS_D_O.UID.eq(item.getUid())),
                                Long.class
                        );
                    }

                    if (existingGlobalId != null) {
                        //log.info("物品跨栏移动:ID={} UID={}, ItemID={}, 从其他Type移动到Type={}",item.getInventoryItemId(), item.getUid(), item.getItemId(), typeValue);
                        
                        QueryWrapper updateWrapper = QueryWrapper.create()
                                .where(INVENTORYITEMS_D_O.INVENTORYITEMID.eq(existingGlobalId));
                        
                        Row updates = new Row();
                        updates.set(INVENTORYITEMS_D_O.TYPE.getName(), typeValue);
                        updates.set(INVENTORYITEMS_D_O.INVENTORYTYPE.getName(), (int) mit.getType());
                        updates.set(INVENTORYITEMS_D_O.POSITION.getName(), (int) item.getPosition());
                        updates.set(INVENTORYITEMS_D_O.QUANTITY.getName(), (int) item.getQuantity());
                        
                        if (isAccount) {
                            updates.set(INVENTORYITEMS_D_O.ACCOUNTID.getName(), id);
                            updates.set(INVENTORYITEMS_D_O.CHARACTERID.getName(), null);
                        } else {
                            updates.set(INVENTORYITEMS_D_O.ACCOUNTID.getName(), null);
                            updates.set(INVENTORYITEMS_D_O.CHARACTERID.getName(), id);
                        }
                        
                        Db.updateByQuery(INVENTORYITEMS_D_O.getName(), updates, updateWrapper);
                        item.setInventoryItemId(existingGlobalId);
                        item.setDirty(false);
                    } else {
                        //log.info("插入新物品: UID={}, ItemID={}", item.getUid(), item.getItemId());
                        InventoryitemsDO itemDO = new InventoryitemsDO();
                        itemDO.setType(typeValue);
                        if (isAccount) {
                            itemDO.setAccountid(id);
                        } else {
                            itemDO.setCharacterid(id);
                        }
                        itemDO.setItemid(item.getItemId());
                        itemDO.setInventorytype((int) mit.getType());
                        itemDO.setPosition((int) item.getPosition());
                        itemDO.setQuantity((int) item.getQuantity());
                        itemDO.setOwner(item.getOwner() == null ? "" : item.getOwner());
                        itemDO.setPetid(item.getPetId());
                        itemDO.setFlag((int) item.getFlag());
                        itemDO.setExpiration(item.getExpiration());
                        itemDO.setGiftFrom(item.getGiftFrom() == null ? "" : item.getGiftFrom());
                        itemDO.setUid(item.getUid());

                        inventoryitemsMapper.insert(itemDO);
                        Long genKey = itemDO.getInventoryitemid();
                        item.setInventoryItemId(genKey);
                        //log.info("新物品插入成功: DB ID={}, UID={}, ItemID={}", genKey, item.getUid(), item.getItemId());

                        if (mit.equals(InventoryType.EQUIP) || mit.equals(InventoryType.EQUIPPED)) {
                            Equip equip = (Equip) item;
                            InventoryequipmentDO equipDO = new InventoryequipmentDO();
                            equipDO.setInventoryitemid(genKey);
                            equipDO.setUpgradeslots((int) equip.getUpgradeSlots());
                            equipDO.setLevel((int) equip.getLevel());
                            equipDO.setStr((int) equip.getStr());
                            equipDO.setDex((int) equip.getDex());
                            equipDO.setInte((int) equip.getInt());
                            equipDO.setLuk((int) equip.getLuk());
                            equipDO.setHp((int) equip.getHp());
                            equipDO.setMp((int) equip.getMp());
                            equipDO.setWatk((int) equip.getWatk());
                            equipDO.setMatk((int) equip.getMatk());
                            equipDO.setWdef((int) equip.getWdef());
                            equipDO.setMdef((int) equip.getMdef());
                            equipDO.setAcc((int) equip.getAcc());
                            equipDO.setAvoid((int) equip.getAvoid());
                            equipDO.setHands((int) equip.getHands());
                            equipDO.setSpeed((int) equip.getSpeed());
                            equipDO.setJump((int) equip.getJump());
                            equipDO.setLocked(0);
                            equipDO.setVicious((int) equip.getVicious());
                            equipDO.setItemlevel((int) equip.getItemLevel());
                            equipDO.setItemexp(equip.getItemExp());
                            equipDO.setRingid(equip.getRingId());

                            inventoryequipmentMapper.insert(equipDO);
                        }
                        item.setDirty(false);
                    }
                }
            }
        }

        List<Long> idsToDelete = new ArrayList<>();
        for (Long existingId : dbIds) {
            if (!processedIds.contains(existingId)) {
                idsToDelete.add(existingId);
            }
        }

        if (!idsToDelete.isEmpty()) {
            //log.info("准备删除 {} 个物品. DB IDs: {}", idsToDelete.size(), idsToDelete);
            
            inventoryequipmentMapper.deleteByQuery(QueryWrapper.create()
                    .where(INVENTORYEQUIPMENT_D_O.INVENTORYITEMID.in(idsToDelete)));
            
            inventorymerchantMapper.deleteByQuery(QueryWrapper.create()
                    .where(INVENTORYMERCHANT_D_O.INVENTORYITEMID.in(idsToDelete)));
            
            int deletedCount = inventoryitemsMapper.deleteByQuery(QueryWrapper.create()
                    .where(INVENTORYITEMS_D_O.INVENTORYITEMID.in(idsToDelete))
                    .and(INVENTORYITEMS_D_O.TYPE.eq(typeValue)));
            //log.info("从 inventoryitems 表中删除了 {} 条记录 (限定 Type={})", deletedCount, typeValue);
        }
        //log.info("物品保存完成. 归属: {}, 存储类型: {}", ownerIdentifier, typeValue);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void saveItemsMerchant(int typeValue, List<Pair<Item, InventoryType>> items, List<Short> bundlesList, int id) {
        QueryWrapper selectMerchantItemsQuery = QueryWrapper.create()
                .select(INVENTORYITEMS_D_O.INVENTORYITEMID, INVENTORYITEMS_D_O.UID)
                .where(INVENTORYITEMS_D_O.TYPE.eq(typeValue))
                .and(INVENTORYITEMS_D_O.CHARACTERID.eq(id));

        List<InventoryitemsDO> existingItems = inventoryitemsMapper.selectListByQuery(selectMerchantItemsQuery);
        Map<Long, Long> dbUidToIdMap = new HashMap<>();
        Set<Long> dbIds = new HashSet<>();
        
        for (InventoryitemsDO doc : existingItems) {
            dbIds.add(doc.getInventoryitemid());
            if (doc.getUid() != null && doc.getUid() > 0) {
                dbUidToIdMap.put(doc.getUid(), doc.getInventoryitemid());
            }
        }
        
        Set<Long> processedIds = new HashSet<>();

        if (items != null) {
            int i = 0;
            for (Pair<Item, InventoryType> pair : items) {
                Item item = pair.getLeft();
                Short bundles = bundlesList.get(i++);
                InventoryType mit = pair.getRight();
                
                Long targetDbId = item.getInventoryItemId();
                
                if (targetDbId == null && item.getUid() > 0) {
                    targetDbId = dbUidToIdMap.get(item.getUid());
                    if (targetDbId != null) {
                        item.setInventoryItemId(targetDbId);
                    }
                }

                if (targetDbId != null && dbIds.contains(targetDbId)) {
                    processedIds.add(targetDbId);

                    if (!item.isDirty()) {
                        continue;
                    }

                    InventoryitemsDO itemDO = new InventoryitemsDO();
                    itemDO.setInventoryitemid(targetDbId);
                    itemDO.setInventorytype((int) mit.getType());
                    itemDO.setPosition((int) item.getPosition());
                    itemDO.setQuantity((int) item.getQuantity());
                    itemDO.setOwner(item.getOwner() == null ? "" : item.getOwner());
                    itemDO.setPetid(item.getPetId());
                    itemDO.setFlag((int) item.getFlag());
                    itemDO.setExpiration(item.getExpiration());
                    itemDO.setGiftFrom(item.getGiftFrom() == null ? "" : item.getGiftFrom());
                    
                    inventoryitemsMapper.update(itemDO);

                    InventorymerchantDO merchantDO = new InventorymerchantDO();
                    merchantDO.setBundles(bundles.intValue());
                    inventorymerchantMapper.updateByQuery(merchantDO,
                            QueryWrapper.create().where(INVENTORYMERCHANT_D_O.INVENTORYITEMID.eq(targetDbId)));

                    if (mit.equals(InventoryType.EQUIP) || mit.equals(InventoryType.EQUIPPED)) {
                        Equip equip = (Equip) item;
                        InventoryequipmentDO equipDO = new InventoryequipmentDO();
                        equipDO.setUpgradeslots((int) equip.getUpgradeSlots());
                        equipDO.setLevel((int) equip.getLevel());
                        equipDO.setStr((int) equip.getStr());
                        equipDO.setDex((int) equip.getDex());
                        equipDO.setInte((int) equip.getInt());
                        equipDO.setLuk((int) equip.getLuk());
                        equipDO.setHp((int) equip.getHp());
                        equipDO.setMp((int) equip.getMp());
                        equipDO.setWatk((int) equip.getWatk());
                        equipDO.setMatk((int) equip.getMatk());
                        equipDO.setWdef((int) equip.getWdef());
                        equipDO.setMdef((int) equip.getMdef());
                        equipDO.setAcc((int) equip.getAcc());
                        equipDO.setAvoid((int) equip.getAvoid());
                        equipDO.setHands((int) equip.getHands());
                        equipDO.setSpeed((int) equip.getSpeed());
                        equipDO.setJump((int) equip.getJump());
                        equipDO.setLocked(0);
                        equipDO.setVicious((int) equip.getVicious());
                        equipDO.setItemlevel((int) equip.getItemLevel());
                        equipDO.setItemexp(equip.getItemExp());
                        equipDO.setRingid(equip.getRingId());

                        inventoryequipmentMapper.updateByQuery(equipDO,
                                QueryWrapper.create().where(INVENTORYEQUIPMENT_D_O.INVENTORYITEMID.eq(targetDbId)));
                    }
                    item.setDirty(false);
                } else {
                    if (item.getUid() > 0) {
                        QueryWrapper checkUidQuery = QueryWrapper.create()
                                .select(INVENTORYITEMS_D_O.INVENTORYITEMID)
                                .where(INVENTORYITEMS_D_O.UID.eq(item.getUid()));

                        Long existingId = inventoryitemsMapper.selectOneByQueryAs(checkUidQuery, Long.class);
                        if (existingId != null) {
                            log.error("发现重复 UID 物品入库尝试 (雇佣商人)! UID: {}, ItemID: {}, OwnerID: {}, Type: {}",
                                    item.getUid(), item.getItemId(), id, typeValue);
                            traceabilityService.log(item, null, TraceabilityService.ActionType.SYSTEM, TraceabilityService.ActionSourceType.SYSTEM_DELETE, 0, "因重复 UID 阻止雇佣商人保存", "Type: " + typeValue);
                            continue;
                        }
                    }

                    InventoryitemsDO itemDO = new InventoryitemsDO();
                    itemDO.setType(typeValue);
                    itemDO.setCharacterid(id);
                    itemDO.setItemid(item.getItemId());
                    itemDO.setInventorytype((int) mit.getType());
                    itemDO.setPosition((int) item.getPosition());
                    itemDO.setQuantity((int) item.getQuantity());
                    itemDO.setOwner(item.getOwner() == null ? "" : item.getOwner());
                    itemDO.setPetid(item.getPetId());
                    itemDO.setFlag((int) item.getFlag());
                    itemDO.setExpiration(item.getExpiration());
                    itemDO.setGiftFrom(item.getGiftFrom() == null ? "" : item.getGiftFrom());
                    itemDO.setUid(item.getUid());

                    inventoryitemsMapper.insert(itemDO);
                    Long genKey = itemDO.getInventoryitemid();
                    item.setInventoryItemId(genKey);

                    InventorymerchantDO merchantDO = new InventorymerchantDO();
                    merchantDO.setInventoryitemid(genKey);
                    merchantDO.setCharacterid(id);
                    merchantDO.setBundles(bundles.intValue());
                    inventorymerchantMapper.insert(merchantDO);

                    if (mit.equals(InventoryType.EQUIP) || mit.equals(InventoryType.EQUIPPED)) {
                        Equip equip = (Equip) item;
                        InventoryequipmentDO equipDO = new InventoryequipmentDO();
                        equipDO.setInventoryitemid(genKey);
                        equipDO.setUpgradeslots((int) equip.getUpgradeSlots());
                        equipDO.setLevel((int) equip.getLevel());
                        equipDO.setStr((int) equip.getStr());
                        equipDO.setDex((int) equip.getDex());
                        equipDO.setInte((int) equip.getInt());
                        equipDO.setLuk((int) equip.getLuk());
                        equipDO.setHp((int) equip.getHp());
                        equipDO.setMp((int) equip.getMp());
                        equipDO.setWatk((int) equip.getWatk());
                        equipDO.setMatk((int) equip.getMatk());
                        equipDO.setWdef((int) equip.getWdef());
                        equipDO.setMdef((int) equip.getMdef());
                        equipDO.setAcc((int) equip.getAcc());
                        equipDO.setAvoid((int) equip.getAvoid());
                        equipDO.setHands((int) equip.getHands());
                        equipDO.setSpeed((int) equip.getSpeed());
                        equipDO.setJump((int) equip.getJump());
                        equipDO.setLocked(0);
                        equipDO.setVicious((int) equip.getVicious());
                        equipDO.setItemlevel((int) equip.getItemLevel());
                        equipDO.setItemexp(equip.getItemExp());
                        equipDO.setRingid(equip.getRingId());

                        inventoryequipmentMapper.insert(equipDO);
                    }
                    item.setDirty(false);
                }
            }
        }

        List<Long> idsToDelete = new ArrayList<>();
        for (Long existingId : dbIds) {
            if (!processedIds.contains(existingId)) {
                idsToDelete.add(existingId);
            }
        }

        if (!idsToDelete.isEmpty()) {
            inventoryequipmentMapper.deleteByQuery(QueryWrapper.create().where(INVENTORYEQUIPMENT_D_O.INVENTORYITEMID.in(idsToDelete)));
            inventorymerchantMapper.deleteByQuery(QueryWrapper.create().where(INVENTORYMERCHANT_D_O.INVENTORYITEMID.in(idsToDelete)));
            inventoryitemsMapper.deleteByQuery(QueryWrapper.create().where(INVENTORYITEMS_D_O.INVENTORYITEMID.in(idsToDelete)));
        }
    }

    public List<Pair<Item, Integer>> loadEquippedItems(int id, boolean isAccount, boolean login) {
        QueryWrapper query = QueryWrapper.create()
                .select(INVENTORYITEMS_D_O.ALL_COLUMNS, INVENTORYEQUIPMENT_D_O.ALL_COLUMNS, CHARACTERS_D_O.ID.as("characterid"))
                .from(CHARACTERS_D_O)
                .rightJoin(INVENTORYITEMS_D_O).on(CHARACTERS_D_O.ID.eq(INVENTORYITEMS_D_O.CHARACTERID))
                .leftJoin(INVENTORYEQUIPMENT_D_O).on(INVENTORYITEMS_D_O.INVENTORYITEMID.eq(INVENTORYEQUIPMENT_D_O.INVENTORYITEMID));

        if (isAccount) {
            query.where(CHARACTERS_D_O.ACCOUNTID.eq(id));
        } else {
            query.where(CHARACTERS_D_O.ID.eq(id));
        }

        if (login) {
            query.and(INVENTORYITEMS_D_O.INVENTORYTYPE.eq(InventoryType.EQUIPPED.getType()));
        }

        List<Row> rows = inventoryitemsMapper.selectRowsByQuery(query);
        List<Pair<Item, Integer>> items = new ArrayList<>();

        for (Row row : rows) {
            Integer cid = row.getInt("characterid");
            Equip equip = loadEquipFromRow(row);
            
            Long uid = row.getLong("uid");
            if (uid != null && uid > 0) {
                equip.setUid(uid);
            } else {
                equip.setUid(SnowflakeIdGenerator.getInstance().nextId());
            }

            Long dbId = row.getLong("inventoryitemid");
            if (dbId != null) {
                equip.setInventoryItemId(dbId);
            }
            
            equip.setDirty(false);
            items.add(new Pair<>(equip, cid));
        }
        return items;
    }

    private Equip loadEquipFromRow(Row row) {
        Equip equip = new Equip(getInt(row, "itemid"), (short) getInt(row, "position"));
        equip.setOwner(getString(row, "owner"));
        equip.setQuantity(getShort(row, "quantity"));
        equip.setAcc(getShort(row, "acc"));
        equip.setAvoid(getShort(row, "avoid"));
        equip.setDex(getShort(row, "dex"));
        equip.setHands(getShort(row, "hands"));
        equip.setHp(getShort(row, "hp"));
        equip.setInt(getShort(row, "int"));
        equip.setJump(getShort(row, "jump"));
        equip.setVicious(getShort(row, "vicious"));
        equip.setFlag(getShort(row, "flag"));
        equip.setLuk(getShort(row, "luk"));
        equip.setMatk(getShort(row, "matk"));
        equip.setMdef(getShort(row, "mdef"));
        equip.setMp(getShort(row, "mp"));
        equip.setSpeed(getShort(row, "speed"));
        equip.setStr(getShort(row, "str"));
        equip.setWatk(getShort(row, "watk"));
        equip.setWdef(getShort(row, "wdef"));
        
        equip.setUpgradeSlots((byte) getInt(row, "upgradeslots"));
        equip.setLevel((short) getInt(row, "level"));
        equip.setItemExp(getInt(row, "itemexp"));
        equip.setItemLevel((short) getInt(row, "itemlevel"));

        equip.setExpiration(getLong(row, "expiration"));
        equip.setGiftFrom(getString(row, "giftFrom"));
        equip.setRingId(getInt(row, "ringid", -1));
        return equip;
    }

    private short getShort(Row row, String column) {
        Integer val = row.getInt(column);
        return val != null ? val.shortValue() : 0;
    }

    private int getInt(Row row, String column) {
        return getInt(row, column, 0);
    }

    private int getInt(Row row, String column, int def) {
        Integer val = row.getInt(column);
        return val != null ? val : def;
    }

    private long getLong(Row row, String column) {
        Long val = row.getLong(column);
        return val != null ? val : -1;
    }

    private String getString(Row row, String column) {
        String val = row.getString(column);
        return val != null ? val : "";
    }
}
