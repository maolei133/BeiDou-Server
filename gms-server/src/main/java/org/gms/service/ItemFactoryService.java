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
                // 延迟生成：如果数据库中缺少 UID，则生成一个新的
                // 注意：这个新的 UID 不会立即持久化回数据库，
                // 但会在物品保存时（例如注销或地图更改时）进行持久化
                item.setUid(SnowflakeIdGenerator.getInstance().nextId());
            }

            // 设置数据库 ID
            Long dbId = row.getLong("inventoryitemid");
            if (dbId != null) {
                item.setInventoryItemId(dbId);
            }
            
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

                items.add(new Pair<>(item, mit));
            }
        }
        return items;
    }

    /**
     * 保存物品到数据库 (增量更新) - 全量保存入口
     *
     * @param typeValue 物品存储位置类型 (1: 背包, 2: 仓库, 3: 商城, 4: 雇佣商人, 5: 结婚礼物, 6: 快递)
     * @param isAccount 是否关联到账号 (true: 关联账号, false: 关联角色)
     * @param items     要保存的物品列表，包含物品对象和库存类型
     * @param id        账号ID或角色ID (取决于 isAccount)
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void saveItems(int typeValue, boolean isAccount, List<Pair<Item, InventoryType>> items, int id) {
        saveItems(typeValue, isAccount, items, id, null);
    }

    /**
     * 保存物品到数据库 (增量更新) - 核心逻辑
     *
     * @param typeValue 物品存储位置类型 (1: 背包, 2: 仓库, 3: 商城, 4: 雇佣商人, 5: 结婚礼物, 6: 快递)
     * @param isAccount 是否关联到账号 (true: 关联账号, false: 关联角色)
     * @param items     要保存的物品列表，包含物品对象和库存类型
     * @param id        账号ID或角色ID (取决于 isAccount)
     * @param targetTypes 需要保存的背包类型集合，如果为null或空则保存所有类型
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void saveItems(int typeValue, boolean isAccount, List<Pair<Item, InventoryType>> items, int id, Set<InventoryType> targetTypes) {
        // 1. 获取数据库中已存在的物品信息 (ID 和 UID)
        QueryWrapper selectQuery = QueryWrapper.create()
                .select(INVENTORYITEMS_D_O.INVENTORYITEMID, INVENTORYITEMS_D_O.UID)
                .where(INVENTORYITEMS_D_O.TYPE.eq(typeValue));
        if (isAccount) {
            selectQuery.and(INVENTORYITEMS_D_O.ACCOUNTID.eq(id));
        } else {
            selectQuery.and(INVENTORYITEMS_D_O.CHARACTERID.eq(id));
        }

        // [关键修复] 限制查询范围
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

        Set<Long> processedIds = new HashSet<>();

        if (items != null) {
            for (Pair<Item, InventoryType> pair : items) {
                Item item = pair.getLeft();
                InventoryType mit = pair.getRight();
                
                // 如果指定了 targetTypes，则只处理属于这些类型的物品
                if (targetTypes != null && !targetTypes.isEmpty() && !targetTypes.contains(mit)) {
                    continue;
                }

                Long targetDbId = item.getInventoryItemId();
                
                // 如果内存中没有DB ID，尝试通过UID找回
                if (targetDbId == null && item.getUid() > 0) {
                    targetDbId = dbUidToIdMap.get(item.getUid());
                    if (targetDbId != null) {
                        item.setInventoryItemId(targetDbId);
                    }
                }

                if (targetDbId != null && dbIds.contains(targetDbId)) {
                    // 更新
                    processedIds.add(targetDbId);

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
                    // UID 不更新，保持原样

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
                } else {
                    // 插入或更新类型（跨类型移动）
                    
                    // 1. 检查全局 UID 是否存在 (处理跨栏移动，如商城->背包)
                    Long existingGlobalId = null;
                    if (item.getUid() > 0) {
                        existingGlobalId = inventoryitemsMapper.selectOneByQueryAs(
                                QueryWrapper.create().select(INVENTORYITEMS_D_O.INVENTORYITEMID)
                                        .where(INVENTORYITEMS_D_O.UID.eq(item.getUid())),
                                Long.class
                        );
                    }

                    if (existingGlobalId != null) {
                        // 发现 UID 存在，说明是跨 type 移动！
                        // 执行 UPDATE type 操作，将该物品“抢”过来
                        
                        // [关键修复] 跨类型移动时，必须同时更新归属权 (accountid/characterid)
                        // 使用 Db.updateByQuery 来确保可以更新为 null 值
                        
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
                        
                        // 执行更新
                        Db.updateByQuery(INVENTORYITEMS_D_O.getName(), updates, updateWrapper);
                        
                        // 更新内存中的 ID，防止后续误判
                        item.setInventoryItemId(existingGlobalId);
                        
                        // 记录日志
//                        log.info("物品跨栏移动: UID={}, OldType=?, NewType={}", item.getUid(), typeValue);
                    } else {
                        // 真的不存在 -> 插入
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
                        item.setInventoryItemId(genKey); // 更新内存对象

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
                    }
                }
            }
        }

        // 删除
        List<Long> idsToDelete = new ArrayList<>();
        for (Long existingId : dbIds) {
            if (!processedIds.contains(existingId)) {
                idsToDelete.add(existingId);
            }
        }

        if (!idsToDelete.isEmpty()) {
            // [关键修复] 删除时必须加上 type 条件，防止误删已经被转移到其他 type 的物品
            // 例如：物品从商城(type=3)转到背包(type=1)。
            // 背包保存时执行了 UPDATE type=1。
            // 商城保存时，发现物品不在内存了，准备 DELETE。
            // 如果不加 type=3 条件，就会把刚刚变成 type=1 的物品删掉！
            
            inventoryequipmentMapper.deleteByQuery(QueryWrapper.create()
                    .where(INVENTORYEQUIPMENT_D_O.INVENTORYITEMID.in(idsToDelete)));
            
            // 注意：inventorymerchant 表通常只关联 type=6 (雇佣商人) 或 type=5 (拍卖行)，
            // 但为了安全起见，这里也应该级联删除。
            inventorymerchantMapper.deleteByQuery(QueryWrapper.create()
                    .where(INVENTORYMERCHANT_D_O.INVENTORYITEMID.in(idsToDelete)));
            
            inventoryitemsMapper.deleteByQuery(QueryWrapper.create()
                    .where(INVENTORYITEMS_D_O.INVENTORYITEMID.in(idsToDelete))
                    .and(INVENTORYITEMS_D_O.TYPE.eq(typeValue))); // 必须加上 type 条件！
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void saveItemsMerchant(int typeValue, List<Pair<Item, InventoryType>> items, List<Short> bundlesList, int id) {
        // 1. 获取数据库中已存在的物品信息
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
                    // 更新
                    processedIds.add(targetDbId);

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
                } else {
                    // 插入
                    // 检查重复 UID
                    if (item.getUid() > 0) {
                        QueryWrapper checkUidQuery = QueryWrapper.create()
                                .select(INVENTORYITEMS_D_O.INVENTORYITEMID)
                                .where(INVENTORYITEMS_D_O.UID.eq(item.getUid()));

                        Long existingId = inventoryitemsMapper.selectOneByQueryAs(checkUidQuery, Long.class);
                        if (existingId != null) {
                            log.error("发现重复 UID 物品入库尝试 (雇佣商人)! UID: {}, ItemID: {}, OwnerID: {}, Type: {}",
                                    item.getUid(), item.getItemId(), id, typeValue);
                            traceabilityService.log(item, null, TraceabilityService.ActionType.ADMIN_DELETE,
                                    "DUPLICATE_UID_BLOCKED", 0, "因重复 UID 阻止雇佣商人保存", "Type: " + typeValue);
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
                }
            }
        }

        // 删除
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
            
            // 加载 UID
            Long uid = row.getLong("uid");
            if (uid != null && uid > 0) {
                equip.setUid(uid);
            } else {
                equip.setUid(SnowflakeIdGenerator.getInstance().nextId());
            }

            // 设置数据库 ID
            Long dbId = row.getLong("inventoryitemid");
            if (dbId != null) {
                equip.setInventoryItemId(dbId);
            }
            
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
        equip.setInt(getShort(row, "inte")); // <-- 改回从 "inte" 列读取
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
        equip.setLevel((byte) getInt(row, "level"));
        equip.setItemExp(getInt(row, "itemexp"));
        equip.setItemLevel((byte) getInt(row, "itemlevel"));

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
