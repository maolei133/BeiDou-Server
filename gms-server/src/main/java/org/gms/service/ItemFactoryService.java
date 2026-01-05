package org.gms.service;

import com.mybatisflex.core.query.QueryWrapper;
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
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

import static org.gms.dao.entity.table.CharactersDOTableDef.CHARACTERS_D_O;
import static org.gms.dao.entity.table.InventoryequipmentDOTableDef.INVENTORYEQUIPMENT_D_O;
import static org.gms.dao.entity.table.InventoryitemsDOTableDef.INVENTORYITEMS_D_O;
import static org.gms.dao.entity.table.InventorymerchantDOTableDef.INVENTORYMERCHANT_D_O;

@Service
@AllArgsConstructor
public class ItemFactoryService {
    private final InventoryitemsMapper inventoryitemsMapper;
    private final InventoryequipmentMapper inventoryequipmentMapper;
    private final InventorymerchantMapper inventorymerchantMapper;

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
            if (mit.equals(InventoryType.EQUIP) || mit.equals(InventoryType.EQUIPPED)) {
                items.add(new Pair<>(loadEquipFromRow(row), mit));
            } else {
                int petid = getInt(row, "petid", -1);
                Item item = new Item(getInt(row, "itemid"), (byte) getInt(row, "position"), getShort(row, "quantity"), petid);
                item.setOwner(getString(row, "owner"));
                item.setExpiration(getLong(row, "expiration"));
                item.setGiftFrom(getString(row, "giftFrom"));
                item.setFlag(getShort(row, "flag"));
                items.add(new Pair<>(item, mit));
            }
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

            if (mit.equals(InventoryType.EQUIP) || mit.equals(InventoryType.EQUIPPED)) {
                items.add(new Pair<>(loadEquipFromRow(row), mit));
            } else {
                if (bundles > 0) {
                    int petid = getInt(row, "petid", -1);
                    Item item = new Item(getInt(row, "itemid"), (byte) getInt(row, "position"), (short) (bundles * getInt(row, "quantity")), petid);
                    item.setOwner(getString(row, "owner"));
                    item.setExpiration(getLong(row, "expiration"));
                    item.setGiftFrom(getString(row, "giftFrom"));
                    item.setFlag(getShort(row, "flag"));
                    items.add(new Pair<>(item, mit));
                }
            }
        }
        return items;
    }

    @Transactional
    public void saveItems(int typeValue, boolean isAccount, List<Pair<Item, InventoryType>> items, int id) {
        QueryWrapper selectQuery = QueryWrapper.create()
                .select(INVENTORYITEMS_D_O.INVENTORYITEMID)
                .where(INVENTORYITEMS_D_O.TYPE.eq(typeValue));
        if (isAccount) {
            selectQuery.and(INVENTORYITEMS_D_O.ACCOUNTID.eq(id));
        } else {
            selectQuery.and(INVENTORYITEMS_D_O.CHARACTERID.eq(id));
        }
        
        List<Long> itemIdsToDelete = inventoryitemsMapper.selectListByQueryAs(selectQuery, Long.class);
        
        if (!itemIdsToDelete.isEmpty()) {
            inventoryequipmentMapper.deleteByQuery(QueryWrapper.create().where(INVENTORYEQUIPMENT_D_O.INVENTORYITEMID.in(itemIdsToDelete)));
            
            QueryWrapper deleteQuery = QueryWrapper.create()
                    .where(INVENTORYITEMS_D_O.TYPE.eq(typeValue));
            if (isAccount) {
                deleteQuery.and(INVENTORYITEMS_D_O.ACCOUNTID.eq(id));
            } else {
                deleteQuery.and(INVENTORYITEMS_D_O.CHARACTERID.eq(id));
            }
            inventoryitemsMapper.deleteByQuery(deleteQuery);
        }

        if (items == null || items.isEmpty()) {
            return;
        }

        for (Pair<Item, InventoryType> pair : items) {
            Item item = pair.getLeft();
            InventoryType mit = pair.getRight();

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
            itemDO.setOwner(item.getOwner());
            itemDO.setPetid(item.getPetId());
            itemDO.setFlag((int) item.getFlag());
            itemDO.setExpiration(item.getExpiration());
            itemDO.setGiftFrom(item.getGiftFrom());

            inventoryitemsMapper.insert(itemDO);
            Long genKey = itemDO.getInventoryitemid();

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

    @Transactional
    public void saveItemsMerchant(int typeValue, List<Pair<Item, InventoryType>> items, List<Short> bundlesList, int id) {
        inventorymerchantMapper.deleteByQuery(QueryWrapper.create().where(INVENTORYMERCHANT_D_O.CHARACTERID.eq(id)));

        QueryWrapper selectQuery = QueryWrapper.create()
                .select(INVENTORYITEMS_D_O.INVENTORYITEMID)
                .where(INVENTORYITEMS_D_O.TYPE.eq(typeValue))
                .and(INVENTORYITEMS_D_O.CHARACTERID.eq(id));
        
        List<Long> itemIdsToDelete = inventoryitemsMapper.selectListByQueryAs(selectQuery, Long.class);
        if (!itemIdsToDelete.isEmpty()) {
            inventoryequipmentMapper.deleteByQuery(QueryWrapper.create().where(INVENTORYEQUIPMENT_D_O.INVENTORYITEMID.in(itemIdsToDelete)));
            
            QueryWrapper deleteQuery = QueryWrapper.create()
                    .where(INVENTORYITEMS_D_O.TYPE.eq(typeValue))
                    .and(INVENTORYITEMS_D_O.CHARACTERID.eq(id));
            inventoryitemsMapper.deleteByQuery(deleteQuery);
        }

        if (items == null || items.isEmpty()) {
            return;
        }

        int i = 0;
        for (Pair<Item, InventoryType> pair : items) {
            Item item = pair.getLeft();
            Short bundles = bundlesList.get(i++);
            InventoryType mit = pair.getRight();

            InventoryitemsDO itemDO = new InventoryitemsDO();
            itemDO.setType(typeValue);
            itemDO.setCharacterid(id);
            itemDO.setItemid(item.getItemId());
            itemDO.setInventorytype((int) mit.getType());
            itemDO.setPosition((int) item.getPosition());
            itemDO.setQuantity((int) item.getQuantity());
            itemDO.setOwner(item.getOwner());
            itemDO.setPetid(item.getPetId());
            itemDO.setFlag((int) item.getFlag());
            itemDO.setExpiration(item.getExpiration());
            itemDO.setGiftFrom(item.getGiftFrom());

            inventoryitemsMapper.insert(itemDO);
            Long genKey = itemDO.getInventoryitemid();

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
            items.add(new Pair<>(loadEquipFromRow(row), cid));
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
        equip.setInt(getShort(row, "inte"));
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