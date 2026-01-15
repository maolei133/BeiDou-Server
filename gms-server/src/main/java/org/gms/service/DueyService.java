package org.gms.service;

import com.mybatisflex.core.paginate.Page;
import com.mybatisflex.core.query.QueryWrapper;
import com.mybatisflex.core.row.Db;
import com.mybatisflex.core.row.Row;
import lombok.AllArgsConstructor;
import org.gms.client.inventory.Equip;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.ItemFactory;
import org.gms.config.GameConfig;
import org.gms.dao.entity.CharactersDO;
import org.gms.dao.entity.DueypackagesDO;
import org.gms.dao.mapper.CharactersMapper;
import org.gms.dao.mapper.DueypackagesMapper;
import org.gms.model.dto.DueyPackageRtnDTO;
import org.gms.model.dto.DueySearchReqDTO;
import org.gms.model.dto.ItemInfoRtnDTO;
import org.gms.model.dto.SendDueyReqDTO;
import org.gms.server.ItemInformationProvider;
import org.gms.util.Pair;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.gms.dao.entity.table.CharactersDOTableDef.CHARACTERS_D_O;
import static org.gms.dao.entity.table.DueypackagesDOTableDef.DUEYPACKAGES_D_O;

@Service
@AllArgsConstructor
public class DueyService {

    private final DueypackagesMapper dueypackagesMapper;
    private final CharactersMapper charactersMapper;
    private final ItemFactoryService itemFactoryService;

    public Page<DueyPackageRtnDTO> getDueyList(DueySearchReqDTO req) {
        QueryWrapper query = QueryWrapper.create()
                .select(DUEYPACKAGES_D_O.ALL_COLUMNS, CHARACTERS_D_O.NAME.as("receiverName"))
                .from(DUEYPACKAGES_D_O)
                .leftJoin(CHARACTERS_D_O).on(DUEYPACKAGES_D_O.RECEIVERID.eq(CHARACTERS_D_O.ID));

        if (req.getReceiverName() != null && !req.getReceiverName().isEmpty()) {
            query.where(CHARACTERS_D_O.NAME.like(req.getReceiverName()));
        }
        if (req.getSenderName() != null && !req.getSenderName().isEmpty()) {
            query.where(DUEYPACKAGES_D_O.SENDERNAME.like(req.getSenderName()));
        }
        if (req.getStartTime() != null) {
            query.where(DUEYPACKAGES_D_O.TIMESTAMP.ge(new Timestamp(req.getStartTime())));
        }
        if (req.getEndTime() != null) {
            query.where(DUEYPACKAGES_D_O.TIMESTAMP.le(new Timestamp(req.getEndTime())));
        }
        if (req.getItemType() != null) {
            query.where(DUEYPACKAGES_D_O.TYPE.eq(req.getItemType()));
        }
        if (req.getChecked() != null) {
            query.where(DUEYPACKAGES_D_O.CHECKED.eq(req.getChecked()));
        }

        query.orderBy(DUEYPACKAGES_D_O.TIMESTAMP.desc());

        Page<Row> page = new Page<>(req.getPageNo(), req.getPageSize());
        Page<Row> rowPage = Db.paginate(null, page, query);
        List<DueyPackageRtnDTO> dtoList = rowPage.getRecords().stream().map(this::convertRowToDTO).collect(Collectors.toList());

        return new Page<>(dtoList, rowPage.getPageNumber(), rowPage.getPageSize(), rowPage.getTotalRow());
    }

    private DueyPackageRtnDTO convertRowToDTO(Row row) {
        DueyPackageRtnDTO dto = new DueyPackageRtnDTO();
        
        Long packageId = getLong(row, "packageid");
        
        dto.setPackageId(packageId);
        dto.setReceiverId(getLong(row, "receiverid"));
        dto.setReceiverName(getString(row, "receiverName"));
        dto.setSenderName(getString(row, "sendername"));
        dto.setMesos(getLong(row, "mesos"));
        
        Object timestampObj = getObjectCaseInsensitive(row, "timestamp");
        Timestamp timestamp = null;
        if (timestampObj instanceof Timestamp) {
            timestamp = (Timestamp) timestampObj;
            dto.setTimestamp(timestamp);
        }
        
        dto.setMessage(getString(row, "message"));
        dto.setChecked(getInt(row, "checked"));
        Integer type = getInt(row, "type");
        dto.setType(type);

        // Calculate expire time and delivery time
        Object expireDateObj = getObjectCaseInsensitive(row, "expire_date");
        if (expireDateObj instanceof Timestamp) {
             dto.setExpireTime((Timestamp) expireDateObj);
        } else if (timestamp != null) {
            // Fallback to default calculation if expire_date is null
            long expireDuration = GameConfig.getServerLong("duey_expire_time", 2592000000L);
            dto.setExpireTime(new Timestamp(timestamp.getTime() + expireDuration));
        }

        if (timestamp != null) {
            // Delivery time
            if (type != null && type == 1) { // Quick delivery
                dto.setDeliveryTime(timestamp);
            } else {
                // Normal delivery: timestamp + duey_normal_delivery_time (default 1 day)
                long deliveryDuration = GameConfig.getServerLong("duey_normal_delivery_time", 86400000L);
                dto.setDeliveryTime(new Timestamp(timestamp.getTime() + deliveryDuration));
            }
        }

        // Load items
        if (dto.getPackageId() != null) {
            List<Pair<Item, InventoryType>> items = itemFactoryService.loadItems(ItemFactory.DUEY.getValue(), false, dto.getPackageId().intValue(), false);
            List<ItemInfoRtnDTO> itemDTOs = new ArrayList<>();
            for (Pair<Item, InventoryType> pair : items) {
                Item item = pair.getLeft();
                ItemInfoRtnDTO itemDTO = new ItemInfoRtnDTO();
                itemDTO.setItemId(item.getItemId());
                itemDTO.setQuantity((int) item.getQuantity());
                itemDTO.setOwner(item.getOwner());
                itemDTO.setExpiration(item.getExpiration());
                
                String itemName = ItemInformationProvider.getInstance().getName(item.getItemId());
                itemDTO.setName(itemName != null ? itemName : String.valueOf(item.getItemId()));
                
                itemDTOs.add(itemDTO);
            }
            dto.setItems(itemDTOs);
        } else {
            dto.setItems(new ArrayList<>());
        }

        return dto;
    }
    
    private Object getObjectCaseInsensitive(Row row, String col) {
        // 1. Try exact match
        Object val = row.get(col);
        if (val != null) return val;
        
        // 2. Try lower case
        val = row.get(col.toLowerCase());
        if (val != null) return val;
        
        // 3. Try upper case
        val = row.get(col.toUpperCase());
        if (val != null) return val;
        
        // 4. Iterate keys (most robust but slower)
        Set<String> keys = row.keySet();
        for (String key : keys) {
            if (key.equalsIgnoreCase(col)) {
                return row.get(key);
            }
        }
        return null;
    }
    
    private Long getLong(Row row, String col) {
        Object val = getObjectCaseInsensitive(row, col);
        if (val instanceof Number) {
            return ((Number) val).longValue();
        }
        return null;
    }
    
    private Integer getInt(Row row, String col) {
        Object val = getObjectCaseInsensitive(row, col);
        if (val instanceof Number) {
            return ((Number) val).intValue();
        }
        return null;
    }
    
    private String getString(Row row, String col) {
        Object val = getObjectCaseInsensitive(row, col);
        return val != null ? val.toString() : null;
    }

    @Transactional
    public void deleteDueyPackage(Long id) {
        dueypackagesMapper.deleteById(id);
        itemFactoryService.saveItems(ItemFactory.DUEY.getValue(), false, new ArrayList<>(), id.intValue());
    }

    public void sendDueyPackage(SendDueyReqDTO req) {
        if (Boolean.TRUE.equals(req.getIsAll())) {
            QueryWrapper query = QueryWrapper.create().select(CHARACTERS_D_O.ID);
            List<Integer> allCharIds = charactersMapper.selectListByQueryAs(query, Integer.class);
            for (Integer cid : allCharIds) {
                sendSinglePackage(req, cid);
            }
        } else if (req.getReceiverIds() != null && !req.getReceiverIds().isEmpty()) {
            for (Integer cid : req.getReceiverIds()) {
                sendSinglePackage(req, cid);
            }
        } else {
            // 兼容旧逻辑，如果 receiverIds 为空，尝试使用 receiverId 或 receiverName
            // 但由于 SendDueyReqDTO 中已经移除了 receiverId 字段，这里只能尝试 receiverName
            // 如果前端传递了 receiverName 但没有 receiverIds，我们需要在这里处理
            if (req.getReceiverName() != null) {
                CharactersDO chr = charactersMapper.selectOneByQuery(QueryWrapper.create().where(CHARACTERS_D_O.NAME.eq(req.getReceiverName())));
                if (chr != null) {
                    sendSinglePackage(req, chr.getId());
                } else {
                    throw new RuntimeException("Receiver not found: " + req.getReceiverName());
                }
            } else {
                throw new RuntimeException("No receiver specified");
            }
        }
    }

    private void sendSinglePackage(SendDueyReqDTO req, Integer receiverId) {
        Item item = null;
        if (req.getItemId() != null && req.getQuantity() != null && req.getQuantity() > 0) {
            // 判断是否为装备
            InventoryType type = ItemInformationProvider.getInstance().getInventoryType(req.getItemId());
            if (type == InventoryType.EQUIP) {
                Equip equip = new Equip(req.getItemId(), (byte) 0, -1);
                equip.setQuantity((short) 1);
                // 设置自定义属性
                if (req.getStr() != null) equip.setStr(req.getStr());
                if (req.getDex() != null) equip.setDex(req.getDex());
                if (req.getInt_() != null) equip.setInt(req.getInt_());
                if (req.getLuk() != null) equip.setLuk(req.getLuk());
                if (req.getHp() != null) equip.setHp(req.getHp());
                if (req.getMp() != null) equip.setMp(req.getMp());
                if (req.getWatk() != null) equip.setWatk(req.getWatk());
                if (req.getMatk() != null) equip.setMatk(req.getMatk());
                if (req.getWdef() != null) equip.setWdef(req.getWdef());
                if (req.getMdef() != null) equip.setMdef(req.getMdef());
                if (req.getAcc() != null) equip.setAcc(req.getAcc());
                if (req.getAvoid() != null) equip.setAvoid(req.getAvoid());
                if (req.getHands() != null) equip.setHands(req.getHands());
                if (req.getSpeed() != null) equip.setSpeed(req.getSpeed());
                if (req.getJump() != null) equip.setJump(req.getJump());
                if (req.getUpgradeSlots() != null) equip.setUpgradeSlots(req.getUpgradeSlots());
                if (req.getLevel() != null) equip.setLevel(req.getLevel());
                if (req.getItemLevel() != null) equip.setItemLevel(req.getItemLevel());
                if (req.getFlag() != null) equip.setFlag(req.getFlag().byteValue());
                
                item = equip;
            } else {
                item = new Item(req.getItemId(), (byte) 0, req.getQuantity().shortValue(), -1);
            }
            
            // 设置物品过期时间 (如果需要)
            // 注意：这里是物品本身的过期时间，不是包裹的过期时间
        }
        
        String sender = req.getSenderName() != null && !req.getSenderName().isEmpty() ? req.getSenderName() : "管理员";

        DueypackagesDO newPackage = new DueypackagesDO();
        newPackage.setReceiverid(receiverId.longValue());
        newPackage.setSendername(sender);
        newPackage.setMesos(req.getMesos() != null ? req.getMesos().longValue() : 0L);
        
        // 设置发送时间 (如果是普通快递且指定了配送时间，则使用配送时间作为timestamp，否则使用当前时间)
        // 注意：DueyPackage.java 中 isDeliveringTime() 逻辑是 timestamp >= now
        // 如果是快速快递，timestamp 就是当前时间
        // 如果是普通快递，timestamp 应该是 配送时间 - 1天 (因为 DueyPackage.java 中 sentTimeInMilliseconds 会 +1个月，逻辑比较奇怪)
        // 重新审视 DueyPackage.java:
        // isDeliveringTime(): timestamp >= System.currentTimeMillis()
        // 这里的 timestamp 实际上是 "可领取时间"
        // 所以如果是快速快递，timestamp = now
        // 如果是普通快递，timestamp = deliveryTime
        
        long timestamp = System.currentTimeMillis();
        if (Boolean.FALSE.equals(req.getQuick()) && req.getDeliveryTime() != null) {
            timestamp = req.getDeliveryTime();
        } else if (Boolean.FALSE.equals(req.getQuick())) {
             // 普通快递默认1天后
             long deliveryDuration = GameConfig.getServerLong("duey_normal_delivery_time", 86400000L);
             timestamp += deliveryDuration;
        }
        
        newPackage.setTimestamp(new Timestamp(timestamp));
        newPackage.setMessage(req.getMessage());
        newPackage.setType(Boolean.TRUE.equals(req.getQuick()) ? 1 : 0);
        newPackage.setChecked(1);
        
        // 设置包裹过期时间
        if (req.getExpireTime() != null) {
            newPackage.setExpireDate(new Timestamp(req.getExpireTime()));
        } else if (req.getExpireDays() != null && req.getExpireDays() > 0) {
             long expireTime = System.currentTimeMillis() + (req.getExpireDays() * 24 * 60 * 60 * 1000L);
             newPackage.setExpireDate(new Timestamp(expireTime));
        } else {
             // 默认过期时间
             long expireDuration = GameConfig.getServerLong("duey_expire_time", 2592000000L);
             newPackage.setExpireDate(new Timestamp(System.currentTimeMillis() + expireDuration));
        }

        if (dueypackagesMapper.insert(newPackage, true) > 0) {
            int packageId = newPackage.getPackageid().intValue();
            if (item != null) {
                List<Pair<Item, InventoryType>> dueyItems = new ArrayList<>();
                dueyItems.add(new Pair<>(item, InventoryType.getByType(item.getItemType())));
                itemFactoryService.saveItems(ItemFactory.DUEY.getValue(), false, dueyItems, packageId);
            }
        } else {
            throw new RuntimeException("Failed to create duey package");
        }
    }
}
