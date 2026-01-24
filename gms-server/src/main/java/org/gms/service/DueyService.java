package org.gms.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.gms.model.dto.DueyItemReqDTO;
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
    private final ObjectMapper objectMapper = new ObjectMapper();

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
            // 配置单位为分钟
            long expireDuration = GameConfig.getServerInt("duey_expire_time", 43200) * 60 * 1000L;
            dto.setExpireTime(new Timestamp(timestamp.getTime() + expireDuration));
        }

        if (timestamp != null) {
            // Delivery time
            if (type != null && type == 1) { // Quick delivery
                dto.setDeliveryTime(timestamp);
            } else {
                // Normal delivery: timestamp + duey_normal_delivery_time (default 1 day)
                // 配置单位为分钟
                long deliveryDuration = GameConfig.getServerInt("duey_normal_delivery_time", 1440) * 60 * 1000L;
                dto.setDeliveryTime(new Timestamp(timestamp.getTime() + deliveryDuration));
            }
        }

        // Load items
        // 优先从 item_data (JSON) 加载，如果为空则从 inventoryitems 表加载
        String itemDataJson = getString(row, "item_data");
        if (itemDataJson != null && !itemDataJson.isEmpty()) {
            try {
                // 尝试解析为 List<ItemInfoRtnDTO>
                try {
                    List<ItemInfoRtnDTO> itemDTOs = objectMapper.readValue(itemDataJson, objectMapper.getTypeFactory().constructCollectionType(List.class, ItemInfoRtnDTO.class));
                    dto.setItems(itemDTOs);
                } catch (Exception e) {
                    // 兼容旧数据，可能是单个对象
                    ItemInfoRtnDTO itemDTO = objectMapper.readValue(itemDataJson, ItemInfoRtnDTO.class);
                    List<ItemInfoRtnDTO> itemDTOs = new ArrayList<>();
                    itemDTOs.add(itemDTO);
                    dto.setItems(itemDTOs);
                }
            } catch (JsonProcessingException e) {
                // JSON 解析失败，降级处理或记录日志
                dto.setItems(new ArrayList<>());
            }
        } else if (dto.getPackageId() != null) {
            List<Pair<Item, InventoryType>> items = itemFactoryService.loadItems(ItemFactory.DUEY.getValue(), false, dto.getPackageId().intValue(), false);
            List<ItemInfoRtnDTO> itemDTOs = new ArrayList<>();
            for (Pair<Item, InventoryType> pair : items) {
                Item item = pair.getLeft();
                ItemInfoRtnDTO itemDTO = convertItemToDTO(item);
                itemDTOs.add(itemDTO);
            }
            dto.setItems(itemDTOs);
        } else {
            dto.setItems(new ArrayList<>());
        }

        return dto;
    }
    
    private ItemInfoRtnDTO convertItemToDTO(Item item) {
        ItemInfoRtnDTO itemDTO = new ItemInfoRtnDTO();
        itemDTO.setItemId(item.getItemId());
        itemDTO.setQuantity((int) item.getQuantity());
        itemDTO.setOwner(item.getOwner());
        itemDTO.setExpiration(item.getExpiration());
        
        String itemName = ItemInformationProvider.getInstance().getName(item.getItemId());
        itemDTO.setName(itemName != null ? itemName : String.valueOf(item.getItemId()));
        
        // 填充装备属性
        if (item instanceof Equip) {
            Equip equip = (Equip) item;
            itemDTO.setStr(equip.getStr());
            itemDTO.setDex(equip.getDex());
            itemDTO.setInt_(equip.getInt());
            itemDTO.setLuk(equip.getLuk());
            itemDTO.setHp(equip.getHp());
            itemDTO.setMp(equip.getMp());
            itemDTO.setWatk(equip.getWatk());
            itemDTO.setMatk(equip.getMatk());
            itemDTO.setWdef(equip.getWdef());
            itemDTO.setMdef(equip.getMdef());
            itemDTO.setAcc(equip.getAcc());
            itemDTO.setAvoid(equip.getAvoid());
            itemDTO.setHands(equip.getHands());
            itemDTO.setSpeed(equip.getSpeed());
            itemDTO.setJump(equip.getJump());
            itemDTO.setUpgradeSlots(equip.getUpgradeSlots());
            itemDTO.setLevel((byte) equip.getLevel());
            itemDTO.setItemLevel((byte) equip.getItemLevel());
            itemDTO.setFlag(equip.getFlag());
            itemDTO.setVicious(equip.getVicious());
        }
        return itemDTO;
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
        // 逻辑修改：前端控制台属于管理员操作，可以正常物理删除记录
        dueypackagesMapper.deleteById(id);
        
        // 同时清理关联的物品数据
        itemFactoryService.saveItems(ItemFactory.DUEY.getValue(), false, new ArrayList<>(), id.intValue());
    }

    @Transactional
    public void sendDueyPackage(SendDueyReqDTO req) {
        if (req.getPackageId() != null) {
            // 更新逻辑
            updateDueyPackage(req);
        } else {
            // 发送逻辑
            if (Boolean.TRUE.equals(req.getIsAll())) {
                QueryWrapper query = QueryWrapper.create().select(CHARACTERS_D_O.ID);
                List<Integer> allCharIds = charactersMapper.selectListByQueryAs(query, Integer.class);
                for (Integer cid : allCharIds) {
                    sendPackageToReceiver(req, cid);
                }
            } else if (req.getReceiverIds() != null && !req.getReceiverIds().isEmpty()) {
                for (Integer cid : req.getReceiverIds()) {
                    sendPackageToReceiver(req, cid);
                }
            } else {
                // 兼容旧逻辑，如果 receiverIds 为空，尝试使用 receiverId 或 receiverName
                if (req.getReceiverName() != null) {
                    CharactersDO chr = charactersMapper.selectOneByQuery(QueryWrapper.create().where(CHARACTERS_D_O.NAME.eq(req.getReceiverName())));
                    if (chr != null) {
                        sendPackageToReceiver(req, chr.getId());
                    } else {
                        throw new RuntimeException("未找到收件人: " + req.getReceiverName());
                    }
                } else {
                    throw new RuntimeException("未指定收件人");
                }
            }
        }
    }

    private void updateDueyPackage(SendDueyReqDTO req) {
        DueypackagesDO existingPackage = dueypackagesMapper.selectOneById(req.getPackageId());
        if (existingPackage == null) {
            throw new RuntimeException("未找到包裹: " + req.getPackageId());
        }

        // 更新基本信息
        if (req.getMesos() != null) existingPackage.setMesos(req.getMesos().longValue());
        if (req.getMessage() != null) existingPackage.setMessage(req.getMessage());
        if (req.getSenderName() != null) existingPackage.setSendername(req.getSenderName());
        if (req.getQuick() != null) existingPackage.setType(req.getQuick() ? 1 : 0);
        
        // 更新收件人 (如果提供了)
        if (req.getReceiverIds() != null && !req.getReceiverIds().isEmpty()) {
            existingPackage.setReceiverid(req.getReceiverIds().get(0).longValue());
        } else if (req.getReceiverName() != null) {
            CharactersDO chr = charactersMapper.selectOneByQuery(QueryWrapper.create().where(CHARACTERS_D_O.NAME.eq(req.getReceiverName())));
            if (chr != null) {
                existingPackage.setReceiverid(chr.getId().longValue());
            }
        }

        // 更新时间相关
        if (req.getExpireTime() != null) {
            existingPackage.setExpireDate(new Timestamp(req.getExpireTime()));
        } else if (req.getExpireDays() != null && req.getExpireDays() > 0) {
             long expireTime = System.currentTimeMillis() + (req.getExpireDays() * 24 * 60 * 60 * 1000L);
             existingPackage.setExpireDate(new Timestamp(expireTime));
        }

        // 构建物品列表
        List<Item> items = new ArrayList<>();
        List<ItemInfoRtnDTO> itemDTOs = new ArrayList<>();

        // 优先处理 items 列表
        if (req.getItems() != null && !req.getItems().isEmpty()) {
            for (DueyItemReqDTO itemReq : req.getItems()) {
                Item item = createItemFromReq(itemReq);
                if (item != null) {
                    items.add(item);
                    itemDTOs.add(convertItemToDTO(item));
                }
            }
        } else if (req.getItemId() != null && req.getQuantity() != null && req.getQuantity() > 0) {
            // 兼容旧的单个物品逻辑
            DueyItemReqDTO singleItemReq = new DueyItemReqDTO();
            singleItemReq.setItemId(req.getItemId());
            singleItemReq.setQuantity(req.getQuantity());
            singleItemReq.setOwner(req.getOwner());
            singleItemReq.setExpiration(req.getItemExpiration());
            singleItemReq.setStr(req.getStr());
            singleItemReq.setDex(req.getDex());
            singleItemReq.setInt_(req.getInt_());
            singleItemReq.setLuk(req.getLuk());
            singleItemReq.setHp(req.getHp());
            singleItemReq.setMp(req.getMp());
            singleItemReq.setWatk(req.getWatk());
            singleItemReq.setMatk(req.getMatk());
            singleItemReq.setWdef(req.getWdef());
            singleItemReq.setMdef(req.getMdef());
            singleItemReq.setAcc(req.getAcc());
            singleItemReq.setAvoid(req.getAvoid());
            singleItemReq.setHands(req.getHands());
            singleItemReq.setSpeed(req.getSpeed());
            singleItemReq.setJump(req.getJump());
            singleItemReq.setUpgradeSlots(req.getUpgradeSlots());
            singleItemReq.setLevel(req.getLevel());
            singleItemReq.setItemLevel(req.getItemLevel());
            singleItemReq.setFlag(req.getFlag());
            singleItemReq.setVicious(req.getVicious());
            
            Item item = createItemFromReq(singleItemReq);
            if (item != null) {
                items.add(item);
                itemDTOs.add(convertItemToDTO(item));
            }
        }

        // 更新 item_data JSON
        if (!itemDTOs.isEmpty()) {
            try {
                existingPackage.setItemData(objectMapper.writeValueAsString(itemDTOs));
            } catch (JsonProcessingException e) {
                throw new RuntimeException("序列化物品数据失败", e);
            }
        } else {
            existingPackage.setItemData(null); // 清空物品
        }

        dueypackagesMapper.update(existingPackage);

        // 更新 inventoryitems 表
        // 只有当包裹未被领取时，才更新 inventoryitems 表
        if (existingPackage.getChecked() != 2) {
            // 先删除旧物品
            itemFactoryService.saveItems(ItemFactory.DUEY.getValue(), false, new ArrayList<>(), req.getPackageId().intValue());
            // 再插入新物品
            if (!items.isEmpty()) {
                List<Pair<Item, InventoryType>> dueyItems = new ArrayList<>();
                for (Item item : items) {
                    dueyItems.add(new Pair<>(item, InventoryType.getByType(item.getItemType())));
                }
                itemFactoryService.saveItems(ItemFactory.DUEY.getValue(), false, dueyItems, req.getPackageId().intValue());
            }
        }
    }

    private void sendPackageToReceiver(SendDueyReqDTO req, Integer receiverId) {
        // 1. 如果有金币或留言，先发送一个包裹（可能包含第一个物品，或者不包含物品）
        // 2. 如果有多个物品，每个物品单独发送一个包裹
        
        // 策略：
        // 如果没有物品，只发金币/留言包裹。
        // 如果有物品：
        //   第一个物品 + 金币 + 留言 -> 包裹1
        //   后续物品 -> 包裹2, 包裹3... (无金币无留言)
        
        List<DueyItemReqDTO> itemsToSend = new ArrayList<>();
        if (req.getItems() != null && !req.getItems().isEmpty()) {
            itemsToSend.addAll(req.getItems());
        } else if (req.getItemId() != null && req.getQuantity() != null && req.getQuantity() > 0) {
            // 兼容旧逻辑
            DueyItemReqDTO singleItem = new DueyItemReqDTO();
            singleItem.setItemId(req.getItemId());
            singleItem.setQuantity(req.getQuantity());
            // ... copy other properties ...
            // 为简化，这里假设 createItemFromReq 会处理 SendDueyReqDTO 中的字段，或者我们在上层已经转换好了
            // 但为了代码复用，我们这里手动构建一个 DueyItemReqDTO
            singleItem.setOwner(req.getOwner());
            singleItem.setExpiration(req.getItemExpiration());
            singleItem.setStr(req.getStr());
            singleItem.setDex(req.getDex());
            singleItem.setInt_(req.getInt_());
            singleItem.setLuk(req.getLuk());
            singleItem.setHp(req.getHp());
            singleItem.setMp(req.getMp());
            singleItem.setWatk(req.getWatk());
            singleItem.setMatk(req.getMatk());
            singleItem.setWdef(req.getWdef());
            singleItem.setMdef(req.getMdef());
            singleItem.setAcc(req.getAcc());
            singleItem.setAvoid(req.getAvoid());
            singleItem.setHands(req.getHands());
            singleItem.setSpeed(req.getSpeed());
            singleItem.setJump(req.getJump());
            singleItem.setUpgradeSlots(req.getUpgradeSlots());
            singleItem.setLevel(req.getLevel());
            singleItem.setItemLevel(req.getItemLevel());
            singleItem.setFlag(req.getFlag());
            singleItem.setVicious(req.getVicious());
            itemsToSend.add(singleItem);
        }

        if (itemsToSend.isEmpty()) {
            // 仅发送金币或留言
            createAndInsertPackage(req, receiverId, null, req.getMesos(), req.getMessage());
        } else {
            // 发送物品
            for (int i = 0; i < itemsToSend.size(); i++) {
                DueyItemReqDTO itemReq = itemsToSend.get(i);
                Item item = createItemFromReq(itemReq);
                if (item != null) {
                    // 只有第一个包裹携带金币和留言
                    Long mesos = (i == 0) ? (req.getMesos() != null ? req.getMesos().longValue() : 0L) : 0L;
                    String message = (i == 0) ? req.getMessage() : "";
                    createAndInsertPackage(req, receiverId, item, mesos.intValue(), message);
                }
            }
        }
    }

    private void createAndInsertPackage(SendDueyReqDTO req, Integer receiverId, Item item, Integer mesos, String message) {
        String sender = req.getSenderName() != null && !req.getSenderName().isEmpty() ? req.getSenderName() : "管理员";

        DueypackagesDO newPackage = new DueypackagesDO();
        newPackage.setReceiverid(receiverId.longValue());
        newPackage.setSendername(sender);
        newPackage.setMesos(mesos != null ? mesos.longValue() : 0L);
        
        long timestamp = System.currentTimeMillis();
        if (Boolean.FALSE.equals(req.getQuick()) && req.getDeliveryTime() != null) {
            timestamp = req.getDeliveryTime();
        } else if (Boolean.FALSE.equals(req.getQuick())) {
             // 普通快递默认1天后
             long deliveryDuration = GameConfig.getServerInt("duey_normal_delivery_time", 1440) * 60 * 1000L;
             timestamp += deliveryDuration;
        }
        
        newPackage.setTimestamp(new Timestamp(timestamp));
        newPackage.setMessage(message);
        newPackage.setType(Boolean.TRUE.equals(req.getQuick()) ? 1 : 0);
        newPackage.setChecked(1);
        
        // 设置包裹过期时间
        if (req.getExpireTime() != null) {
            newPackage.setExpireDate(new Timestamp(req.getExpireTime()));
        } else if (req.getExpireDays() != null && req.getExpireDays() > 0) {
             long expireTime = System.currentTimeMillis() + (req.getExpireDays() * 24 * 60 * 60 * 1000L);
             newPackage.setExpireDate(new Timestamp(expireTime));
        } else {
             long expireDuration = GameConfig.getServerInt("duey_expire_time", 43200) * 60 * 1000L;
             newPackage.setExpireDate(new Timestamp(System.currentTimeMillis() + expireDuration));
        }
        
        // 序列化 itemData
        if (item != null) {
            ItemInfoRtnDTO itemDTO = convertItemToDTO(item);
            // 即使是单个物品，为了统一格式，也可以考虑用 List 包装，或者保持单个对象
            // 为了兼容性，如果只有一个物品，我们存单个对象，或者存 List 但只含一个
            // 前面的 convertRowToDTO 已经做了兼容处理
            // 这里我们存 List 以便未来扩展，或者为了保持与 update 逻辑一致
            // 但 update 逻辑中如果是多物品会存 List
            // 这里拆包后每个包裹只有一个物品
            List<ItemInfoRtnDTO> itemDTOs = new ArrayList<>();
            itemDTOs.add(itemDTO);
            try {
                newPackage.setItemData(objectMapper.writeValueAsString(itemDTOs));
            } catch (JsonProcessingException e) {
                throw new RuntimeException("Failed to serialize item data", e);
            }
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
    
    private Item createItemFromReq(DueyItemReqDTO req) {
        if (req.getItemId() == null || req.getQuantity() == null || req.getQuantity() <= 0) {
            return null;
        }
        
        Item item;
        InventoryType type = ItemInformationProvider.getInstance().getInventoryType(req.getItemId());
        if (type == InventoryType.EQUIP) {
            Equip equip = new Equip(req.getItemId(), (byte) 0, -1);
            equip.setQuantity((short) 1);
            if (req.getStr() != null) equip.setStr(limitShort(req.getStr()));
            if (req.getDex() != null) equip.setDex(limitShort(req.getDex()));
            if (req.getInt_() != null) equip.setInt(limitShort(req.getInt_()));
            if (req.getLuk() != null) equip.setLuk(limitShort(req.getLuk()));
            if (req.getHp() != null) equip.setHp(limitShort(req.getHp()));
            if (req.getMp() != null) equip.setMp(limitShort(req.getMp()));
            if (req.getWatk() != null) equip.setWatk(limitShort(req.getWatk()));
            if (req.getMatk() != null) equip.setMatk(limitShort(req.getMatk()));
            if (req.getWdef() != null) equip.setWdef(limitShort(req.getWdef()));
            if (req.getMdef() != null) equip.setMdef(limitShort(req.getMdef()));
            if (req.getAcc() != null) equip.setAcc(limitShort(req.getAcc()));
            if (req.getAvoid() != null) equip.setAvoid(limitShort(req.getAvoid()));
            if (req.getHands() != null) equip.setHands(limitShort(req.getHands()));
            if (req.getSpeed() != null) equip.setSpeed(limitShort(req.getSpeed()));
            if (req.getJump() != null) equip.setJump(limitShort(req.getJump()));
            if (req.getUpgradeSlots() != null) equip.setUpgradeSlots(limitByte(req.getUpgradeSlots()));
            if (req.getLevel() != null) equip.setLevel(limitShort(req.getLevel()));
            if (req.getItemLevel() != null) equip.setItemLevel(limitShort(req.getItemLevel()));
            if (req.getFlag() != null) equip.setFlag(limitShort(req.getFlag()));
            if (req.getVicious() != null) equip.setVicious(limitShort(req.getVicious()));
            item = equip;
        } else {
            item = new Item(req.getItemId(), (byte) 0, req.getQuantity().shortValue(), -1);
        }

        if (req.getOwner() != null) item.setOwner(req.getOwner());
        if (req.getExpiration() != null) item.setExpiration(req.getExpiration());
        
        return item;
    }
    
    private short limitShort(Integer val) {
        if (val == null) return 0;
        if (val > Short.MAX_VALUE) return Short.MAX_VALUE;
        if (val < Short.MIN_VALUE) return Short.MIN_VALUE;
        return val.shortValue();
    }
    
    private byte limitByte(Integer val) {
        if (val == null) return 0;
        if (val > Byte.MAX_VALUE) return Byte.MAX_VALUE;
        if (val < Byte.MIN_VALUE) return Byte.MIN_VALUE;
        return val.byteValue();
    }
}
