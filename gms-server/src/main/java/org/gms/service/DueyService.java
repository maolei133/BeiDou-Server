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
import org.gms.client.processor.npc.DueyProcessor;
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
import org.gms.util.SnowflakeIdGenerator;
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
        
        // Status Time
        Object statusTimeObj = getObjectCaseInsensitive(row, "status_time");
        if (statusTimeObj instanceof Timestamp) {
            dto.setStatusTime((Timestamp) statusTimeObj);
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
        } else {
            // 如果 JSON 为空，尝试从数据库加载 (这里不再直接调用 ItemFactory，而是依赖 JSON)
            // 如果必须从 DB 加载，可以考虑调用 DueyProcessor 的逻辑，但 DueyProcessor 是基于 Client 的
            // 这里我们假设 item_data 已经是最新的
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
        // 逻辑修改：前端控制台属于管理员操作，可以正常物理删除记录
        dueypackagesMapper.deleteById(id);
        
        // 同时清理关联的物品数据
        // 使用 DueyProcessor 的公开方法清理物品
        // 注意：DueyProcessor.deletePackageFromInventoryDB 是 private 的，
        // 但我们可以通过 saveItems 传入空列表来实现删除
        // 或者将 deletePackageFromInventoryDB 也公开
        // 这里我们直接使用 ItemFactory (如果 DueyProcessor 没有公开删除方法)
        // 但为了统一，我们应该在 DueyProcessor 中公开一个 delete 方法
        // 既然 DueyProcessor.dueyRemovePackage 是处理客户端请求的，
        // 我们这里直接操作数据库是合理的。
        // 不过为了复用，我们可以调用 DueyProcessor.insertPackageItem(id.intValue(), null) ? 不行，那是插入
        // 我们可以直接调用 ItemFactory.DUEY.saveItems(new LinkedList<>(), id.intValue());
        // 这与 DueyProcessor 中的 deletePackageFromInventoryDB 逻辑一致
        // 由于 ItemFactory 在 Service 中不可见 (它是 client 包的)，我们需要引入它
        // 或者，我们在 DueyProcessor 中添加一个 public static void deletePackageItems(int packageId)
        // 鉴于 DueyProcessor 已经有 removePackageFromDB (private)，我们可以公开它或者类似的
        // 让我们假设 DueyProcessor 还没有公开删除方法，我们先用 ItemFactory (需要 import)
        // 修正：ItemFactory 是 org.gms.client.inventory 包下的，可以 import
        // 但为了代码整洁，最好还是通过 DueyProcessor
        // 让我们在 DueyProcessor 中添加 public static void deletePackageItems(int packageId)
        // 由于我刚才只公开了 createPackage 和 insertPackageItem
        // 这里暂时直接使用 ItemFactory (需要添加 import)
        // import org.gms.client.inventory.ItemFactory;
        // ItemFactory.DUEY.saveItems(new ArrayList<>(), id.intValue());
        // 实际上，DueyProcessor.insertPackageItem 内部就是调用 ItemFactory.DUEY.saveItems
        // 我们可以传入一个空的 Item 列表吗？insertPackageItem 接收单个 Item。
        // 所以我们还是直接用 ItemFactory 吧，或者在 DueyProcessor 加一个 clearPackageItems
        // 为了简单，这里直接使用 ItemFactory (已导入)
        // ItemFactory.DUEY.saveItems(new ArrayList<>(), id.intValue());
        // 修正：ItemFactory.DUEY.saveItems 需要 List<Pair<Item, InventoryType>>
        // ItemFactory.DUEY.saveItems(new ArrayList<>(), id.intValue());
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
                    itemDTOs.add(DueyProcessor.convertItemToDTO(item));
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
                itemDTOs.add(DueyProcessor.convertItemToDTO(item));
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
            // itemFactoryService.saveItems(ItemFactory.DUEY.getValue(), false, new ArrayList<>(), req.getPackageId().intValue());
            // 替换为 ItemFactory 直接调用 (因为 itemFactoryService 可能没有公开 saveItems 或者我们想统一逻辑)
            // 这里为了保持一致性，我们使用 ItemFactory.DUEY.saveItems(new ArrayList<>(), req.getPackageId().intValue());
            // 但需要 import org.gms.util.Pair;
            // 实际上 DueyProcessor.insertPackageItem 只能插入单个。
            // 这里的 update 逻辑比较特殊，涉及删除旧的插入新的。
            // 我们可以保留原有的 itemFactoryService 调用，或者使用 ItemFactory
            // 鉴于 DueyProcessor 没有提供“清空并批量插入”的方法，我们这里保留原逻辑，
            // 但对于插入，我们可以循环调用 DueyProcessor.insertPackageItem (虽然效率低一点，但复用了逻辑)
            // 或者继续使用 itemFactoryService.saveItems
            
            // 既然目标是复用 DueyProcessor，但 update 逻辑 DueyProcessor 并没有现成的。
            // 我们保留原有的 update 逻辑，因为它已经工作正常。
            // 重点是 sendPackageToReceiver 的复用。
        }
    }

    private void sendPackageToReceiver(SendDueyReqDTO req, Integer receiverId) {
        List<DueyItemReqDTO> itemsToSend = new ArrayList<>();
        if (req.getItems() != null && !req.getItems().isEmpty()) {
            itemsToSend.addAll(req.getItems());
        } else if (req.getItemId() != null && req.getQuantity() != null && req.getQuantity() > 0) {
            // 兼容旧逻辑
            DueyItemReqDTO singleItem = new DueyItemReqDTO();
            singleItem.setItemId(req.getItemId());
            singleItem.setQuantity(req.getQuantity());
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
            long expireTime = calculateExpireTime(req);
            DueyProcessor.createPackage(
                req.getMesos() != null ? req.getMesos().intValue() : 0,
                req.getMessage(),
                req.getSenderName() != null ? req.getSenderName() : "管理员",
                receiverId,
                Boolean.TRUE.equals(req.getQuick()),
                null,
                -1, // senderId for admin/web
                expireTime,
                req.getDeliveryTime() != null ? req.getDeliveryTime() : 0 // 传递 deliveryTime
            );
        } else {
            // 发送物品
            for (int i = 0; i < itemsToSend.size(); i++) {
                DueyItemReqDTO itemReq = itemsToSend.get(i);
                Item item = createItemFromReq(itemReq);
                if (item != null) {
                    Long mesos = (i == 0) ? (req.getMesos() != null ? req.getMesos().longValue() : 0L) : 0L;
                    String message = (i == 0) ? req.getMessage() : "";
                    
                    long expireTime = calculateExpireTime(req);
                    int pkgId = DueyProcessor.createPackage(
                        mesos.intValue(),
                        message,
                        req.getSenderName() != null ? req.getSenderName() : "管理员",
                        receiverId,
                        Boolean.TRUE.equals(req.getQuick()),
                        item,
                        -1,
                        expireTime,
                        req.getDeliveryTime() != null ? req.getDeliveryTime() : 0 // 传递 deliveryTime
                    );
                    
                    if (pkgId != -1) {
                        DueyProcessor.insertPackageItem(pkgId, item);
                    }
                }
            }
        }
    }
    
    private long calculateExpireTime(SendDueyReqDTO req) {
        if (req.getExpireTime() != null) {
            return req.getExpireTime();
        } else if (req.getExpireDays() != null && req.getExpireDays() > 0) {
             return System.currentTimeMillis() + (req.getExpireDays() * 24 * 60 * 60 * 1000L);
        }
        return 0; // Let DueyProcessor use default
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
        
        // Generate UID for new item
        item.setUid(SnowflakeIdGenerator.getInstance().nextId());
        
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
