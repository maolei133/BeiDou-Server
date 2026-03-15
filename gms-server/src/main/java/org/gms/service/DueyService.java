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
import org.gms.client.processor.npc.DueyProcessor;
import org.gms.config.GameConfig;
import org.gms.dao.entity.CharactersDO;
import org.gms.dao.entity.DueypackagesDO;
import org.gms.dao.mapper.CharactersMapper;
import org.gms.dao.mapper.DueypackagesMapper;
import org.gms.model.dto.*;
import org.gms.server.ItemInformationProvider;
import org.gms.util.ItemConverter;
import org.gms.util.Pair;
import org.gms.util.SnowflakeIdGenerator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.gms.dao.entity.table.CharactersDOTableDef.CHARACTERS_D_O;
import static org.gms.dao.entity.table.DueypackagesDOTableDef.DUEYPACKAGES_D_O;

@Service
public class DueyService {

    private final DueypackagesMapper dueypackagesMapper;
    private final CharactersMapper charactersMapper;
    private final ObjectMapper objectMapper;

    public DueyService(
            DueypackagesMapper dueypackagesMapper,
            CharactersMapper charactersMapper,
            @Qualifier("sparseItemObjectMapper") ObjectMapper objectMapper
    ) {
        this.dueypackagesMapper = dueypackagesMapper;
        this.charactersMapper = charactersMapper;
        this.objectMapper = objectMapper;
    }

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
        // **关键修复**：修复了调用不存在的方法的错误，正确使用 DTO 中的 itemId 字段
        if (req.getItemId() != null && req.getItemId() > 0) {
            query.where(DUEYPACKAGES_D_O.ITEM_ID.eq(req.getItemId()));
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

        Object expireDateObj = getObjectCaseInsensitive(row, "expire_date");
        if (expireDateObj instanceof Timestamp) {
             dto.setExpireTime((Timestamp) expireDateObj);
        } else if (timestamp != null) {
            long expireDuration = GameConfig.getServerInt("duey_expire_time", 43200) * 60 * 1000L;
            dto.setExpireTime(new Timestamp(timestamp.getTime() + expireDuration));
        }
        
        Object statusTimeObj = getObjectCaseInsensitive(row, "status_time");
        if (statusTimeObj instanceof Timestamp) {
            dto.setStatusTime((Timestamp) statusTimeObj);
        }

        Object deliveryTimeObj = getObjectCaseInsensitive(row, "delivery_time");
        if (deliveryTimeObj instanceof Timestamp) {
            dto.setDeliveryTime((Timestamp) deliveryTimeObj);
        } else if (timestamp != null) {
            // 兼容旧数据，根据类型推断送达时间
            if (type != null && type == 1) { // 快速配送
                dto.setDeliveryTime(timestamp);
            } else { // 普通配送
                long deliveryDuration = GameConfig.getServerInt("duey_normal_delivery_time", 1440) * 60 * 1000L;
                dto.setDeliveryTime(new Timestamp(timestamp.getTime() + deliveryDuration));
            }
        }

        // --- 物品信息解析逻辑 (严格按照指示重写) ---
        ItemInfoRtnDTO apiItemDTO = null;
        String itemDataJson = getString(row, "item_data");
        Integer itemIdFromDb = getInt(row, "item_id"); // **核心1：从数据库行中获取 item_id**

        // 仅当数据库中明确存在 item_id 时，才处理物品信息
        if (itemIdFromDb != null && itemIdFromDb > 0) {
            // 尝试从 item_data 解析基础属性
            if (itemDataJson != null && !itemDataJson.isEmpty() && !itemDataJson.equals("{}")) {
                try {
                    apiItemDTO = objectMapper.readValue(itemDataJson, ItemInfoRtnDTO.class);
                } catch (JsonProcessingException e) {
                    // 解析失败，忽略错误，后续会创建新对象
                }
            }

            // 如果解析失败或JSON为空，则创建一个新的DTO对象
            if (apiItemDTO == null) {
                apiItemDTO = new ItemInfoRtnDTO();
            }
            
            // **核心2：将数据库的 item_id 强制设置到DTO中，确保返回给前端的JSON包含此字段**
            apiItemDTO.setItemId(itemIdFromDb);

            // 补充必要信息
            if (apiItemDTO.getName() == null || apiItemDTO.getName().isEmpty()) {
                apiItemDTO.setName(ItemInformationProvider.getInstance().getName(itemIdFromDb));
            }
            if (apiItemDTO.getQuantity() == null || apiItemDTO.getQuantity() <= 0) {
                apiItemDTO.setQuantity(1); // 默认为1
            }
        }
        
        // 后备方案：如果上述逻辑未能创建DTO，但存在旧的 inventoryitems 记录，则加载它
        if (apiItemDTO == null && packageId != null) {
            List<Pair<Item, InventoryType>> itemsFromDbList = ItemFactory.DUEY.loadItems(packageId.intValue(), false);
            if (!itemsFromDbList.isEmpty()) {
                apiItemDTO = convertItemToItemInfoRtnDTO(itemsFromDbList.get(0).getLeft());
            }
        }

        dto.setItem(apiItemDTO);

        return dto;
    }

    /**
     * 将后端的 Item 业务对象转换为前端 API 需要的 ItemInfoRtnDTO 对象。
     * @param item 完整的 Item 对象
     * @return 用于 API 传输的 ItemInfoRtnDTO 对象
     */
    private ItemInfoRtnDTO convertItemToItemInfoRtnDTO(Item item) {
        if (item == null) return null;
        ItemInfoRtnDTO dto = new ItemInfoRtnDTO();
        dto.setItemId(item.getItemId()); // **确保转换时包含 itemId**
        dto.setQuantity((int)item.getQuantity());
        dto.setOwner(item.getOwner());
        dto.setExpiration(item.getExpiration());
        dto.setName(ItemInformationProvider.getInstance().getName(item.getItemId()));
        dto.setSn((long) item.getSN());
        dto.setPetId(item.getPetId());

        if (item instanceof Equip) {
            Equip equip = (Equip) item;
            dto.setStr(equip.getStr());
            dto.setDex(equip.getDex());
            dto.setInt_(equip.getInt());
            dto.setLuk(equip.getLuk());
            dto.setHp(equip.getHp());
            dto.setMp(equip.getMp());
            dto.setWatk(equip.getWatk());
            dto.setMatk(equip.getMatk());
            dto.setWdef(equip.getWdef());
            dto.setMdef(equip.getMdef());
            dto.setAcc(equip.getAcc());
            dto.setAvoid(equip.getAvoid());
            dto.setHands(equip.getHands());
            dto.setSpeed(equip.getSpeed());
            dto.setJump(equip.getJump());
            dto.setUpgradeSlots((int) equip.getUpgradeSlots());
            dto.setLevel(equip.getLevel());
            dto.setItemLevel(equip.getItemLevel());
            dto.setFlag(equip.getFlag());
            dto.setVicious(equip.getVicious());
        }
        return dto;
    }
    
    private Object getObjectCaseInsensitive(Row row, String col) {
        Object val = row.get(col);
        if (val != null) return val;
        val = row.get(col.toLowerCase());
        if (val != null) return val;
        val = row.get(col.toUpperCase());
        if (val != null) return val;
        for (String key : row.keySet()) {
            if (key.equalsIgnoreCase(col)) {
                return row.get(key);
            }
        }
        return null;
    }
    
    private Long getLong(Row row, String col) {
        Object val = getObjectCaseInsensitive(row, col);
        return (val instanceof Number) ? ((Number) val).longValue() : null;
    }
    
    private Integer getInt(Row row, String col) {
        Object val = getObjectCaseInsensitive(row, col);
        return (val instanceof Number) ? ((Number) val).intValue() : null;
    }
    
    private String getString(Row row, String col) {
        Object val = getObjectCaseInsensitive(row, col);
        return val != null ? val.toString() : null;
    }

    @Transactional
    public void deleteDueyPackage(Long id) {
        dueypackagesMapper.deleteById(id);
    }

    @Transactional
    public void sendDueyPackage(SendDueyReqDTO req) {
        if (req.getPackageId() != null) {
            updateDueyPackage(req);
        } else {
            // 批量发送逻辑
            List<Integer> targetReceiverIds = new ArrayList<>();
            if (Boolean.TRUE.equals(req.getIsAll())) {
                QueryWrapper query = QueryWrapper.create().select(CHARACTERS_D_O.ID);
                targetReceiverIds.addAll(charactersMapper.selectListByQueryAs(query, Integer.class));
            } else if (req.getReceiverIds() != null && !req.getReceiverIds().isEmpty()) {
                targetReceiverIds.addAll(req.getReceiverIds());
            } else if (req.getReceiverName() != null) {
                CharactersDO chr = charactersMapper.selectOneByQuery(QueryWrapper.create().where(CHARACTERS_D_O.NAME.eq(req.getReceiverName())));
                if (chr != null) {
                    targetReceiverIds.add(chr.getId());
                } else {
                    throw new RuntimeException("未找到收件人: " + req.getReceiverName());
                }
            }

            if (targetReceiverIds.isEmpty()) {
                throw new RuntimeException("未指定任何有效收件人");
            }

            for (Integer cid : targetReceiverIds) {
                sendPackageToReceiver(req, cid);
            }
        }
    }

    private void updateDueyPackage(SendDueyReqDTO req) {
        DueypackagesDO existingPackage = dueypackagesMapper.selectOneById(req.getPackageId());
        if (existingPackage == null) {
            throw new RuntimeException("未找到包裹: " + req.getPackageId());
        }

        if (req.getMesos() != null) existingPackage.setMesos(req.getMesos().longValue());
        if (req.getMessage() != null) existingPackage.setMessage(req.getMessage());
        if (req.getSenderName() != null) existingPackage.setSendername(req.getSenderName());
        if (req.getQuick() != null) existingPackage.setType(req.getQuick() ? 1 : 0);
        
        if (req.getReceiverIds() != null && !req.getReceiverIds().isEmpty()) {
            existingPackage.setReceiverid(req.getReceiverIds().get(0).longValue());
        } else if (req.getReceiverName() != null) {
            CharactersDO chr = charactersMapper.selectOneByQuery(QueryWrapper.create().where(CHARACTERS_D_O.NAME.eq(req.getReceiverName())));
            if (chr != null) {
                existingPackage.setReceiverid(chr.getId().longValue());
            }
        }

        if (req.getExpireTime() != null) {
            existingPackage.setExpireDate(new Timestamp(req.getExpireTime()));
        } else if (req.getExpireDays() != null && req.getExpireDays() > 0) {
             long expireTime = System.currentTimeMillis() + (req.getExpireDays() * 24 * 60 * 60 * 1000L);
             existingPackage.setExpireDate(new Timestamp(expireTime));
        }

        // 更新操作：同样遵循一个包裹一个物品的原则，只处理第一个物品
        if (req.getItems() != null && !req.getItems().isEmpty()) {
            DueyItemReqDTO itemReq = req.getItems().get(0);
            Item item = createItemFromReq(itemReq);
            if (item != null) {
                try {
                    // **核心：序列化到数据库时，不包含itemId**
                    ItemInfoRtnDTO itemDtoForJson = convertItemToItemInfoRtnDTO(item);
                    itemDtoForJson.setItemId(null); 
                    existingPackage.setItemData(objectMapper.writeValueAsString(itemDtoForJson));
                    
                    // **核心：将itemId存到独立字段**
                    existingPackage.setItemId(item.getItemId());
                    existingPackage.setUid(item.getUid());
                } catch (JsonProcessingException e) {
                    throw new RuntimeException("序列化物品数据失败", e);
                }
            }
        } else {
            // 如果没有物品，则清空物品信息
            existingPackage.setItemData(null);
            existingPackage.setItemId(0);
            existingPackage.setUid(0L);
        }

        dueypackagesMapper.update(existingPackage);
    }

    private void sendPackageToReceiver(SendDueyReqDTO req, Integer receiverId) {
        // 根据规范，一个包裹最多一个物品。如果请求中有多个物品，则为每个物品创建一个包裹。
        if (req.getItems() == null || req.getItems().isEmpty()) {
            // 如果没有物品，只发送金币和留言
            long expireTime = calculateExpireTime(req);
            DueyProcessor.createPackage(
                req.getMesos() != null ? req.getMesos().intValue() : 0,
                req.getMessage(),
                req.getSenderName() != null ? req.getSenderName() : "管理员",
                receiverId,
                Boolean.TRUE.equals(req.getQuick()),
                null, // 没有物品
                -1,
                expireTime,
                req.getDeliveryTime() != null ? req.getDeliveryTime() : 0
            );
        } else {
            // 如果有物品，为每个物品创建一个单独的包裹
            for (int i = 0; i < req.getItems().size(); i++) {
                DueyItemReqDTO itemReq = req.getItems().get(i);
                Item item = createItemFromReq(itemReq);
                if (item != null) {
                    // 只有第一个包裹包含金币和留言
                    Long mesos = (i == 0) ? (req.getMesos() != null ? req.getMesos().longValue() : 0L) : 0L;
                    String message = (i == 0) ? req.getMessage() : "批量发送的物品之一";
                    
                    long expireTime = calculateExpireTime(req);
                    DueyProcessor.createPackage(
                        mesos.intValue(),
                        message,
                        req.getSenderName() != null ? req.getSenderName() : "管理员",
                        receiverId,
                        Boolean.TRUE.equals(req.getQuick()),
                        item,
                        -1,
                        expireTime,
                        req.getDeliveryTime() != null ? req.getDeliveryTime() : 0
                    );
                }
            }
        }
    }
    
    private long calculateExpireTime(SendDueyReqDTO req) {
        if (req.getExpireTime() != null) return req.getExpireTime();
        if (req.getExpireDays() != null && req.getExpireDays() > 0) {
             return System.currentTimeMillis() + (req.getExpireDays() * 24 * 60 * 60 * 1000L);
        }
        // 默认过期时间，例如30天
        return System.currentTimeMillis() + (30L * 24 * 60 * 60 * 1000);
    }
    
    private Item createItemFromReq(DueyItemReqDTO req) {
        if (req.getItemId() == null || req.getQuantity() == null || req.getQuantity() <= 0) return null;
        
        Item item;
        if (ItemInformationProvider.getInstance().getInventoryType(req.getItemId()) == InventoryType.EQUIP) {
            Equip equip = new Equip(req.getItemId(), (byte) 0, -1);
            equip.setQuantity((short) 1); // 装备数量强制为1
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
        item.setUid(SnowflakeIdGenerator.getInstance().nextId());
        return item;
    }
    
    private short limitShort(Integer val) {
        if (val == null) return 0;
        return (val > Short.MAX_VALUE) ? Short.MAX_VALUE : (val < Short.MIN_VALUE) ? Short.MIN_VALUE : val.shortValue();
    }
    
    private byte limitByte(Integer val) {
        if (val == null) return 0;
        return (val > Byte.MAX_VALUE) ? Byte.MAX_VALUE : (val < Byte.MIN_VALUE) ? Byte.MIN_VALUE : val.byteValue();
    }
}
