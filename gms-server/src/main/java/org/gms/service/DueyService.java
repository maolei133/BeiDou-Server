package org.gms.service;

import com.mybatisflex.core.paginate.Page;
import com.mybatisflex.core.query.QueryWrapper;
import com.mybatisflex.core.row.Db;
import com.mybatisflex.core.row.Row;
import lombok.AllArgsConstructor;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.ItemFactory;
import org.gms.dao.entity.CharactersDO;
import org.gms.dao.entity.DueypackagesDO;
import org.gms.dao.mapper.CharactersMapper;
import org.gms.dao.mapper.DueypackagesMapper;
import org.gms.model.dto.DueyPackageRtnDTO;
import org.gms.model.dto.DueySearchReqDTO;
import org.gms.model.dto.ItemInfoRtnDTO;
import org.gms.model.dto.SendDueyReqDTO;
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
        if (timestampObj instanceof Timestamp) {
            dto.setTimestamp((Timestamp) timestampObj);
        }
        
        dto.setMessage(getString(row, "message"));
        dto.setChecked(getInt(row, "checked"));
        dto.setType(getInt(row, "type"));

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
        } else {
            Integer receiverId = req.getReceiverId();
            if (receiverId == null && req.getReceiverName() != null) {
                CharactersDO chr = charactersMapper.selectOneByQuery(QueryWrapper.create().where(CHARACTERS_D_O.NAME.eq(req.getReceiverName())));
                if (chr != null) {
                    receiverId = chr.getId();
                }
            }

            if (receiverId != null) {
                sendSinglePackage(req, receiverId);
            } else {
                throw new RuntimeException("Receiver not found");
            }
        }
    }

    private void sendSinglePackage(SendDueyReqDTO req, Integer receiverId) {
        Item item = null;
        if (req.getItemId() != null && req.getQuantity() != null && req.getQuantity() > 0) {
            item = new Item(req.getItemId(), (byte) 0, req.getQuantity().shortValue(), -1);
            // 设置过期时间
            if (req.getExpireTime() != null) {
                item.setExpiration(req.getExpireTime());
            } else if (req.getExpireDays() != null && req.getExpireDays() > 0) {
                 long expireTime = System.currentTimeMillis() + (req.getExpireDays() * 24 * 60 * 60 * 1000L);
                 item.setExpiration(expireTime);
            }
        }
        
        String sender = req.getSenderName() != null && !req.getSenderName().isEmpty() ? req.getSenderName() : "管理员";

        DueypackagesDO newPackage = new DueypackagesDO();
        newPackage.setReceiverid(receiverId.longValue());
        newPackage.setSendername(sender);
        newPackage.setMesos(req.getMesos() != null ? req.getMesos().longValue() : 0L);
        newPackage.setTimestamp(new Timestamp(System.currentTimeMillis()));
        newPackage.setMessage(req.getMessage());
        newPackage.setType(Boolean.TRUE.equals(req.getQuick()) ? 1 : 0);
        newPackage.setChecked(1);

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
