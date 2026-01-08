package org.gms.service;


import lombok.extern.slf4j.Slf4j;
import org.gms.client.inventory.Equip;
import org.gms.client.inventory.InventoryType;
import org.gms.constants.inventory.ItemConstants;
import org.gms.exception.BizException;
import org.gms.server.ItemInformationProvider;
import org.gms.util.I18nUtil;
import org.gms.util.Pair;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class ItemService {
    public Equip getEquipmentInfoByItemId(Integer itemId) {
        ItemInformationProvider ii = ItemInformationProvider.getInstance();
//        String itemName = ii.getName(itemId);
        Equip equip = (Equip) ItemInformationProvider.getInstance().getEquipById(itemId);
        if (equip == null) {
            throw new BizException(I18nUtil.getExceptionMessage("EQUIP_NOT_FOUND"));
        }

        if (!ItemConstants.getInventoryType(itemId).equals(InventoryType.EQUIP)) {
            throw new BizException(I18nUtil.getExceptionMessage("ONLY_SUPPORT_GIVE_EQUIP"));
        }
        return equip;
    }

    public Pair<String, String> getNameDesc(Integer itemId) {
        ItemInformationProvider ii = ItemInformationProvider.getInstance();
        Pair<String, String> nameDesc = ii.getNameDesc(itemId);
        if (nameDesc == null) {
            throw new BizException(I18nUtil.getExceptionMessage("ITEM_NOT_FOUND"));
        }
        return nameDesc;
    }

    public Pair<String, String> getItemInfoByItemId(Integer itemId) {
        Pair<String, String> nameDesc = getNameDesc(itemId);
        if (ItemConstants.getInventoryType(itemId).equals(InventoryType.EQUIP)) {
            throw new BizException(I18nUtil.getExceptionMessage("ONLY_SUPPORT_GIVE_ITEM"));
        }
        return nameDesc;
    }
}
