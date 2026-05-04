package org.gms.util;

import org.gms.client.inventory.Equip;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.constants.inventory.ItemConstants;
import org.gms.model.dto.ItemInfoRtnDTO;

/**
 * 物品对象转换工具类
 */
public class ItemConverter {

    /**
     * 从 DTO 恢复物品对象 (兼容旧调用)。
     * <p>
     * 此方法用于处理没有明确提供 quantity 的场景 (如物品找回系统的旧日志)。
     * 它会尝试从 DTO 中读取 quantity (如果存在于旧JSON中)，否则默认为 1。
     *
     * @param itemId   物品的模板ID
     * @param itemDTO  包含物品属性的DTO对象
     * @return 恢复的物品对象
     * @deprecated 推荐使用 {@link #restoreItemFromDTO(int, short, ItemInfoRtnDTO)}
     */
    @Deprecated
    public static Item restoreItemFromDTO(int itemId, ItemInfoRtnDTO itemDTO) {
        // 兼容性处理：如果旧JSON中包含quantity，则使用它，否则默认为1
        short quantity = (itemDTO.getQuantity() != null) ? itemDTO.getQuantity().shortValue() : 1;
        return restoreItemFromDTO(itemId, quantity, itemDTO);
    }

    /**
     * 从 DTO 恢复物品对象 (标准方法)。
     * <p>
     * 注意：
     * 1. 此方法不再从DTO中读取itemId和quantity，这两个值必须由调用方从数据库的独立字段提供。
     * 2. 此方法不会设置 UID，调用方需要从数据库中获取该值并手动设置。
     *
     * @param itemId   物品的模板ID (从数据库独立字段读取)
     * @param quantity 物品的数量 (从数据库独立字段读取)
     * @param itemDTO  只包含物品扩展属性的DTO对象
     * @return 恢复的物品对象 (Item 或 Equip)
     */
    public static Item restoreItemFromDTO(int itemId, short quantity, ItemInfoRtnDTO itemDTO) {
        Item item;
        int petId = (itemDTO.getPetId() == null || itemDTO.getPetId() == 0) ? -1 : itemDTO.getPetId();

        if (ItemConstants.getInventoryType(itemId) == InventoryType.EQUIP) {
            Equip equip = new Equip(itemId, (byte) 0, -1);
            equip.setQuantity(quantity); // 直接使用传入的quantity
            if (itemDTO.getStr() != null) equip.setStr(itemDTO.getStr());
            if (itemDTO.getDex() != null) equip.setDex(itemDTO.getDex());
            if (itemDTO.getInt_() != null) equip.setInt(itemDTO.getInt_());
            if (itemDTO.getLuk() != null) equip.setLuk(itemDTO.getLuk());
            if (itemDTO.getHp() != null) equip.setHp(itemDTO.getHp());
            if (itemDTO.getMp() != null) equip.setMp(itemDTO.getMp());
            if (itemDTO.getWatk() != null) equip.setWatk(itemDTO.getWatk());
            if (itemDTO.getMatk() != null) equip.setMatk(itemDTO.getMatk());
            if (itemDTO.getWdef() != null) equip.setWdef(itemDTO.getWdef());
            if (itemDTO.getMdef() != null) equip.setMdef(itemDTO.getMdef());
            if (itemDTO.getAcc() != null) equip.setAcc(itemDTO.getAcc());
            if (itemDTO.getAvoid() != null) equip.setAvoid(itemDTO.getAvoid());
            if (itemDTO.getHands() != null) equip.setHands(itemDTO.getHands());
            if (itemDTO.getSpeed() != null) equip.setSpeed(itemDTO.getSpeed());
            if (itemDTO.getJump() != null) equip.setJump(itemDTO.getJump());
            equip.setUpgradeSlots(itemDTO.getUpgradeSlots() != null ? itemDTO.getUpgradeSlots() : 0);
            if (itemDTO.getLevel() != null) equip.setLevel(itemDTO.getLevel());
            if (itemDTO.getItemLevel() != null) equip.setItemLevel(itemDTO.getItemLevel());
            if (itemDTO.getFlag() != null) equip.setFlag(itemDTO.getFlag().shortValue());
            if (itemDTO.getVicious() != null) equip.setVicious(itemDTO.getVicious());
            if (itemDTO.getOwner() != null) equip.setOwner(itemDTO.getOwner());
            if (itemDTO.getExpiration() != null) equip.setExpiration(itemDTO.getExpiration());
            item = equip;
        } else {
            // 对于普通物品, 直接使用传入的 quantity
            item = new Item(itemId, (byte) 0, quantity, petId);
            if (itemDTO.getOwner() != null) item.setOwner(itemDTO.getOwner());
            if (itemDTO.getExpiration() != null) item.setExpiration(itemDTO.getExpiration());
        }
        return item;
    }
}
