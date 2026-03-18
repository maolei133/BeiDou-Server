/**
 * @author Matze
 * @author Ronan - improved check space feature and removed redundant object calls
 */
package org.gms.client.inventory.manipulator;

import org.apache.logging.log4j.message.MapMessage;
import org.gms.client.BuffStat;
import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.inventory.*;
import org.gms.config.GameConfig;
import org.gms.constants.id.ItemId;
import org.gms.constants.inventory.ItemConstants;
import org.gms.manager.ServerManager;
import org.gms.model.pojo.NewYearCardRecord;
import org.gms.model.pojo.TraceabilityRules;
import org.gms.server.ItemInformationProvider;
import org.gms.server.StatEffect;
import org.gms.server.ThreadManager;
import org.gms.server.logging.AuditLogger;
import org.gms.server.logging.LogAction;
import org.gms.server.logging.LogModule;
import org.gms.server.maps.MapleMap;
import org.gms.service.ItemFactoryService;
import org.gms.service.TraceabilityConfigService;
import org.gms.service.TraceabilityService;
import org.gms.util.I18nUtil;
import org.gms.util.PacketCreator;
import org.gms.util.Pair;
import org.gms.util.SpringContextUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.*;
import java.util.List;
import java.util.*;
import java.util.function.Consumer;

public class InventoryManipulator {
    private static final Logger log = LoggerFactory.getLogger(InventoryManipulator.class);
    private static final ItemFactoryService itemFactoryService = ServerManager.getApplicationContext().getBean(ItemFactoryService.class);
    private static final TraceabilityService traceabilityService = ServerManager.getApplicationContext().getBean(TraceabilityService.class);
    private static final TraceabilityConfigService configService = ServerManager.getApplicationContext().getBean(TraceabilityConfigService.class);

    public static boolean addById(Client c, int itemId, short quantity) {
        return addById(c, itemId, quantity, null, -1, -1);
    }

    public static boolean addById(Client c, int itemId, short quantity, long expiration) {
        return addById(c, itemId, quantity, null, -1, (byte) 0, expiration);
    }

    public static boolean addById(Client c, int itemId, short quantity, String owner, int petid) {
        return addById(c, itemId, quantity, owner, petid, -1);
    }
    
    public static boolean addById(Client c, int itemId, short quantity, String owner, int petid, Consumer<Item> tracker) {
        return addById(c, itemId, quantity, owner, petid, -1, tracker);
    }

    public static boolean addById(Client c, int itemId, short quantity, String owner, int petid, long expiration) {
        return addById(c, itemId, quantity, owner, petid, (byte) 0, expiration);
    }
    
    public static boolean addById(Client c, int itemId, short quantity, String owner, int petid, long expiration, Consumer<Item> tracker) {
        return addById(c, itemId, quantity, owner, petid, (byte) 0, expiration, tracker);
    }

    public static boolean addById(Client c, int itemId, short quantity, String owner, int petid, short flag, long expiration) {
        return addById(c, itemId, quantity, owner, petid, flag, expiration, null);
    }

    public static boolean addById(Client c, int itemId, short quantity, String owner, int petid, short flag, long expiration, Consumer<Item> tracker) {
        Character chr = c.getPlayer();
        InventoryType type = ItemConstants.getInventoryType(itemId);

        Inventory inv = chr.getInventory(type);
        inv.lockInventory();
        try {
            boolean result = addByIdInternal(c, chr, type, inv, itemId, quantity, owner, petid, flag, expiration, tracker);
            if (result) {
                // 实时保存
                final InventoryType finalType = type;
                ItemFactory.INVENTORY.saveItems(inv.list().stream().map(i -> new org.gms.util.Pair<>(i, finalType)).toList(), chr.getId(), Collections.singleton(finalType));
            }
            return result;
        } finally {
            inv.unlockInventory();
        }
    }

    private static boolean addByIdInternal(Client c, Character chr, InventoryType type, Inventory inv, int itemId, short quantity, String owner, int petid, short flag, long expiration, Consumer<Item> tracker) {
        ItemInformationProvider ii = ItemInformationProvider.getInstance();
        if (!type.equals(InventoryType.EQUIP)) {
            short slotMax = ii.getSlotMax(c, itemId);
            List<Item> existing = inv.listById(itemId);
            if (!ItemConstants.isRechargeable(itemId) && petid == -1) {
                if (existing.size() > 0) { // first update all existing slots to slotMax
                    Iterator<Item> i = existing.iterator();
                    while (quantity > 0) {
                        if (i.hasNext()) {
                            Item eItem = i.next();
                            short oldQ = eItem.getQuantity();
                            if (oldQ < slotMax && ((eItem.getOwner().equals(owner) || owner == null) && eItem.getFlag() == flag)) {
                                short newQ = (short) Math.min(oldQ + quantity, slotMax);
                                short addedQty = (short) (newQ - oldQ);

                                // 溯源日志：记录合并
                                traceabilityService.log(eItem, chr, TraceabilityService.ActionType.MERGE, "背包内合并", addedQty, String.format("数量: %d -> %d", oldQ, newQ), "合并到UID: " + eItem.getUid());

                                if (eItem.getExpiration() > 0) {
                                    if (expiration > 0) {
                                        double totalExp = (double) eItem.getExpiration() * oldQ + (double) expiration * addedQty;
                                        eItem.setExpiration((long) (totalExp / newQ));
                                    } else {
                                        eItem.setExpiration(expiration);
                                    }
                                }

                                quantity -= addedQty;
                                eItem.setQuantity(newQ);
                                c.sendPacket(PacketCreator.modifyInventory(true, Collections.singletonList(new ModifyInventory(1, eItem))));
                                if (tracker != null) tracker.accept(eItem);
                            }
                        } else {
                            break;
                        }
                    }
                }
                boolean sandboxItem = (flag & ItemConstants.SANDBOX) == ItemConstants.SANDBOX;
                while (quantity > 0) {
                    short newQ = (short) Math.min(quantity, slotMax);
                    if (newQ != 0) {
                        quantity -= newQ;
                        Item nItem = new Item(itemId, (short) 0, newQ, petid);
                        nItem.setFlag(flag);
                        nItem.setExpiration(expiration);
                        short newSlot = inv.addItem(nItem);
                        if (newSlot == -1) {
                            c.sendPacket(PacketCreator.getInventoryFull());
                            c.sendPacket(PacketCreator.getShowInventoryFull());
                            return false;
                        }
                        if (owner != null) {
                            nItem.setOwner(owner);
                        }
                        c.sendPacket(PacketCreator.modifyInventory(true, Collections.singletonList(new ModifyInventory(0, nItem))));
                        if (sandboxItem) {
                            chr.setHasSandboxItem();
                        }
                        if (tracker != null) tracker.accept(nItem);
                    } else {
                        c.sendPacket(PacketCreator.enableActions());
                        return false;
                    }
                }
            } else {
                Item nItem = new Item(itemId, (short) 0, quantity, petid);
                nItem.setFlag(flag);
                nItem.setExpiration(expiration);
                short newSlot = inv.addItem(nItem);
                if (newSlot == -1) {
                    c.sendPacket(PacketCreator.getInventoryFull());
                    c.sendPacket(PacketCreator.getShowInventoryFull());
                    return false;
                }
                c.sendPacket(PacketCreator.modifyInventory(true, Collections.singletonList(new ModifyInventory(0, nItem))));
                if (InventoryManipulator.isSandboxItem(nItem)) {
                    chr.setHasSandboxItem();
                }
                if (tracker != null) tracker.accept(nItem);
            }
        } else if (quantity == 1) {
            Item nEquip = ii.getEquipById(itemId);
            if (nEquip == null) {
                return false;
            }
            nEquip.setFlag(flag);
            nEquip.setExpiration(expiration);
            if (owner != null) {
                nEquip.setOwner(owner);
            }
            short newSlot = inv.addItem(nEquip);
            if (newSlot == -1) {
                c.sendPacket(PacketCreator.getInventoryFull());
                c.sendPacket(PacketCreator.getShowInventoryFull());
                return false;
            }
            c.sendPacket(PacketCreator.modifyInventory(true, Collections.singletonList(new ModifyInventory(0, nEquip))));
            if (InventoryManipulator.isSandboxItem(nEquip)) {
                chr.setHasSandboxItem();
            }
            if (tracker != null) tracker.accept(nEquip);
        } else {
            throw new RuntimeException("试图创建一件数量不为 1 的装备");
        }
        return true;
    }

    public static boolean addFromDrop(Client c, Item item) {
        return addFromDrop(c, item, true);
    }

    public static boolean addFromDrop(Client c, Item item, boolean show) {
        return addFromDrop(c, item, show, item.getPetId());
    }

    public static boolean addFromDrop(Client c, Item item, boolean show, int petId) {
        Character chr = c.getPlayer();
        InventoryType type = item.getInventoryType();

        Inventory inv = chr.getInventory(type);
        inv.lockInventory();
        try {
            boolean result = addFromDropInternal(c, chr, type, inv, item, show, petId);
            if (result) {
                // 实时保存
                final InventoryType finalType = type;
                ItemFactory.INVENTORY.saveItems(inv.list().stream().map(i -> new org.gms.util.Pair<>(i, finalType)).toList(), chr.getId(), Collections.singleton(finalType));
            }
            return result;
        } finally {
            inv.unlockInventory();
        }
    }

    private static boolean addFromDropInternal(Client c, Character chr, InventoryType type, Inventory inv, Item item, boolean show, int petId) {
        ItemInformationProvider ii = ItemInformationProvider.getInstance();
        // ----------------------------------------------------------------
        // 核心防复制检查：检查背包中是否已存在相同 UID 的物品
        // ----------------------------------------------------------------
        if (item.getUid() > 0) {
            Item existingItem = inv.findByUid(item.getUid());
            if (existingItem != null) {
                // 检查是否为可堆叠物品的合法合并操作
                boolean isStackable = !ItemConstants.isRechargeable(item.getItemId()) && ii.getSlotMax(c, item.getItemId()) > 1;
                if (existingItem.getItemId() == item.getItemId() && isStackable) {
                    // 是合法的堆叠物品合并，不应阻止。日志记录为调试信息。
                    log.debug("允许重复UID的堆叠物品合并。玩家: {}, 物品ID: {}, UID: {}", chr.getName(), item.getItemId(), item.getUid());
                } else {
                    // 否则，视为复制风险，拒绝入包
                    log.warn("拦截到重复UID物品入包请求 (可能是重复包或复制尝试)。玩家: {}, 物品ID: {}, UID: {}, 现有物品ID: {}",
                            chr.getName(), item.getItemId(), item.getUid(), existingItem.getItemId());

                    // 记录异常日志
                    traceabilityService.log(item, chr, TraceabilityService.ActionType.ADMIN_DELETE,
                            "DUPLICATE_UID_BLOCKED", item.getQuantity(), "由于背包中存在重复的UID，阻止了addFromDrop操作", "现有物品ID: " + existingItem.getItemId());

                    c.sendPacket(PacketCreator.serverNotice(1, "操作失败：检测到物品数据异常 (E01)。"));
                    c.sendPacket(PacketCreator.enableActions());
                    return false;
                }
            }
        }

        int itemid = item.getItemId();
        if (ii.isPickupRestricted(itemid) && chr.haveItemWithId(itemid, true)) {
            c.sendPacket(PacketCreator.getInventoryFull());
            c.sendPacket(PacketCreator.showItemUnavailable());
            return false;
        }
        short quantity = item.getQuantity();

        if (!type.equals(InventoryType.EQUIP)) {
            short slotMax = ii.getSlotMax(c, itemid);
            List<Item> existing = inv.listById(itemid);
            if (!ItemConstants.isRechargeable(itemid) && petId == -1) {
                if (existing.size() > 0) { // first update all existing slots to slotMax
                    Iterator<Item> i = existing.iterator();
                    while (quantity > 0) {
                        if (i.hasNext()) {
                            Item eItem = i.next();
                            short oldQ = eItem.getQuantity();
                            if (oldQ < slotMax && item.getFlag() == eItem.getFlag() && item.getOwner().equals(eItem.getOwner())) {
                                short newQ = (short) Math.min(oldQ + quantity, slotMax);
                                short addedQty = (short) (newQ - oldQ);

                                // 溯源日志：记录合并
                                traceabilityService.log(item, chr, TraceabilityService.ActionType.MERGE, "拾取合并", addedQty, String.format("数量: %d -> %d", oldQ, newQ), "合并到UID: " + eItem.getUid());

                                if (eItem.getExpiration() > 0) {
                                    if (item.getExpiration() > 0) {
                                        double totalExp = (double) eItem.getExpiration() * oldQ + (double) item.getExpiration() * addedQty;
                                        eItem.setExpiration((long) (totalExp / newQ));
                                    } else {
                                        eItem.setExpiration(item.getExpiration());
                                    }
                                }

                                quantity -= addedQty;
                                eItem.setQuantity(newQ);
                                item.setPosition(eItem.getPosition());
                                c.sendPacket(PacketCreator.modifyInventory(true, Collections.singletonList(new ModifyInventory(1, eItem))));
                            }
                        } else {
                            break;
                        }
                    }
                }
                while (quantity > 0) {
                    short newQ = (short) Math.min(quantity, slotMax);
                    quantity -= newQ;
                    Item nItem = new Item(itemid, (short) 0, newQ, petId);
                    nItem.setExpiration(item.getExpiration());
                    nItem.setOwner(item.getOwner());
                    nItem.setFlag(item.getFlag());
                    // 如果是拆分出来的新堆叠，必须生成新 UID
                    // 如果是完全移动（quantity == 0），则保留原 UID
                    if (quantity > 0) {
                         // 拆分情况：新堆叠生成新 UID
                         // 注意：这里 nItem 是新创建的对象，构造函数里已经生成了新 UID
                         // 但为了明确逻辑，如果 item 有 UID 且我们正在拆分它，
                         // 我们应该保留原 UID 给其中一部分（通常是留在原地的，或者这里是新进入背包的）
                         // 这里情况比较复杂：item 是来源物品。
                         // 如果 item 是整个放入背包，nItem 应该继承 item 的 UID。
                         // 如果 item 被拆分成多个 nItem（因为堆叠限制），第一个 nItem 继承 UID，后续的生成新 UID？
                         // 或者全部生成新 UID？
                         // 为了安全和简化，对于可堆叠物品的新堆叠，我们总是生成新 UID，除非是完全恢复（如从仓库取出整个堆叠）
                         // 但 addFromDrop 的 item 参数通常是一个临时对象（copy），它的 UID 可能是原物品的。
                         // 如果我们在这里生成新 UID，那么原物品的 UID 历史就断了。
                         // 考虑到这是“新进入背包”的物品，如果它没有合并到现有堆叠，它就是一个新的堆叠。
                         // 如果 item.getUid() > 0，我们应该尝试保留它。
                         // 但如果 quantity > 0，说明我们正在循环创建多个堆叠（因为超过 slotMax）。
                         // 这种情况下，只有第一个堆叠可以继承 UID，后续的必须是新的。
                         // 或者，为了避免 UID 冲突（如果背包里已经有这个 UID 的物品但满了），我们应该生成新的。
                         // 鉴于我们前面已经检查了 UID 冲突，这里如果能走到这，说明背包里没有这个 UID。
                         // 所以，第一个 nItem 可以继承 item.getUid()。
                         if (item.getUid() > 0 && nItem.getUid() != item.getUid()) {
                             // 只有当这是第一个分堆时才继承，但这里很难判断是第几个。
                             // 简单策略：总是生成新 UID，除非是装备。
                             // 这样虽然断了 UID 链，但绝对安全。
                             // 改进策略：对于可堆叠物品，入包即视为新实例（除非合并）。
                         }
                    } else {
                        // 刚好放完，或者最后一部分
                        if (item.getUid() > 0) {
                            nItem.setUid(item.getUid());
                        }
                    }
                    
                    short newSlot = inv.addItem(nItem);
                    if (newSlot == -1) {
                        c.sendPacket(PacketCreator.getInventoryFull());
                        c.sendPacket(PacketCreator.getShowInventoryFull());
                        item.setQuantity((short) (quantity + newQ));
                        return false;
                    }
                    nItem.setPosition(newSlot);
                    item.setPosition(newSlot);
                    c.sendPacket(PacketCreator.modifyInventory(true, Collections.singletonList(new ModifyInventory(0, nItem))));
                    if (InventoryManipulator.isSandboxItem(nItem)) {
                        chr.setHasSandboxItem();
                    }
                }
            } else {
                Item nItem = new Item(itemid, (short) 0, quantity, petId);
                nItem.setExpiration(item.getExpiration());
                nItem.setFlag(item.getFlag());
                if (item.getUid() > 0) {
                    nItem.setUid(item.getUid());
                }

                short newSlot = inv.addItem(nItem);
                if (newSlot == -1) {
                    c.sendPacket(PacketCreator.getInventoryFull());
                    c.sendPacket(PacketCreator.getShowInventoryFull());
                    return false;
                }
                nItem.setPosition(newSlot);
                item.setPosition(newSlot);
                c.sendPacket(PacketCreator.modifyInventory(true, Collections.singletonList(new ModifyInventory(0, nItem))));
                if (InventoryManipulator.isSandboxItem(nItem)) {
                    chr.setHasSandboxItem();
                }
                c.sendPacket(PacketCreator.enableActions());
            }
        } else if (quantity == 1) {
            short newSlot = inv.addItem(item);
            if (newSlot == -1) {
                c.sendPacket(PacketCreator.getInventoryFull());
                c.sendPacket(PacketCreator.getShowInventoryFull());
                return false;
            }
            item.setPosition(newSlot);
            c.sendPacket(PacketCreator.modifyInventory(true, Collections.singletonList(new ModifyInventory(0, item))));
            if (InventoryManipulator.isSandboxItem(item)) {
                chr.setHasSandboxItem();
            }
        } else {
            log.warn("尝试拾取数量大于 1 的装备 ID {} --> {}", itemid, quantity);
            c.sendPacket(PacketCreator.getInventoryFull());
            c.sendPacket(PacketCreator.showItemUnavailable());
            return false;
        }
        if (show) {
            c.sendPacket(PacketCreator.getShowItemGain(itemid, item.getQuantity()));
        }
        return true;
    }

    private static boolean haveItemWithId(Inventory inv, int itemid) {
        return inv.findById(itemid) != null;
    }

    public static boolean checkSpace(Client c, int itemid, int quantity, String owner) {
        ItemInformationProvider ii = ItemInformationProvider.getInstance();
        InventoryType type = ItemConstants.getInventoryType(itemid);
        Character chr = c.getPlayer();
        Inventory inv = chr.getInventory(type);

        if (ii.isPickupRestricted(itemid)) {
            if (haveItemWithId(inv, itemid)) {
                return false;
            } else if (ItemConstants.isEquipment(itemid) && haveItemWithId(chr.getInventory(InventoryType.EQUIPPED), itemid)) {
                return false;
            }
        }

        if (!type.equals(InventoryType.EQUIP)) {
            short slotMax = ii.getSlotMax(c, itemid);
            List<Item> existing = inv.listById(itemid);

            final int numSlotsNeeded;
            if (ItemConstants.isRechargeable(itemid)) {
                numSlotsNeeded = 1;
            } else {
                if (existing.size() > 0) // first update all existing slots to slotMax
                {
                    for (Item eItem : existing) {
                        short oldQ = eItem.getQuantity();
                        if (oldQ < slotMax && owner.equals(eItem.getOwner())) {
                            short newQ = (short) Math.min(oldQ + quantity, slotMax);
                            quantity -= (newQ - oldQ);
                        }
                        if (quantity <= 0) {
                            break;
                        }
                    }
                }

                if (slotMax > 0) {
                    numSlotsNeeded = (int) (Math.ceil(((double) quantity) / slotMax));
                } else {
                    numSlotsNeeded = 1;
                }
            }

            return !inv.isFull(numSlotsNeeded - 1);
        } else {
            return !inv.isFull();
        }
    }

    public static int checkSpaceProgressively(Client c, int itemid, int quantity, String owner, int usedSlots, boolean useProofInv) {
        // return value --> bit0: if has space for this one;
        //                  value after: new slots filled;
        // assumption: equipments always have slotMax == 1.

        int returnValue;

        ItemInformationProvider ii = ItemInformationProvider.getInstance();
        InventoryType type = !useProofInv ? ItemConstants.getInventoryType(itemid) : InventoryType.CANHOLD;
        Character chr = c.getPlayer();
        Inventory inv = chr.getInventory(type);

        if (ii.isPickupRestricted(itemid)) {
            if (haveItemWithId(inv, itemid)) {
                return 0;
            } else if (ItemConstants.isEquipment(itemid) && haveItemWithId(chr.getInventory(InventoryType.EQUIPPED), itemid)) {
                return 0;   // thanks Captain & Aika & Vcoc for pointing out inventory checkup on player trades missing out one-of-a-kind items.
            }
        }

        if (!type.equals(InventoryType.EQUIP)) {
            short slotMax = ii.getSlotMax(c, itemid);
            final int numSlotsNeeded;

            if (ItemConstants.isRechargeable(itemid)) {
                numSlotsNeeded = 1;
            } else {
                List<Item> existing = inv.listById(itemid);

                if (existing.size() > 0) // first update all existing slots to slotMax
                {
                    for (Item eItem : existing) {
                        short oldQ = eItem.getQuantity();
                        if (oldQ < slotMax && owner.equals(eItem.getOwner())) {
                            short newQ = (short) Math.min(oldQ + quantity, slotMax);
                            quantity -= (newQ - oldQ);
                        }
                        if (quantity <= 0) {
                            break;
                        }
                    }
                }

                if (slotMax > 0) {
                    numSlotsNeeded = (int) (Math.ceil(((double) quantity) / slotMax));
                } else {
                    numSlotsNeeded = 1;
                }
            }

            returnValue = ((numSlotsNeeded + usedSlots) << 1);
            returnValue += (numSlotsNeeded == 0 || !inv.isFullAfterSomeItems(numSlotsNeeded - 1, usedSlots)) ? 1 : 0;
            //System.out.print(" needed " + numSlotsNeeded + " used " + usedSlots + " rval " + returnValue);
        } else {
            returnValue = ((quantity + usedSlots) << 1);
            returnValue += (!inv.isFullAfterSomeItems(0, usedSlots)) ? 1 : 0;
            //System.out.print(" eqpneeded " + 1 + " used " + usedSlots + " rval " + returnValue);
        }

        return returnValue;
    }

    public static void removeFromSlot(Client c, InventoryType type, short slot, short quantity, boolean fromDrop) {
        removeFromSlot(c, type, slot, quantity, fromDrop, false);
    }

    public static void removeFromSlot(Client c, InventoryType type, short slot, short quantity, boolean fromDrop, boolean consume) {
        Character chr = c.getPlayer();
        if (chr == null) return;    //避免角色掉线导致空指针报错
        Inventory inv = chr.getInventory(type);
        Item item = inv.getItem(slot);
        boolean allowZero = consume && ItemConstants.isRechargeable(item.getItemId());

        if (type == InventoryType.EQUIPPED) {
            inv.lockInventory();
            try {
                chr.unequippedItem((Equip) item);
                inv.removeItem(slot, quantity, allowZero);
            } finally {
                inv.unlockInventory();
            }

            announceModifyInventory(c, item, fromDrop, allowZero);
        } else {
            int petid = item.getPetId();
            if (petid > -1) { // thanks Vcoc for finding a d/c issue with equipped pets and pets remaining on DB here
                int petIdx = chr.getPetIndex(petid);
                if (petIdx > -1) {
                    Pet pet = chr.getPet(petIdx);
                    chr.unEquipPet(pet, true);
                }

                inv.removeItem(slot, quantity, allowZero);
                if (type != InventoryType.CANHOLD) {
                    announceModifyInventory(c, item, fromDrop, allowZero);
                }

                // thanks Robin Schulz for noticing pet issues when moving pets out of inventory
            } else {
                inv.removeItem(slot, quantity, allowZero);
                if (type != InventoryType.CANHOLD) {
                    announceModifyInventory(c, item, fromDrop, allowZero);
                }
            }
        }
        
        // 实时保存
        final InventoryType finalType = type;
        ItemFactory.INVENTORY.saveItems(inv.list().stream().map(i -> new org.gms.util.Pair<>(i, finalType)).toList(), chr.getId(), Collections.singleton(finalType));
    }

    private static void announceModifyInventory(Client c, Item item, boolean fromDrop, boolean allowZero) {
        if (item.getQuantity() == 0 && !allowZero) {
            c.sendPacket(PacketCreator.modifyInventory(fromDrop, Collections.singletonList(new ModifyInventory(3, item))));
        } else {
            c.sendPacket(PacketCreator.modifyInventory(fromDrop, Collections.singletonList(new ModifyInventory(1, item))));
        }
    }

    public static void removeById(Client c, InventoryType type, int itemId, int quantity, boolean fromDrop, boolean consume) {
        int removeQuantity = quantity;
        Inventory inv = c.getPlayer().getInventory(type);
        int slotLimit = type == InventoryType.EQUIPPED ? 128 : inv.getSlotLimit();

        for (short i = 0; i <= slotLimit; i++) {
            Item item = inv.getItem((short) (type == InventoryType.EQUIPPED ? -i : i));
            if (item != null) {
                if (item.getItemId() == itemId || item.getCashId() == itemId) {
                    if (removeQuantity <= item.getQuantity()) {
                        removeFromSlot(c, type, item.getPosition(), (short) removeQuantity, fromDrop, consume);
                        removeQuantity = 0;
                        break;
                    } else {
                        removeQuantity -= item.getQuantity();
                        removeFromSlot(c, type, item.getPosition(), item.getQuantity(), fromDrop, consume);
                    }
                }
            }
        }
        if (removeQuantity > 0 && type != InventoryType.CANHOLD) {
            throw new RuntimeException("[Hack] 物品数量不足 Item:" + itemId + ", 数量 (剩余/总需): " + (quantity - removeQuantity) + "/" + quantity);
        }
    }

    private static boolean isSameOwner(Item source, Item target) {
        return source.getOwner().equals(target.getOwner());
    }

    public static void move(Client c, InventoryType type, short src, short dst) {
        Inventory inv = c.getPlayer().getInventory(type);

        if (src < 0 || dst < 0) {
            return;
        }
        if (dst > inv.getSlotLimit()) {
            return;
        }
        ItemInformationProvider ii = ItemInformationProvider.getInstance();
        Item source = inv.getItem(src);
        Item initialTarget = inv.getItem(dst);
        if (source == null) {
            return;
        }
        short olddstQ = -1;
        if (initialTarget != null) {
            olddstQ = initialTarget.getQuantity();
        }
        short oldsrcQ = source.getQuantity();
        short slotMax = ii.getSlotMax(c, source.getItemId());
        inv.move(src, dst, slotMax);
        final List<ModifyInventory> mods = new ArrayList<>();
        if (!(type.equals(InventoryType.EQUIP) || (type.equals(InventoryType.CASH) && (slotMax <= 1 || ItemConstants.isPet(source.getItemId()) || ItemConstants.isRing(source.getItemId())))) && initialTarget != null && initialTarget.getItemId() == source.getItemId() && !ItemConstants.isRechargeable(source.getItemId()) && isSameOwner(source, initialTarget)) {
            if ((olddstQ + oldsrcQ) > slotMax) {
                mods.add(new ModifyInventory(1, source));
                mods.add(new ModifyInventory(1, initialTarget));
            } else {
                mods.add(new ModifyInventory(3, source));
                mods.add(new ModifyInventory(1, initialTarget));
            }
        } else {
            mods.add(new ModifyInventory(2, source, src));
        }
        c.sendPacket(PacketCreator.modifyInventory(true, mods));
        // 添加物品代码提示
        if (GameConfig.getServerBoolean("use_debug") && c.getPlayer().isGM()) { // 假设isGM()是检查玩家是否是管理员的方法
            int itemID = source.getItemId();
            c.getPlayer().dropMessage(5, I18nUtil.getMessage("InventoryManipulator.handlePacket.message1") + itemID);
        }
        
        // 实时保存
        final InventoryType finalType = type;
        ItemFactory.INVENTORY.saveItems(inv.list().stream().map(i -> new org.gms.util.Pair<>(i, finalType)).toList(), c.getPlayer().getId(), Collections.singleton(finalType));
    }

    /*
    穿上装备判断
     */
    public static void equip(Client c, short src, short dst) {
        ItemInformationProvider ii = ItemInformationProvider.getInstance();

        Character chr = c.getPlayer();
        Inventory eqpInv = chr.getInventory(InventoryType.EQUIP);
        Inventory eqpdInv = chr.getInventory(InventoryType.EQUIPPED);

        Equip source = (Equip) eqpInv.getItem(src);
        int itemGender = ItemId.getGender(source.getItemId());
        //控制台参数为true时进行校验判断
        if(GameConfig.getServerBoolean("use_equipment_gender_limit") && itemGender != 2 && itemGender != chr.getGender()) {  //判断装备是否要求角色性别
            c.sendPacket(PacketCreator.enableActions());
            chr.dropMessage(1,I18nUtil.getMessage("InventoryManipulator.equip.message1"));    //发送弹窗提示性别不符
            log.warn(I18nUtil.getLogMessage("InventoryManipulator.warn.equip.message1"),      //后台记录信息
                    chr.getName(),
                    chr.getGender() <= 0 ? I18nUtil.getMessage("Character.Gender0") : I18nUtil.getMessage("Character.Gender1"),
                    ii.getName(source.getItemId()),
                    itemGender <= 0 ? I18nUtil.getMessage("Character.Gender0") : I18nUtil.getMessage("Character.Gender1"),
                    source.getItemId()
            );
            return;
        }
        if (source == null || !ii.canWearEquipment(chr, source, dst)) {
            c.sendPacket(PacketCreator.enableActions());
            return;
        } else if ((ItemId.isExplorerMount(source.getItemId()) && chr.isCygnus()) ||
                ((ItemId.isCygnusMount(source.getItemId())) && !chr.isCygnus())) {// Adventurer taming equipment    //冒险家驯服设备
            return;
        }
        boolean itemChanged = false;

        if (ii.isUntradeableOnEquip(source.getItemId())) {
            short flag = source.getFlag();      // thanks BHB for noticing flags missing after equipping these      //感谢BHB在安装这些设备后发现旗帜丢失
            flag |= ItemConstants.UNTRADEABLE;
            source.setFlag(flag);

            itemChanged = true;
        }
        switch (dst) {
        case -6: // unequip the overall
            Item top = eqpdInv.getItem((short) -5);
            if (top != null && ItemConstants.isOverall(top.getItemId())) {
                if (eqpInv.isFull()) {
                    c.sendPacket(PacketCreator.getInventoryFull());
                    c.sendPacket(PacketCreator.getShowInventoryFull());
                    return;
                }
                unequip(c, (byte) -5, eqpInv.getNextFreeSlot());
            }
            break;
        case -5:
            final Item bottom = eqpdInv.getItem((short) -6);
            if (bottom != null && ItemConstants.isOverall(source.getItemId())) {
                if (eqpInv.isFull()) {
                    c.sendPacket(PacketCreator.getInventoryFull());
                    c.sendPacket(PacketCreator.getShowInventoryFull());
                    return;
                }
                unequip(c, (byte) -6, eqpInv.getNextFreeSlot());
            }
            break;
        case -10: // check if weapon is two-handed
            Item weapon = eqpdInv.getItem((short) -11);
            if (weapon != null && ii.isTwoHanded(weapon.getItemId())) {
                if (eqpInv.isFull()) {
                    c.sendPacket(PacketCreator.getInventoryFull());
                    c.sendPacket(PacketCreator.getShowInventoryFull());
                    return;
                }
                unequip(c, (byte) -11, eqpInv.getNextFreeSlot());
            }
            break;
        case -11:
            Item shield = eqpdInv.getItem((short) -10);
            if (shield != null && ii.isTwoHanded(source.getItemId())) {
                if (eqpInv.isFull()) {
                    c.sendPacket(PacketCreator.getInventoryFull());
                    c.sendPacket(PacketCreator.getShowInventoryFull());
                    return;
                }
                unequip(c, (byte) -10, eqpInv.getNextFreeSlot());
            }
            break;
        case -18:
            if (chr.getMapleMount() != null) {
                chr.getMapleMount().setItemId(source.getItemId());
            }
            break;
        }

        //1112413, 1112414, 1112405 (Lilin's Ring)
        source = (Equip) eqpInv.getItem(src);
        eqpInv.removeSlot(src);

        Equip target;
        eqpdInv.lockInventory();
        try {
            target = (Equip) eqpdInv.getItem(dst);
            if (target != null) {
                chr.unequippedItem(target);
                eqpdInv.removeSlot(dst);
            }
        } finally {
            eqpdInv.unlockInventory();
        }

        final List<ModifyInventory> mods = new ArrayList<>();
        if (itemChanged) {
            mods.add(new ModifyInventory(3, source));
            mods.add(new ModifyInventory(0, source.copy()));//to prevent crashes
        }

        source.setPosition(dst);

        eqpdInv.lockInventory();
        try {
            if (source.getRingId() > -1) {
                chr.getRingById(source.getRingId()).equip();
            }
            chr.equippedItem(source);
            eqpdInv.addItemFromDB(source);
        } finally {
            eqpdInv.unlockInventory();
        }

        if (target != null) {
            target.setPosition(src);
            eqpInv.addItemFromDB(target);
        }
        if (chr.getBuffedValue(BuffStat.BOOSTER) != null && ItemConstants.isWeapon(source.getItemId())) {
            chr.cancelBuffStats(BuffStat.BOOSTER);
        }

        mods.add(new ModifyInventory(2, source, src));
        c.sendPacket(PacketCreator.modifyInventory(true, mods));
        chr.equipChanged();

        // 实时保存
        ItemFactory.INVENTORY.saveItems(eqpInv.list().stream().map(i -> new org.gms.util.Pair<>(i, InventoryType.EQUIP)).toList(), chr.getId(), Collections.singleton(InventoryType.EQUIP));
        ItemFactory.INVENTORY.saveItems(eqpdInv.list().stream().map(i -> new org.gms.util.Pair<>(i, InventoryType.EQUIPPED)).toList(), chr.getId(), Collections.singleton(InventoryType.EQUIPPED));
    }

    public static void unequip(Client c, short src, short dst) {
        Character chr = c.getPlayer();
        Inventory eqpInv = chr.getInventory(InventoryType.EQUIP);
        Inventory eqpdInv = chr.getInventory(InventoryType.EQUIPPED);

        Equip source = (Equip) eqpdInv.getItem(src);
        Equip target = (Equip) eqpInv.getItem(dst);
        if (dst < 0) {
            return;
        }
        if (source == null) {
            return;
        }
        if (target != null && src <= 0) {
            c.sendPacket(PacketCreator.getInventoryFull());
            return;
        }

        eqpdInv.lockInventory();
        try {
            if (source.getRingId() > -1) {
                chr.getRingById(source.getRingId()).unequip();
            }
            chr.unequippedItem(source);
            eqpdInv.removeSlot(src);
        } finally {
            eqpdInv.unlockInventory();
        }

        if (target != null) {
            eqpInv.removeSlot(dst);
        }
        source.setPosition(dst);
        eqpInv.addItemFromDB(source);
        if (target != null) {
            target.setPosition(src);
            eqpdInv.addItemFromDB(target);
        }
        c.sendPacket(PacketCreator.modifyInventory(true, Collections.singletonList(new ModifyInventory(2, source, src))));
        chr.equipChanged();
        
        // 实时保存
        ItemFactory.INVENTORY.saveItems(eqpInv.list().stream().map(i -> new org.gms.util.Pair<>(i, InventoryType.EQUIP)).toList(), chr.getId(), Collections.singleton(InventoryType.EQUIP));
        ItemFactory.INVENTORY.saveItems(eqpdInv.list().stream().map(i -> new org.gms.util.Pair<>(i, InventoryType.EQUIPPED)).toList(), chr.getId(), Collections.singleton(InventoryType.EQUIPPED));
    }

    private static boolean isDisappearingItemDrop(Item it) {
        ItemInformationProvider ii = ItemInformationProvider.getInstance();
        if (ii.isDropRestricted(it.getItemId())) {
            return true;
        } else if (ii.isCash(it.getItemId())) {
            if (GameConfig.getServerBoolean("use_enforce_unmerchable_cash")) {     // thanks Ari for noticing cash drops not available server-side
                return true;
            } else {
                return ItemConstants.isPet(it.getItemId()) && GameConfig.getServerBoolean("use_enforce_unmerchable_pet");
            }
        } else if (isDroppedItemRestricted(it)) {
            return true;
        } else {
            return ItemId.isWeddingRing(it.getItemId());
        }
    }

    public static void drop(Client c, InventoryType type, short src, short quantity) {
        if (src < 0) {
            type = InventoryType.EQUIPPED;
        }

        Character chr = c.getPlayer();
        Inventory inv = chr.getInventory(type);
        Item source = inv.getItem(src);

        if (chr.isGM() && chr.gmLevel() < GameConfig.getServerInt("minimum_gm_level_to_drop")) {
            chr.message("您的 GM 等级不足，无法丢弃物品。");
            log.info("GM %s 尝试丢弃物品 ID %d", chr.getName(), source.getItemId());
            return;
        }

        if (chr.getTrade() != null || chr.getMiniGame() != null || source == null) { //Only check needed would prob be merchants (to see if the player is in one)
            return;
        }
        int itemId = source.getItemId();

        MapleMap map = chr.getMap();
        if ((!ItemConstants.isRechargeable(itemId) && source.getQuantity() < quantity) || quantity < 0) {
            return;
        }

        int petid = source.getPetId();
        if (petid > -1) {
            int petIdx = chr.getPetIndex(petid);
            if (petIdx > -1) {
                Pet pet = chr.getPet(petIdx);
                chr.unEquipPet(pet, true);
            }
        }

        // 物品找回系统拦截点，单纯丢出到地图上无需记录
        // 修改：在丢弃时记录找回，但状态设为 PENDING (待确认)，防止“丢弃->找回->拾取”的复制漏洞
        // 只有当物品真正从地图上消失时，才会激活为 RECOVERABLE
/*        if (isValuableForRecovery(source)) {
            TraceabilityService traceabilityService = SpringContextUtil.getBean(TraceabilityService.class);
            traceabilityService.logRecovery(source, chr, "DROP");
        }*/
        
        // 准备溯源日志信息
        String dropSource = String.format("玩家丢弃于地图: %s(%d)", map.getMapName(), map.getId());

        Point dropPos = new Point(chr.getPosition());
        if (quantity < source.getQuantity() && !ItemConstants.isRechargeable(itemId)) {
            Item target = source.copy();
            target.setQuantity(quantity);
            source.setQuantity((short) (source.getQuantity() - quantity));
            c.sendPacket(PacketCreator.modifyInventory(true, Collections.singletonList(new ModifyInventory(1, source))));

            if (ItemConstants.isNewYearCardEtc(itemId)) {
                if (itemId == ItemId.NEW_YEARS_CARD_SEND) {
                    NewYearCardRecord.removeAllNewYearCard(true, chr);
                    c.getAbstractPlayerInteraction().removeAll(ItemId.NEW_YEARS_CARD_SEND);
                } else {
                    NewYearCardRecord.removeAllNewYearCard(false, chr);
                    c.getAbstractPlayerInteraction().removeAll(ItemId.NEW_YEARS_CARD_RECEIVED);
                }
            }

            if (isDisappearingItemDrop(target)) {
                map.disappearingItemDrop(chr, chr, target, dropPos);
                // 对于直接消失的物品，立即激活找回状态，并记录溯源日志
                if (isValuableForRecovery(target)) {
                    traceabilityService.activateRecovery(target.getUid());
                    traceabilityService.log(target, chr, TraceabilityService.ActionType.DROP, dropSource, -quantity, null, "直接销毁");
                }
            } else {
                map.spawnItemDrop(chr, chr, target, dropPos, true, true);
                // 溯源日志：记录丢弃到地图的物品
//                traceabilityService.log(target, chr, TraceabilityService.ActionType.DROP, dropSource, -quantity);
            }
        } else {
            if (type == InventoryType.EQUIPPED) {
                inv.lockInventory();
                try {
                    chr.unequippedItem((Equip) source);
                    inv.removeSlot(src);
                } finally {
                    inv.unlockInventory();
                }
            } else {
                inv.removeSlot(src);
            }

            c.sendPacket(PacketCreator.modifyInventory(true, Collections.singletonList(new ModifyInventory(3, source))));
            if (src < 0) {
                chr.equipChanged();
            } else if (ItemConstants.isNewYearCardEtc(itemId)) {
                if (itemId == ItemId.NEW_YEARS_CARD_SEND) {
                    NewYearCardRecord.removeAllNewYearCard(true, chr);
                    c.getAbstractPlayerInteraction().removeAll(ItemId.NEW_YEARS_CARD_SEND);
                } else {
                    NewYearCardRecord.removeAllNewYearCard(false, chr);
                    c.getAbstractPlayerInteraction().removeAll(ItemId.NEW_YEARS_CARD_RECEIVED);
                }
            }

            if (isDisappearingItemDrop(source)) {
                map.disappearingItemDrop(chr, chr, source, dropPos);
                // 对于直接消失的物品，立即激活找回状态，并记录溯源日志
                if (isValuableForRecovery(source)) {
                    traceabilityService.activateRecovery(source.getUid());
                    traceabilityService.log(source, chr, TraceabilityService.ActionType.DROP, dropSource, -quantity, null, "直接销毁");
                }
            } else {
                map.spawnItemDrop(chr, chr, source, dropPos, true, true);
                // 溯源日志：记录丢弃到地图的物品
//                traceabilityService.log(source, chr, TraceabilityService.ActionType.DROP, dropSource, -quantity);
            }
        }

        int quantityNow = chr.getItemQuantity(itemId, false);
        if (itemId == chr.getItemEffect()) {
            if (quantityNow <= 0) {
                chr.setItemEffect(0);
                map.broadcastMessage(PacketCreator.itemEffect(chr.getId(), 0));
            }
        } else if (itemId == ItemId.CHALKBOARD_1 || itemId == ItemId.CHALKBOARD_2) {
            if (source.getQuantity() <= 0) {
                chr.setChalkboard(null);
            }
        } else if (itemId == ItemId.ARPQ_SPIRIT_JEWEL) {
            chr.updateAriantScore(quantityNow);
        }
        
        // 实时保存
        final InventoryType finalType = type;
        ItemFactory.INVENTORY.saveItems(inv.list().stream().map(i -> new org.gms.util.Pair<>(i, finalType)).toList(), chr.getId(), Collections.singleton(finalType));
    }

    private static boolean isDroppedItemRestricted(Item it) {
        return GameConfig.getServerBoolean("use_erase_untradeable_drop") && it.isUntradeable();
    }

    public static boolean isSandboxItem(Item it) {
        return (it.getFlag() & ItemConstants.SANDBOX) == ItemConstants.SANDBOX;
    }

    /**
     * 计算装备的属性总和（不包括HP/MP），用于价值判断。
     * @param equip 要计算的装备对象
     * @return 属性总和
     */
    private static long calculateEquipStatsSum(Equip equip) {
        if (equip == null) {
            return 0;
        }
        long sum = 0;
        sum += equip.getStr();
        sum += equip.getDex();
        sum += equip.getInt();
        sum += equip.getLuk();
        sum += equip.getWatk();
        sum += equip.getMatk();
        sum += equip.getWdef();
        sum += equip.getMdef();
        sum += equip.getAcc();
        sum += equip.getAvoid();
        sum += equip.getHands();
        sum += equip.getSpeed();
        sum += equip.getJump();
        return sum;
    }

    /**
     * (V2.2) 判断物品是否值得进入找回系统或溯源系统.
     * <p>
     * 此方法现在完全由溯源系统的动态配置驱动。
     * </p>
     *
     * @param item 要判断的物品
     * @return 如果物品被视为“有价值”，则返回true
     */
    public static boolean isValuableForRecovery(Item item) {
        if (item == null) return false;

        TraceabilityRules config = configService.getTraceabilityConfig();
        TraceabilityRules.ValueConditions conditions = config.getValueConditions();
        if (conditions == null) {
            return false; // 如果没有配置规则，则默认所有物品都无价值
        }

        int itemId = item.getItemId();
        ItemInformationProvider ii = ItemInformationProvider.getInstance();

        // 0. 现金物品：总是被视为有价值
        if (ii.isCash(itemId)) {
            return true;
        }

        // 1. 装备判断
        if (item instanceof Equip equip) {
            TraceabilityRules.Equip equipConditions = conditions.getEquip();
            if (equipConditions != null) {
                // 检查：如果装备穿戴等级大于等于设定值（通常120以上视为高价值）
                if (equipConditions.getMinLevel() > 0 && ii.getEquipLevelReq(itemId) >= equipConditions.getMinLevel()) {
                    return true;
                }
                // 检查：如果装备已经砸卷超过指定的次数（即当前可用槽数被消耗了指定次数以上）
                if (equipConditions.getMinUpgradeSlotsUsed() > 0 && equip.getLevel() >= equipConditions.getMinUpgradeSlotsUsed()) {
                    return true;
                }
                // 检查：如果装备的成长等级（如特殊可升级装备）超过指定的等级
                if (equipConditions.getMinGrowthLevel() > 0 && equip.getItemLevel() >= equipConditions.getMinGrowthLevel()) {
                    return true;
                }
                // 检查：如果装备使用的金锤子次数大于等于设定的次数
                if (equipConditions.getMinViciousHammerUsed() > 0 && equip.getVicious() >= equipConditions.getMinViciousHammerUsed()) {
                    return true;
                }
                // 检查：如果装备当前属性总和(不含HP/MP)超过白板属性大于等于设定的值
                int minStatsAboveBase = equipConditions.getMinStatsAboveBase();
                if (minStatsAboveBase > 0) {
                    Equip baseEquip = (Equip) ii.getEquipById(itemId);
                    if (baseEquip != null) {
                        long currentStatsSum = calculateEquipStatsSum(equip);
                        long baseStatsSum = calculateEquipStatsSum(baseEquip);
                        if (currentStatsSum - baseStatsSum >= minStatsAboveBase) {
                            return true;
                        }
                    }
                }
            }
        }

        // 2. 特定物品ID列表判断（如特殊的纪念道具、神级物品）
        TraceabilityRules.Item itemConditions = conditions.getItem();
        if (itemConditions != null) {
            List<Integer> specificItemIds = itemConditions.getSpecificItemIds();
            if (specificItemIds != null && specificItemIds.contains(itemId)) {
                return true;
            }

            // 3. 物品类型判断
            List<TraceabilityRules.ItemType> itemTypes = itemConditions.getItemTypes();
            if (itemTypes != null && !itemTypes.isEmpty()) {
                int itemPrefix = itemId / 10000;
                for (TraceabilityRules.ItemType it : itemTypes) {
                    if (it.getT() == itemPrefix) {
                        return true;
                    }
                }
            }

            // 兼容以前的硬编码检查
            if (itemConditions.isScrolls() && itemId / 10000 == 204) {
                return true;
            }
            if (itemConditions.isSkillBooks() && itemId / 10000 == 228) {
                return true;
            }
            if (itemConditions.isMasteryBooks() && itemId / 10000 == 229) {
                return true;
            }
        }

        return false;
    }
}
