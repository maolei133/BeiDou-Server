/*
    This file is part of the HeavenMS MapleStory Server
    Copyleft (L) 2016 - 2019 RonanLana

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation version 3 as published by
    the Free Software Foundation. You may not use, modify or distribute
    this program under any other version of the GNU Affero General Public
    License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package org.gms.client.processor.action;

import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.inventory.Equip;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.manipulator.InventoryManipulator;
import org.gms.config.GameConfig;
import org.gms.constants.game.GameConstants;
import org.gms.constants.id.ItemId;
import org.gms.constants.inventory.ItemConstants;
import org.gms.manager.ServerManager;
import org.gms.net.packet.InPacket;
import org.gms.service.TraceabilityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.gms.server.ItemInformationProvider;
import org.gms.server.MakerItemFactory;
import org.gms.server.MakerItemFactory.MakerItemCreateEntry;
import org.gms.util.PacketCreator;
import org.gms.util.Pair;

import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * @author Ronan
 */
public class MakerProcessor {
    private static final Logger log = LoggerFactory.getLogger(MakerProcessor.class);
    private static final ItemInformationProvider ii = ItemInformationProvider.getInstance();
    private static final TraceabilityService traceabilityService = ServerManager.getApplicationContext().getBean(TraceabilityService.class);

    public static void makerAction(InPacket p, Client c) {
        if (c.tryacquireClient()) {
            try {
                int type = p.readInt();
                int toCreate = p.readInt();
                int toDisassemble = -1, pos = -1;
                boolean makerSucceeded = true;

                MakerItemCreateEntry recipe;
                Map<Integer, Short> reagentids = new LinkedHashMap<>();
                int stimulantid = -1;

                if (type == 3) {    // building monster crystal
                    int fromLeftover = toCreate;
                    toCreate = ii.getMakerCrystalFromLeftover(toCreate);
                    if (toCreate == -1) {
                        c.sendPacket(PacketCreator.serverNotice(1, ii.getName(fromLeftover) + " 无法用于怪物水晶转换。"));
                        c.sendPacket(PacketCreator.makerEnableActions());
                        return;
                    }

                    recipe = MakerItemFactory.generateLeftoverCrystalEntry(fromLeftover, toCreate);
                } else if (type == 4) {  // disassembling
                    p.readInt(); // 1... probably inventory type
                    pos = p.readInt();

                    Item it = c.getPlayer().getInventory(InventoryType.EQUIP).getItem((short) pos);
                    if (it != null && it.getItemId() == toCreate) {
                        toDisassemble = toCreate;

                        Pair<Integer, List<Pair<Integer, Integer>>> pair = generateDisassemblyInfo(toDisassemble);
                        if (pair != null) {
                            recipe = MakerItemFactory.generateDisassemblyCrystalEntry(toDisassemble, pair.getLeft(), pair.getRight());
                        } else {
                            c.sendPacket(PacketCreator.serverNotice(1, ii.getName(toCreate) + " 无法用于怪物水晶拆解。"));
                            c.sendPacket(PacketCreator.makerEnableActions());
                            return;
                        }
                    } else {
                        c.sendPacket(PacketCreator.serverNotice(1, "尝试拆解该物品时发生未知错误。"));
                        c.sendPacket(PacketCreator.makerEnableActions());
                        return;
                    }
                } else {
                    if (ItemConstants.isEquipment(toCreate)) {   // only equips uses stimulant and reagents
                        if (p.readByte() != 0) {  // stimulant
                            stimulantid = ii.getMakerStimulant(toCreate);
                            if (!c.getAbstractPlayerInteraction().haveItem(stimulantid)) {
                                stimulantid = -1;
                            }
                        }

                        int reagents = Math.min(p.readInt(), getMakerReagentSlots(toCreate));
                        for (int i = 0; i < reagents; i++) {  // crystals
                            int reagentid = p.readInt();
                            if (ItemConstants.isMakerReagent(reagentid)) {
                                Short rs = reagentids.get(reagentid);
                                if (rs == null) {
                                    reagentids.put(reagentid, (short) 1);
                                } else {
                                    reagentids.put(reagentid, (short) (rs + 1));
                                }
                            }
                        }

                        List<Pair<Integer, Short>> toUpdate = new LinkedList<>();
                        for (Map.Entry<Integer, Short> r : reagentids.entrySet()) {
                            int qty = c.getAbstractPlayerInteraction().getItemQuantity(r.getKey());

                            if (qty < r.getValue()) {
                                toUpdate.add(new Pair<>(r.getKey(), (short) qty));
                            }
                        }

                        // remove those not present on player inventory
                        if (!toUpdate.isEmpty()) {
                            for (Pair<Integer, Short> rp : toUpdate) {
                                if (rp.getRight() > 0) {
                                    reagentids.put(rp.getLeft(), rp.getRight());
                                } else {
                                    reagentids.remove(rp.getLeft());
                                }
                            }
                        }

                        if (!reagentids.isEmpty()) {
                            if (!removeOddMakerReagents(toCreate, reagentids)) {
                                c.sendPacket(PacketCreator.serverNotice(1, "你只能在武器物品上使用物理攻击力和魔法攻击力强化宝石。"));
                                c.sendPacket(PacketCreator.makerEnableActions());
                                return;
                            }
                        }
                    }

                    recipe = MakerItemFactory.getItemCreateEntry(toCreate, stimulantid, reagentids);
                }

                short createStatus = getCreateStatus(c, recipe);

                switch (createStatus) {
                    case -1:// non-available for Maker itemid has been tried to forge
                        log.warn("角色 {} 尝试使用制作技能合成物品 ID {}。", c.getPlayer().getName(), toCreate);
                        c.sendPacket(PacketCreator.serverNotice(1, "请求的物品无法通过本次操作进行合成。"));
                        c.sendPacket(PacketCreator.makerEnableActions());
                        break;

                    case 1: // 缺少物品
                        c.sendPacket(PacketCreator.serverNotice(1, "你的背包中没有制作 " + ii.getName(toCreate) + " 所需的全部物品。"));
                        c.sendPacket(PacketCreator.makerEnableActions());
                        break;

                    case 2: // 缺少金币
                        c.sendPacket(PacketCreator.serverNotice(1, "你的金币不足（需要 " + GameConstants.numberWithCommas(recipe.getCost()) + "）以完成此操作。"));
                        c.sendPacket(PacketCreator.makerEnableActions());
                        break;

                    case 3: // 等级不足
                        c.sendPacket(PacketCreator.serverNotice(1, "你的等级不足以完成此操作。"));
                        c.sendPacket(PacketCreator.makerEnableActions());
                        break;

                    case 4: // 技能等级不足
                        c.sendPacket(PacketCreator.serverNotice(1, "你的制作技能等级不足以完成此操作。"));
                        c.sendPacket(PacketCreator.makerEnableActions());
                        break;

                    case 5: // 背包已满
                        c.sendPacket(PacketCreator.serverNotice(1, "你的背包已满。"));
                        c.sendPacket(PacketCreator.makerEnableActions());
                        break;

                    default:
                        if (toDisassemble != -1) {
                            Item disassembledItem = c.getPlayer().getInventory(InventoryType.EQUIP).getItem((short) pos);
                            if (disassembledItem != null) {
                                traceabilityService.log(disassembledItem, c.getPlayer(), TraceabilityService.ActionType.ITEM_USAGE, TraceabilityService.ActionSourceType.ITEM_CONSUME, -1, String.format("通过制作技能 [%d] %s 消耗", toCreate, ii.getName(toCreate)),String.format("数量: %d -> %d", disassembledItem.getQuantity(), disassembledItem.getQuantity() - 1));
                            }
                            InventoryManipulator.removeFromSlot(c, InventoryType.EQUIP, (short) pos, (short) 1, false);
                        } else {
                            for (Pair<Integer, Integer> pair : recipe.getReqItems()) {
                                Item consumedItem = c.getPlayer().getInventory(ItemConstants.getInventoryType(pair.getLeft())).findById(pair.getLeft());
                                if (consumedItem != null) {
                                     traceabilityService.log(consumedItem, c.getPlayer(), TraceabilityService.ActionType.ITEM_USAGE, TraceabilityService.ActionSourceType.ITEM_CONSUME, -pair.getRight(), String.format("通过制作技能 [%d] %s 消耗", toCreate, ii.getName(toCreate)),String.format("数量: %d -> %d", consumedItem.getQuantity(), consumedItem.getQuantity() - pair.getRight()));
                                }
                                c.getAbstractPlayerInteraction().gainItem(pair.getLeft(), (short) -pair.getRight(), false);
                            }
                        }

                        int cost = recipe.getCost();
                        if (stimulantid == -1 && reagentids.isEmpty()) {
                            if (cost > 0) {
                                c.getPlayer().gainMeso(-cost, false);
                            }

                            for (Pair<Integer, Integer> pair : recipe.getGainItems()) {
                                c.getPlayer().setCS(true);
                                int gainId = pair.getLeft();
                                short gainCnt = pair.getRight().shortValue();
                                int finalToCreate = toCreate;
                                InventoryManipulator.addById(c, gainId, gainCnt, "", -1, -1, (addedItem) -> {
                                    traceabilityService.log(addedItem, c.getPlayer(), TraceabilityService.ActionType.ITEM_USAGE, TraceabilityService.ActionSourceType.ITEM_CRAFT, gainCnt, String.format("通过制作技能 [%d] %s 制作", finalToCreate, ii.getName(finalToCreate)), null);
                                });
                                c.getPlayer().setCS(false);
                            }
                        } else {
                            toCreate = recipe.getGainItems().get(0).getLeft();

                            if (stimulantid != -1) {
                                Item stimulantItem = c.getPlayer().getInventory(ItemConstants.getInventoryType(stimulantid)).findById(stimulantid);
                                if (stimulantItem != null) {
                                     traceabilityService.log(stimulantItem, c.getPlayer(), TraceabilityService.ActionType.ITEM_USAGE, TraceabilityService.ActionSourceType.ITEM_CONSUME, -1, String.format("通过制作技能 [%d] %s 消耗", toCreate, ii.getName(toCreate)),String.format("数量: %d -> %d", stimulantItem.getQuantity(), stimulantItem.getQuantity() - 1));
                                }
                                c.getAbstractPlayerInteraction().gainItem(stimulantid, (short) -1, false);
                            }
                            if (!reagentids.isEmpty()) {
                                for (Map.Entry<Integer, Short> r : reagentids.entrySet()) {
                                    Item reagentItem = c.getPlayer().getInventory(ItemConstants.getInventoryType(r.getKey())).findById(r.getKey());
                                    if (reagentItem != null) {
                                         traceabilityService.log(reagentItem, c.getPlayer(), TraceabilityService.ActionType.ITEM_USAGE, TraceabilityService.ActionSourceType.ITEM_CONSUME, -r.getValue(), String.format("通过制作技能 [%d] %s 消耗", toCreate, ii.getName(toCreate)),String.format("数量: %d -> %d", reagentItem.getQuantity(), reagentItem.getQuantity() - r.getValue()));
                                    }
                                    c.getAbstractPlayerInteraction().gainItem(r.getKey(), (short) (-1 * r.getValue()), false);
                                }
                            }

                            if (cost > 0) {
                                c.getPlayer().gainMeso(-cost, false);
                            }
                            makerSucceeded = addBoostedMakerItem(c, toCreate, stimulantid, reagentids);
                        }

                        // thanks inhyuk for noticing missing MAKER_RESULT packets
                        if (type == 3) {
                            c.sendPacket(PacketCreator.makerResultCrystal(recipe.getGainItems().get(0).getLeft(), recipe.getReqItems().get(0).getLeft()));
                        } else if (type == 4) {
                            c.sendPacket(PacketCreator.makerResultDesynth(recipe.getReqItems().get(0).getLeft(), recipe.getCost(), recipe.getGainItems()));
                        } else {
                            c.sendPacket(PacketCreator.makerResult(makerSucceeded, recipe.getGainItems().get(0).getLeft(), recipe.getGainItems().get(0).getRight(), recipe.getCost(), recipe.getReqItems(), stimulantid, new LinkedList<>(reagentids.keySet())));
                        }

                        c.sendPacket(PacketCreator.showMakerEffect(makerSucceeded));
                        c.getPlayer().getMap().broadcastMessage(c.getPlayer(), PacketCreator.showForeignMakerEffect(c.getPlayer().getId(), makerSucceeded), false);

                        if (toCreate == 4260003 && type == 3 && c.getPlayer().getQuestStatus(6033) == 1) {
                            c.getAbstractPlayerInteraction().setQuestProgress(6033, 1);
                        }
                }
            } finally {
                c.releaseClient();
            }
        }
    }

    // checks and prevents hackers from PE'ing Maker operations with invalid operations
    private static boolean removeOddMakerReagents(int toCreate, Map<Integer, Short> reagentids) {
        Map<Integer, Integer> reagentType = new LinkedHashMap<>();
        List<Integer> toRemove = new LinkedList<>();

        boolean isWeapon = ItemConstants.isWeapon(toCreate) || GameConfig.getServerBoolean("use_maker_permissive_atk_up");  // thanks Vcoc for finding a case where a weapon wouldn't be counted as such due to a bounding on isWeapon

        for (Map.Entry<Integer, Short> r : reagentids.entrySet()) {
            int curRid = r.getKey();
            int type = r.getKey() / 100;

            if (type < 42502 && !isWeapon) {     // only weapons should gain w.att/m.att from these.
                return false;   //toRemove.add(curRid);
            } else {
                Integer tableRid = reagentType.get(type);

                if (tableRid != null) {
                    if (tableRid < curRid) {
                        toRemove.add(tableRid);
                        reagentType.put(type, curRid);
                    } else {
                        toRemove.add(curRid);
                    }
                } else {
                    reagentType.put(type, curRid);
                }
            }
        }

        // removing less effective gems of repeated type
        for (Integer i : toRemove) {
            reagentids.remove(i);
        }

        // the Maker skill will use only one of each gem
        for (Integer i : reagentids.keySet()) {
            reagentids.put(i, (short) 1);
        }

        return true;
    }

    private static int getMakerReagentSlots(int itemId) {
        try {
            int eqpLevel = ii.getEquipLevelReq(itemId);

            if (eqpLevel < 78) {
                return 1;
            } else if (eqpLevel >= 78 && eqpLevel < 108) {
                return 2;
            } else {
                return 3;
            }
        } catch (NullPointerException npe) {
            return 0;
        }
    }

    private static Pair<Integer, List<Pair<Integer, Integer>>> generateDisassemblyInfo(int itemId) {
        int recvFee = ii.getMakerDisassembledFee(itemId);
        if (recvFee > -1) {
            List<Pair<Integer, Integer>> gains = ii.getMakerDisassembledItems(itemId);
            if (!gains.isEmpty()) {
                return new Pair<>(recvFee, gains);
            }
        }

        return null;
    }

    public static int getMakerSkillLevel(Character chr) {
        return chr.getSkillLevel((chr.getJob().getId() / 1000) * 10000000 + 1007);
    }

    private static short getCreateStatus(Client c, MakerItemCreateEntry recipe) {
        if (recipe.isInvalid()) {
            return -1;
        }

        if (!hasItems(c, recipe)) {
            return 1;
        }

        if (c.getPlayer().getMeso() < recipe.getCost()) {
            return 2;
        }

        if (c.getPlayer().getLevel() < recipe.getReqLevel()) {
            return 3;
        }

        if (getMakerSkillLevel(c.getPlayer()) < recipe.getReqSkillLevel()) {
            return 4;
        }

        List<Integer> addItemids = new LinkedList<>();
        List<Integer> addQuantity = new LinkedList<>();
        List<Integer> rmvItemids = new LinkedList<>();
        List<Integer> rmvQuantity = new LinkedList<>();

        for (Pair<Integer, Integer> p : recipe.getReqItems()) {
            rmvItemids.add(p.getLeft());
            rmvQuantity.add(p.getRight());
        }

        for (Pair<Integer, Integer> p : recipe.getGainItems()) {
            addItemids.add(p.getLeft());
            addQuantity.add(p.getRight());
        }

        if (!c.getAbstractPlayerInteraction().canHoldAllAfterRemoving(addItemids, addQuantity, rmvItemids, rmvQuantity)) {
            return 5;
        }

        return 0;
    }

    private static boolean hasItems(Client c, MakerItemCreateEntry recipe) {
        for (Pair<Integer, Integer> p : recipe.getReqItems()) {
            int itemId = p.getLeft();
            if (c.getPlayer().getInventory(ItemConstants.getInventoryType(itemId)).countById(itemId) < p.getRight()) {
                return false;
            }
        }
        return true;
    }

    private static boolean addBoostedMakerItem(Client c, int itemid, int stimulantid, Map<Integer, Short> reagentids) {
        if (stimulantid != -1 && !ItemInformationProvider.rollSuccessChance(90.0)) {
            return false;
        }

        Item item = ii.getEquipById(itemid);
        if (item == null) {
            return false;
        }

        Equip eqp = (Equip) item;
        if (ItemConstants.isAccessory(item.getItemId()) && eqp.getUpgradeSlots() <= 0) {
            eqp.setUpgradeSlots(3);
        }

        if (GameConfig.getServerBoolean("use_enhanced_crafting")) {
            if (!(c.getPlayer().isGM() && GameConfig.getServerBoolean("use_perfect_gm_scroll"))) {
                eqp.setUpgradeSlots((byte) (eqp.getUpgradeSlots() + 1));
            }
            item = ItemInformationProvider.getInstance().scrollEquipWithId(eqp, ItemId.CHAOS_SCROll_60, true, ItemId.CHAOS_SCROll_60, c.getPlayer().isGM());
        }

        if (!reagentids.isEmpty()) {
            Map<String, Integer> stats = new LinkedHashMap<>();
            List<Short> randOption = new LinkedList<>();
            List<Short> randStat = new LinkedList<>();

            for (Map.Entry<Integer, Short> r : reagentids.entrySet()) {
                Pair<String, Integer> reagentBuff = ii.getMakerReagentStatUpgrade(r.getKey());

                if (reagentBuff != null) {
                    String s = reagentBuff.getLeft();

                    if (s.substring(0, 4).contains("rand")) {
                        if (s.substring(4).equals("Stat")) {
                            randStat.add((short) (reagentBuff.getRight() * r.getValue()));
                        } else {
                            randOption.add((short) (reagentBuff.getRight() * r.getValue()));
                        }
                    } else {
                        String stat = s.substring(3);

                        if (!stat.equals("ReqLevel")) {    // improve req level... really?
                            switch (stat) {
                                case "MaxHP":
                                    stat = "MHP";
                                    break;

                                case "MaxMP":
                                    stat = "MMP";
                                    break;
                            }

                            Integer d = stats.get(stat);
                            if (d == null) {
                                stats.put(stat, reagentBuff.getRight() * r.getValue());
                            } else {
                                stats.put(stat, d + (reagentBuff.getRight() * r.getValue()));
                            }
                        }
                    }
                }
            }

            ItemInformationProvider.improveEquipStats(eqp, stats);

            for (Short sh : randStat) {
                ii.scrollOptionEquipWithChaos(eqp, sh, false);
            }

            for (Short sh : randOption) {
                ii.scrollOptionEquipWithChaos(eqp, sh, true);
            }
        }

        if (stimulantid != -1) {
            eqp = ii.randomizeUpgradeStats(eqp);
        }

        traceabilityService.log(item, c.getPlayer(), TraceabilityService.ActionType.ITEM_USAGE, TraceabilityService.ActionSourceType.ITEM_CRAFT, 1, String.format("通过制作技能 [%d] %s 制作", item.getItemId(), ii.getName(item.getItemId())), null);
        InventoryManipulator.addFromDrop(c, item, false, -1);
        return true;
    }
}