/*
This file is part of the OdinMS Maple Story Server
Copyright (C) 2008 Patrick Huy <patrick.huy@frz.cc>
Matthias Butz <matze@odinms.de>
Jan Christian Meyer <vimes@odinms.de>

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
package org.gms.net.server.channel.handlers;

import org.apache.logging.log4j.message.MapMessage;
import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.Ring;
import org.gms.client.inventory.Equip;
import org.gms.client.inventory.Inventory;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.ItemFactory;
import org.gms.client.inventory.manipulator.InventoryManipulator;
import org.gms.config.GameConfig;
import org.gms.constants.id.ItemId;
import org.gms.constants.inventory.ItemConstants;
import org.gms.dao.entity.CharactersDO;
import org.gms.dao.entity.ModifiedCashItemDO;
import org.gms.manager.ServerManager;
import org.gms.net.AbstractPacketHandler;
import org.gms.net.packet.InPacket;
import org.gms.net.server.Server;
import org.gms.server.logging.AuditLogger;
import org.gms.server.logging.LogAction;
import org.gms.server.logging.LogModule;
import org.gms.service.CharacterService;
import org.gms.service.TraceabilityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.gms.server.CashShop;
import org.gms.server.CashShop.CashItemFactory;
import org.gms.server.ItemInformationProvider;
import org.gms.service.NoteService;
import org.gms.util.PacketCreator;
import org.gms.util.Pair;

import java.util.Calendar;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static java.util.concurrent.TimeUnit.DAYS;

public final class CashOperationHandler extends AbstractPacketHandler {
    private static final Logger log = LoggerFactory.getLogger(CashOperationHandler.class);

    private final NoteService noteService;
    private static final TraceabilityService traceabilityService = ServerManager.getApplicationContext().getBean(TraceabilityService.class);

    public CashOperationHandler(NoteService noteService) {
        this.noteService = noteService;
    }

    @Override
    public void handlePacket(InPacket p, Client c) {
        Character chr = c.getPlayer();
        CashShop cs = chr.getCashShop();

        if (!cs.isOpened()) {
            c.sendPacket(PacketCreator.enableActions());
            return;
        }

        if (c.tryacquireClient()) {     // 感谢 Thora 发现现金操作中的一个漏洞
            try {
                final int action = p.readByte();
                if (action == 0x03 || action == 0x1E) { // 购买
                    p.readByte();
                    final int useNX = p.readInt();
                    final int snCS = p.readInt();
                    ModifiedCashItemDO cItem = CashItemFactory.getItem(snCS);
                    if (cItem == null || !canBuy(chr, cItem, cs.getCash(useNX),useNX)) {
                        if (cItem == null) {
                            chr.dropMessage(1, "该商品未入库，暂时无法购买。");
                            log.warn("玩家 {} 尝试购买的道具不存在，SN {}。", chr.getName(),snCS);
                        }
                        c.enableCSActions();
                        return;
                    }

                    if (action == 0x03) { // 道具
                        if (ItemConstants.isCashStore(cItem.getItemId()) && chr.getLevel() < 16) {
                            c.enableCSActions();
                            return;
                        } else if (ItemConstants.isMapleLife(cItem.getItemId()) && chr.getLevel() < 30) {
                            c.enableCSActions();
                            return;
                        }

                        Item item = cItem.toItem();
                        cs.gainCash(useNX, cItem, chr.getWorld());  // 感谢 Rohenn 注意到道具获取后的现金操作
                        cs.addToInventory(item);
                        c.sendPacket(PacketCreator.showBoughtCashItem(item, c.getAccID()));
                        
                        // 日志记录
                        AuditLogger.info(LogModule.CASH_SHOP, LogAction.CS_BUY, new MapMessage().with("itm", item.getItemId()).with("sn", snCS).with("cost", cItem.getPrice()));
                        traceabilityService.log(item, chr, TraceabilityService.ActionType.SHOP_BUY, "商城购买");
                    } else { // 礼包
                        cs.gainCash(useNX, cItem, chr.getWorld());

                        List<Item> cashPackage = CashItemFactory.getPackage(cItem.getItemId());
                        for (Item item : cashPackage) {
                            if (GameConfig.getServerBoolean("use_pet_equip_permanent") && ItemConstants.isPetEquip(item.getItemId())) {//商城是否允许将可升级次数>0的宠物装备时效设为永久。
                                if (item.getInventoryType().equals(InventoryType.EQUIP) && ((Equip) item).getUpgradeSlots() > 0) {
                                    item.setExpiration(-1L);
                                }
                            }
                            cs.addToInventory(item);
                            
                            // 日志记录
                            traceabilityService.log(item, chr, TraceabilityService.ActionType.SHOP_BUY, "商城礼包购买");
                        }
                        c.sendPacket(PacketCreator.showBoughtCashPackage(cashPackage, c.getAccID()));
                        log.info("玩家 {} 购买的礼包 {} (SN {}) 内含如下道具：[\r\n{}\r\n]",
                                chr.getName(),
                                cItem.getItemId(),
                                cItem.getSn(),
                                String.join("\r\n",cashPackage.stream().map(
                                        item -> ItemInformationProvider.getInstance().getName(item.getItemId()) +
                                                "(" + item.getItemId() + ") (SN "+item.getSN()+") 有效期 " + (item.getExpiration() <= 0 ? "永久" : (((item.getExpiration() - System.currentTimeMillis()) / (24 * 60 * 60 * 1000L)) + 1) + "天") +
                                                " 数量 " + item.getQuantity()
                                    ).toList()
                                )
                        );
                        AuditLogger.info(LogModule.CASH_SHOP, LogAction.CS_BUY, new MapMessage().with("itm", cItem.getItemId()).with("sn", snCS).with("cost", cItem.getPrice()).with("msg", "礼包"));
                    }
                    c.sendPacket(PacketCreator.showCash(chr));
                    cs.save(); // 购买后保存商城数据
                } else if (action == 0x04) {//TODO: 赠送礼物时检查性别
                    int birthday = p.readInt();
                    ModifiedCashItemDO cItem = CashItemFactory.getItem(p.readInt());
                    CharacterService characterService = ServerManager.getApplicationContext().getBean(CharacterService.class);
                    CharactersDO charactersDO = characterService.findByName(p.readString());
                    String message = p.readString();
                    if (!canBuy(chr, cItem, cs.getCash(CashShop.NX_PREPAID),CashShop.NX_PREPAID) || message.isEmpty() || message.length() > 73) {
                        c.enableCSActions();
                        return;
                    }
                    if (!checkBirthday(c, birthday)) {
                        c.sendPacket(PacketCreator.showCashShopMessage((byte) 0xC4));
                        return;
                    } else if (charactersDO == null) {
                        c.sendPacket(PacketCreator.showCashShopMessage((byte) 0xA9));
                        return;
                    } else if (Objects.equals(charactersDO.getAccountid(), c.getAccID())) {
                        c.sendPacket(PacketCreator.showCashShopMessage((byte) 0xA8));
                        return;
                    }
                    cs.gainCash(4, cItem, chr.getWorld());
                    cs.gift(charactersDO.getId(), chr.getName(), message, cItem.getSn());
                    c.sendPacket(PacketCreator.showGiftSucceed(charactersDO.getName(), cItem));
                    c.sendPacket(PacketCreator.showCash(chr));

                    String noteMessage = chr.getName() + " 给你送了一份礼物！快去商城看看吧。";
                    noteService.sendNormal(noteMessage, chr.getName(), charactersDO.getName());

                    Character receiver = c.getChannelServer().getPlayerStorage().getCharacterByName(charactersDO.getName());
                    if (receiver != null) {
                        noteService.show(receiver);
                    }
                    
                    AuditLogger.info(LogModule.CASH_SHOP, LogAction.CS_GIFT, new MapMessage().with("itm", cItem.getItemId()).with("to", charactersDO.getName()).with("cost", cItem.getPrice()));
                    
                    cs.save(); // 赠送后保存商城数据
                } else if (action == 0x05) { // 修改愿望单
                    cs.clearWishList();
                    for (byte i = 0; i < 10; i++) {
                        int sn = p.readInt();
                        ModifiedCashItemDO cItem = CashItemFactory.getItem(sn);
                        if (cItem != null && cItem.isSelling() && sn != 0) {
                            cs.addToWishList(sn);
                        }
                    }
                    c.sendPacket(PacketCreator.showWishList(chr, true));
                    cs.save(); // 修改愿望单后保存
                } else if (action == 0x06) { // 增加背包栏位
                    p.skip(1);
                    int cash = p.readInt();
                    byte mode = p.readByte();
                    if (mode == 0) {
                        byte type = p.readByte();
                        if (cs.getCash(cash) < 4000) {
                            c.enableCSActions();
                            return;
                        }
                        int qty = 4;
                        if (!chr.canGainSlots(type, qty)) {
                            c.enableCSActions();
                            return;
                        }
                        cs.gainCash(cash, -4000);
                        if (chr.gainSlots(type, qty, false)) {
                            c.sendPacket(PacketCreator.showBoughtInventorySlots(type, chr.getSlots(type)));
                            c.sendPacket(PacketCreator.showCash(chr));
                            cs.save(); // 购买格子后保存
                            AuditLogger.info(LogModule.CASH_SHOP, LogAction.CS_BUY, new MapMessage().with("msg", "增加背包栏位").with("type", type).with("qty", qty));
                        } else {
                            log.warn("无法为玩家 {} 的账号 {} 添加类型为 {} 的背包格子 {} 个", chr.getName(),Character.makeMapleReadable(chr.getName()), type, qty);
                        }
                    } else {
                        ModifiedCashItemDO cItem = CashItemFactory.getItem(p.readInt());
                        if(cItem == null) {
                            c.enableCSActions();
                            return;
                        }
                        int type = (cItem.getItemId() - 9110000) / 1000;
                        if (!canBuy(chr, cItem, cs.getCash(cash),cash)) {
                            c.enableCSActions();
                            return;
                        }
                        int qty = 8;
                        if (!chr.canGainSlots(type, qty)) {
                            c.enableCSActions();
                            return;
                        }
                        cs.gainCash(cash, cItem, chr.getWorld());
                        if (chr.gainSlots(type, qty, false)) {
                            c.sendPacket(PacketCreator.showBoughtInventorySlots(type, chr.getSlots(type)));
                            c.sendPacket(PacketCreator.showCash(chr));
                            cs.save(); // 购买格子后保存
                            AuditLogger.info(LogModule.CASH_SHOP, LogAction.CS_BUY, new MapMessage().with("msg", "增加背包栏位(礼包)").with("type", type).with("qty", qty));
                        } else {
                            log.warn("无法为玩家 {} 的账号 {} 添加类型为 {} 的背包格子 {} 个", chr.getName(),Character.makeMapleReadable(chr.getName()), type, qty);
                        }
                    }
                } else if (action == 0x07) { // 增加仓库栏位
                    p.skip(1);
                    int cash = p.readInt();
                    byte mode = p.readByte();
                    if (mode == 0) {
                        if (cs.getCash(cash) < 4000) {
                            c.enableCSActions();
                            return;
                        }
                        int qty = 4;
                        if (!chr.getStorage().canGainSlots(qty)) {
                            c.enableCSActions();
                            return;
                        }
                        cs.gainCash(cash, -4000);
                        if (chr.getStorage().gainSlots(qty)) {
                            log.debug("玩家 {} 为账号 {} 购买了背包格子 {} 个",Character.makeMapleReadable(chr.getName()), chr.getName(), qty);
                            chr.setUsedStorage();

                            c.sendPacket(PacketCreator.showBoughtStorageSlots(chr.getStorage().getSlots()));
                            c.sendPacket(PacketCreator.showCash(chr));
                            cs.save(); // 购买格子后保存
                            AuditLogger.info(LogModule.CASH_SHOP, LogAction.CS_BUY, new MapMessage().with("msg", "增加仓库栏位").with("qty", qty));
                        } else {
                            log.warn("无法为玩家 {} 账号 {} 添加背包格子 {} 个",Character.makeMapleReadable(chr.getName()), chr.getName(), qty);
                        }
                    } else {
                        ModifiedCashItemDO cItem = CashItemFactory.getItem(p.readInt());

                        if (!canBuy(chr, cItem, cs.getCash(cash),cash)) {
                            c.enableCSActions();
                            return;
                        }
                        int qty = 8;
                        if (!chr.getStorage().canGainSlots(qty)) {
                            c.enableCSActions();
                            return;
                        }
                        cs.gainCash(cash, cItem, chr.getWorld());
                        if (chr.getStorage().gainSlots(qty)) {    // 感谢 ABaldParrot 和 Thora 在此发现仓库问题
                            log.debug("玩家 {} 为账号 {} 购买了背包格子 {} 个",Character.makeMapleReadable(chr.getName()), chr.getName(), qty);
                            chr.setUsedStorage();

                            c.sendPacket(PacketCreator.showBoughtStorageSlots(chr.getStorage().getSlots()));
                            c.sendPacket(PacketCreator.showCash(chr));
                            cs.save(); // 购买格子后保存
                            AuditLogger.info(LogModule.CASH_SHOP, LogAction.CS_BUY, new MapMessage().with("msg", "增加仓库栏位(礼包)").with("qty", qty));
                        } else {
                            log.warn("无法为玩家 {} 账号 {} 添加背包格子 {} 个",Character.makeMapleReadable(chr.getName()), chr.getName(), qty);
                        }
                    }
                } else if (action == 0x08) { // 增加角色栏位
                    p.skip(1);
                    int cash = p.readInt();
                    ModifiedCashItemDO cItem = CashItemFactory.getItem(p.readInt());

                    if (!canBuy(chr, cItem, cs.getCash(cash),cash)) {
                        c.enableCSActions();
                        return;
                    }
                    if (!c.canGainCharacterSlot()) {
                        chr.dropMessage(1, "你已经用完了12个额外角色位置，无法继续增加。");
                        c.enableCSActions();
                        return;
                    }
                    cs.gainCash(cash, cItem, chr.getWorld());
                    if (c.gainCharacterSlot()) {
                        c.sendPacket(PacketCreator.showBoughtCharacterSlot(c.getCharacterSlots()));
                        c.sendPacket(PacketCreator.showCash(chr));
                        cs.save(); // 购买角色位后保存
                        AuditLogger.info(LogModule.CASH_SHOP, LogAction.CS_BUY, new MapMessage().with("msg", "增加角色栏位"));
                    } else {
                        log.warn("无法为账号 {} 添加背包格子", Character.makeMapleReadable(chr.getName()));
                        c.enableCSActions();
                        return;
                    }
                } else if (action == 0x0D) { // 从商城仓库取出
                    Item item = cs.findByCashId(p.readInt());
                    if (item == null) {
                        c.enableCSActions();
                        return;
                    }
                    InventoryType type = item.getInventoryType();
                    if (chr.getInventory(type).addItem(item) != -1) {
                        cs.removeFromInventory(item);
                        c.sendPacket(PacketCreator.takeFromCashInventory(item));

                        if (item instanceof Equip equip) {
                            if (equip.getRingId() >= 0) {
                                Ring ring = Ring.loadFromDb(equip.getRingId());
                                chr.addPlayerRing(ring);
                            }
                        }
                        
                        // 实时保存
                        ItemFactory.INVENTORY.saveItems(
                            chr.getInventory(type).list().stream().map(i -> new Pair<>(i, type)).toList(),
                            chr.getId(),
                            Collections.singleton(type)
                        );
                        cs.save();
                        
                        // 日志记录
                        AuditLogger.info(LogModule.CASH_SHOP, LogAction.CS_OUT, new MapMessage().with("itm", item.getItemId()).with("msg", "从商城仓库取出"));
                        traceabilityService.log(item, chr, TraceabilityService.ActionType.STORAGE_OUT, "商城取出");
                    }
                } else if (action == 0x0E) { // 存入商城仓库
                    int cashId = p.readInt();
                    p.skip(4);

                    byte invType = p.readByte();
                    if (invType < 1 || invType > 5) {
                        c.disconnect(false, false);
                        return;
                    }

                    Inventory mi = chr.getInventory(InventoryType.getByType(invType));
                    Item item = mi.findByCashId(cashId);
                    if (item == null) {
                        c.enableCSActions();
                        return;
                    } else if (c.getPlayer().getPetIndex(item.getPetId()) > -1) {
                        chr.getClient().sendPacket(PacketCreator.serverNotice(1, "无法将当前装备的宠物放入商城保管箱里。"));
                        c.enableCSActions();
                        return;
                    } else if (ItemId.isWeddingRing(item.getItemId()) || ItemId.isWeddingToken(item.getItemId())) {
                        chr.getClient().sendPacket(PacketCreator.serverNotice(1, "无法将缔结了关系/羁绊的道具放入商城保管箱里"));
                        c.enableCSActions();
                        return;
                    }
                    cs.addToInventory(item);
                    mi.removeSlot(item.getPosition());
                    c.sendPacket(PacketCreator.putIntoCashInventory(item, c.getAccID()));
                    
                    // 实时保存
                    cs.save();
                    ItemFactory.INVENTORY.saveItems(
                        mi.list().stream().map(i -> new Pair<>(i, InventoryType.getByType(invType))).toList(),
                        chr.getId(),
                        Collections.singleton(InventoryType.getByType(invType))
                    );
                    
                    // 日志记录
                    AuditLogger.info(LogModule.CASH_SHOP, LogAction.CS_IN, new MapMessage().with("itm", item.getItemId()).with("msg", "存入商城仓库"));
                    traceabilityService.log(item, chr, TraceabilityService.ActionType.STORAGE_IN, "商城存入");
                } else if (action == 0x1D) { // 情侣戒指 (action 28)
                    int birthday = p.readInt();
                    if (checkBirthday(c, birthday)) {
                        int toCharge = p.readInt();
                        int SN = p.readInt();
                        String recipientName = p.readString();
                        String text = p.readString();
                        ModifiedCashItemDO itemRing = CashItemFactory.getItem(SN);
                        Character partner = c.getChannelServer().getPlayerStorage().getCharacterByName(recipientName);
                        if (partner == null) {
                            chr.sendPacket(PacketCreator.serverNotice(1, "无法找到指定的玩家，请确保你与该玩家处于统一频道。"));
                        } else {

                            if (partner.getGender() == chr.getGender()) {
                                chr.dropMessage(5, "你不能与该玩家结婚，推荐购买友谊戒指。");
                                c.enableCSActions();
                                return;
                            }

                            if (itemRing.toItem() instanceof Equip eqp) {
                                Pair<Integer, Integer> rings = Ring.createRing(itemRing.getItemId(), chr, partner);
                                eqp.setRingId(rings.getLeft());
                                cs.addToInventory(eqp);
                                c.sendPacket(PacketCreator.showBoughtCashItem(eqp, c.getAccID()));
                                cs.gainCash(toCharge, itemRing, chr.getWorld());
                                cs.gift(partner.getId(), chr.getName(), text, eqp.getSN(), rings.getRight());
                                chr.getCrushRings().add(Ring.loadFromDb(rings.getLeft()));
                                noteService.sendWithFame(text, chr.getName(), partner.getName());
                                noteService.show(partner);
                                cs.save(); // 购买戒指后保存
                                
                                AuditLogger.info(LogModule.CASH_SHOP, LogAction.CS_BUY, new MapMessage().with("itm", itemRing.getItemId()).with("msg", "情侣戒指"));
                            }
                        }
                    } else {
                        c.sendPacket(PacketCreator.showCashShopMessage((byte) 0xC4));
                    }

                    c.sendPacket(PacketCreator.showCash(c.getPlayer()));
                } else if (action == 0x20) {
                    int serialNumber = p.readInt();  // 感谢 GabrielSin 发现一个使用1金币现金道具的潜在漏洞。
                    if (serialNumber / 10000000 != 8) {
                        c.sendPacket(PacketCreator.showCashShopMessage((byte) 0xC0));
                        return;
                    }

                    ModifiedCashItemDO item = CashItemFactory.getItem(serialNumber);
                    if (item == null || !item.isSelling()) {
                        c.sendPacket(PacketCreator.showCashShopMessage((byte) 0xC0));
                        return;
                    }

                    int itemId = item.getItemId();
                    int itemPrice = item.getPrice();
                    if (itemPrice <= 0) {
                        c.sendPacket(PacketCreator.showCashShopMessage((byte) 0xC0));
                        return;
                    }

                    if (chr.getMeso() >= itemPrice) {
                        if (chr.canHold(itemId)) {
                            chr.gainMeso(-itemPrice, false);
                            InventoryManipulator.addById(c, itemId, (short) 1, "", -1);
                            c.sendPacket(PacketCreator.showBoughtQuestItem(itemId));
                            
                            // 实时保存
                            InventoryType type = ItemConstants.getInventoryType(itemId);
                            ItemFactory.INVENTORY.saveItems(
                                chr.getInventory(type).list().stream().map(i -> new Pair<>(i, type)).toList(),
                                chr.getId(),
                                Collections.singleton(type)
                            );

                            AuditLogger.info(LogModule.CASH_SHOP, LogAction.CS_BUY, new MapMessage().with("itm", itemId).with("msg", "任务道具"));
                        }
                    }
                    c.sendPacket(PacketCreator.showCash(c.getPlayer()));
                } else if (action == 0x23) { // 友情戒指 :3
                    int birthday = p.readInt();
                    if (checkBirthday(c, birthday)) {
                        int payment = p.readByte();
                        p.skip(3); //0s
                        int snID = p.readInt();
                        ModifiedCashItemDO itemRing = CashItemFactory.getItem(snID);
                        String sentTo = p.readString();
                        String text = p.readString();
                        Character partner = c.getChannelServer().getPlayerStorage().getCharacterByName(sentTo);
                        if (partner == null) {
                            c.sendPacket(PacketCreator.showCashShopMessage((byte) 0xBE));
                        } else {
                            // 需要检查以确保它实际上是装备和正确的SN...
                            if (itemRing.toItem() instanceof Equip eqp) {
                                Pair<Integer, Integer> rings = Ring.createRing(itemRing.getItemId(), chr, partner);
                                eqp.setRingId(rings.getLeft());
                                cs.addToInventory(eqp);
                                c.sendPacket(PacketCreator.showBoughtCashRing(eqp, partner.getName(), c.getAccID()));
                                cs.gainCash(payment, -itemRing.getPrice());
                                cs.gift(partner.getId(), chr.getName(), text, eqp.getSN(), rings.getRight());
                                chr.getFriendshipRings().add(Ring.loadFromDb(rings.getLeft()));
                                noteService.sendWithFame(text, chr.getName(), partner.getName());
                                noteService.show(partner);
                                cs.save(); // 购买戒指后保存
                                AuditLogger.info(LogModule.CASH_SHOP, LogAction.CS_BUY, new MapMessage().with("itm", itemRing.getItemId()).with("msg", "友情戒指"));
                            }
                        }
                    } else {
                        c.sendPacket(PacketCreator.showCashShopMessage((byte) 0xC4));
                    }

                    c.sendPacket(PacketCreator.showCash(c.getPlayer()));
                } else if (action == 0x2E) { // 角色改名
                    ModifiedCashItemDO cItem = CashItemFactory.getItem(p.readInt());
                    if (cItem == null || !canBuy(chr, cItem, cs.getCash(CashShop.NX_PREPAID),CashShop.NX_PREPAID)) {
                        c.sendPacket(PacketCreator.showCashShopMessage((byte) 0));
                        c.enableCSActions();
                        return;
                    }
                    if (cItem.getSn() == 50600000 && GameConfig.getServerBoolean("allow_cash_shop_name_change")) {
                        p.readString(); // 旧名字
                        String newName = p.readString();
                        if (!Character.canCreateChar(newName) || chr.getLevel() < 10) { //(目前未跟踪最长封禁持续时间)
                            c.sendPacket(PacketCreator.showCashShopMessage((byte) 0));
                            c.enableCSActions();
                            return;
                        } else if (c.getTempBanCalendar() != null && (c.getTempBanCalendar().getTimeInMillis() + DAYS.toMillis(30)) > Calendar.getInstance().getTimeInMillis()) {
                            c.sendPacket(PacketCreator.showCashShopMessage((byte) 0));
                            c.enableCSActions();
                            return;
                        }
                        if (chr.registerNameChange(newName)) { // 成功
                            Item item = cItem.toItem();
                            c.sendPacket(PacketCreator.showNameChangeSuccess(item, c.getAccID()));
                            cs.gainCash(4, cItem, chr.getWorld());
                            cs.addToInventory(item);
                            cs.save(); // 改名后保存
                            AuditLogger.info(LogModule.CASH_SHOP, LogAction.CS_BUY, new MapMessage().with("msg", "角色改名").with("new", newName));
                        } else {
                            c.sendPacket(PacketCreator.showCashShopMessage((byte) 0));
                        }
                    }
                    c.enableCSActions();
                } else if (action == 0x31) { // 跨区转移
                    ModifiedCashItemDO cItem = CashItemFactory.getItem(p.readInt());
                    if (cItem == null || !canBuy(chr, cItem, cs.getCash(CashShop.NX_PREPAID),CashShop.NX_PREPAID)) {
                        c.sendPacket(PacketCreator.showCashShopMessage((byte) 0));
                        c.enableCSActions();
                        return;
                    }
                    if (cItem.getSn() == 50600001 && GameConfig.getServerBoolean("allow_cash_shop_world_transfer")) {
                        int newWorldSelection = p.readInt();

                        int worldTransferError = chr.checkWorldTransferEligibility();
                        if (worldTransferError != 0 || newWorldSelection >= Server.getInstance().getWorldsSize() || Server.getInstance().getWorldsSize() <= 1) {
                            c.sendPacket(PacketCreator.showCashShopMessage((byte) 0));
                            return;
                        } else if (newWorldSelection == c.getWorld()) {
                            c.sendPacket(PacketCreator.showCashShopMessage((byte) 0xDC));
                            return;
                        } else if (c.getAvailableCharacterWorldSlots(newWorldSelection) < 1 || Server.getInstance().getAccountWorldCharacterCount(c.getAccID(), newWorldSelection) >= 3) {
                            c.sendPacket(PacketCreator.showCashShopMessage((byte) 0xDF));
                            return;
                        } else if (chr.registerWorldTransfer(newWorldSelection)) {
                            Item item = cItem.toItem();
                            c.sendPacket(PacketCreator.showWorldTransferSuccess(item, c.getAccID()));
                            cs.gainCash(4, cItem, chr.getWorld());
                            cs.addToInventory(item);
                            cs.save(); // 转服后保存
                            AuditLogger.info(LogModule.CASH_SHOP, LogAction.CS_BUY, new MapMessage().with("msg", "世界转移").with("to", newWorldSelection));
                        } else {
                            c.sendPacket(PacketCreator.showCashShopMessage((byte) 0));
                        }
                    }
                    c.enableCSActions();
                } else {
                    log.warn("未处理的操作：{}，数据包：{}", action, p);
                }
            } finally {
                c.releaseClient();
            }
        } else {
            c.sendPacket(PacketCreator.enableActions());
        }
    }

    public static boolean checkBirthday(Client c, int idate) {
        int year = idate / 10000;
        int month = (idate - year * 10000) / 100;
        int day = idate - year * 10000 - month * 100;
        Calendar cal = Calendar.getInstance();
        cal.setTimeInMillis(0);
        cal.set(year, month - 1, day);
        return c.checkBirthDate(cal);
    }

    private static boolean canBuy(Character chr, ModifiedCashItemDO cItem, int cash, int useNX) {
        if (cItem == null) {
            return false;
        }

        // 将重复调用的方法设为变量
        String playerName = chr.getName();
        String itemName = ItemInformationProvider.getInstance().getName(cItem.getItemId());
        int itemId = cItem.getItemId();
        int sn = cItem.getSn();
        int price = cItem.getPrice();

        if (!cItem.isSelling()) {
            chr.dropMessage(1, "该商品已下架，暂时无法购买。");
            log.warn("玩家 {} 尝试购买的道具 {} (SN {}) 状态为已下架，购买失败。", playerName, itemName, sn);
            return false;
        }

        if (ItemConstants.isRateCoupon(itemId) && !GameConfig.getServerBoolean("use_supply_rate_coupons")) {
            chr.dropMessage(1, "倍率卡目前已暂停购买。");
            log.warn("玩家 {} 尝试购买的倍率卡 {}({}) (SN {}) 已被禁止购买。", playerName, itemName, itemId, sn);
            return false;
        }

        if (price > cash) {
            log.warn("玩家 {} 尝试购买的道具 {} (SN {}) 的价格 {} 大于现金 {}", playerName, itemName, sn, price, cash);
            return false;
        }

        if (GameConfig.getServerBoolean("use_pet_equip_permanent") && ItemConstants.isPetEquip(itemId)) {//商城是否允许将可升级次数>0的宠物装备时效设为永久。
            Item item = cItem.toItem();
            if (item.getInventoryType().equals(InventoryType.EQUIP) && ((Equip) item).getUpgradeSlots() > 0) {
                cItem.setPeriod(-1L);
            }
        }

        // 重新获取period值，因为可能被修改
        long period = cItem.getPeriod();
        String periodDesc = period > 0 ? period + "天" : "永久";
        String cashName = chr.getCashShop().getCashName(useNX);

        log.info("玩家 {} 购买了现金道具 {}({}) (SN {}) 有效期 {} 数量 {} 花费 {}{}",playerName, itemName, itemId, sn, periodDesc, cItem.getCount(), price, cashName);
        return true;
    }
}
