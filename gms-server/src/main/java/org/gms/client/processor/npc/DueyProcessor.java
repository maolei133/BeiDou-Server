/*
	This file is part of the OdinMS Maple Story Server
    Copyright (C) 2008 Patrick Huy <patrick.huy@frz.cc>
		       Matthias Butz <matze@odinms.de>
		       Jan Christian Meyer <vimes@odinms.de>

    Copyleft (L) 2016 - 2019 RonanLana (HeavenMS)

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
package org.gms.client.processor.npc;

import com.mybatisflex.core.query.QueryWrapper;
import com.mybatisflex.core.update.UpdateChain;
import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.autoban.AutobanFactory;
import org.gms.client.inventory.Inventory;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.ItemFactory;
import org.gms.client.inventory.manipulator.InventoryManipulator;
import org.gms.client.inventory.manipulator.KarmaManipulator;
import org.gms.config.GameConfig;
import org.gms.constants.id.ItemId;
import org.gms.constants.inventory.ItemConstants;
import org.gms.dao.entity.CharactersDO;
import org.gms.dao.entity.DueypackagesDO;
import org.gms.dao.mapper.CharactersMapper;
import org.gms.dao.mapper.DueypackagesMapper;
import org.gms.net.server.channel.Channel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.gms.server.DueyPackage;
import org.gms.server.ItemInformationProvider;
import org.gms.server.Trade;
import org.gms.util.PacketCreator;
import org.gms.util.Pair;
import org.gms.util.SpringContextUtil;

import java.sql.Timestamp;
import java.util.*;

/**
 * 快递处理器
 * @author RonanLana - synchronization of Duey modules
 */
public class DueyProcessor {
    private static final Logger log = LoggerFactory.getLogger(DueyProcessor.class);

    public enum Actions {
        TOSERVER_RECV_ITEM(0x00),
        TOSERVER_SEND_ITEM(0x02),
        TOSERVER_CLAIM_PACKAGE(0x04),
        TOSERVER_REMOVE_PACKAGE(0x05),
        TOSERVER_CLOSE_DUEY(0x07),
        TOCLIENT_OPEN_DUEY(0x08),
        TOCLIENT_SEND_ENABLE_ACTIONS(0x09),
        TOCLIENT_SEND_NOT_ENOUGH_MESOS(0x0A),
        TOCLIENT_SEND_INCORRECT_REQUEST(0x0B),
        TOCLIENT_SEND_NAME_DOES_NOT_EXIST(0x0C),
        TOCLIENT_SEND_SAMEACC_ERROR(0x0D),
        TOCLIENT_SEND_RECEIVER_STORAGE_FULL(0x0E),
        TOCLIENT_SEND_RECEIVER_UNABLE_TO_RECV(0x0F),
        TOCLIENT_SEND_RECEIVER_STORAGE_WITH_UNIQUE(0x10),
        TOCLIENT_SEND_MESO_LIMIT(0x11),
        TOCLIENT_SEND_SUCCESSFULLY_SENT(0x12),
        TOCLIENT_RECV_UNKNOWN_ERROR(0x13),
        TOCLIENT_RECV_ENABLE_ACTIONS(0x14),
        TOCLIENT_RECV_NO_FREE_SLOTS(0x15),
        TOCLIENT_RECV_RECEIVER_WITH_UNIQUE(0x16),
        TOCLIENT_RECV_SUCCESSFUL_MSG(0x17),
        TOCLIENT_RECV_PACKAGE_MSG(0x1B);
        final byte code;

        Actions(int code) {
            this.code = (byte) code;
        }

        public byte getCode() {
            return code;
        }
    }

    private static Pair<Integer, Integer> getAccountCharacterIdFromCNAME(String name) {
        CharactersMapper mapper = SpringContextUtil.getBean(CharactersMapper.class);
        QueryWrapper query = QueryWrapper.create().select(CharactersDO::getId, CharactersDO::getAccountid).where(CharactersDO::getName).eq(name);
        CharactersDO result = mapper.selectOneByQuery(query);
        if (result != null) {
            return new Pair<>(result.getAccountid(), result.getId());
        }
        return new Pair<>(-1, -1);
    }

    private static void showDueyNotification(Client c, Character player) {
        DueypackagesMapper mapper = SpringContextUtil.getBean(DueypackagesMapper.class);
        QueryWrapper query = QueryWrapper.create()
                .select(DueypackagesDO::getSendername, DueypackagesDO::getType)
                .where(DueypackagesDO::getReceiverid).eq(player.getId())
                .and(DueypackagesDO::getChecked).eq(1)
                .orderBy(DueypackagesDO::getType, false);

        DueypackagesDO result = mapper.selectOneByQuery(query);
        if (result != null) {
            UpdateChain.of(DueypackagesDO.class)
                    .set(DueypackagesDO::getChecked, 0)
                    .where(DueypackagesDO::getReceiverid).eq(player.getId())
                    .update();
            c.sendPacket(PacketCreator.sendDueyParcelReceived(result.getSendername(), result.getType() == 1));
        }
    }

    private static void deletePackageFromInventoryDB(int packageId) {
        ItemFactory.DUEY.saveItems(new LinkedList<>(), packageId);
    }

    private static void removePackageFromDB(int packageId) {
        DueypackagesMapper mapper = SpringContextUtil.getBean(DueypackagesMapper.class);
        mapper.deleteById(packageId);
        deletePackageFromInventoryDB(packageId);
    }

    private static DueyPackage getPackageFromDB(DueypackagesDO data) {
        int packageId = data.getPackageid().intValue();
        List<Pair<Item, InventoryType>> dueyItems = ItemFactory.DUEY.loadItems(packageId, false);
        DueyPackage dueypack;

        if (!dueyItems.isEmpty()) {
            dueypack = new DueyPackage(packageId, dueyItems.get(0).getLeft());
        } else {
            dueypack = new DueyPackage(packageId);
        }

        dueypack.setSender(data.getSendername());
        dueypack.setMesos(data.getMesos().intValue());
        dueypack.setSentTime(data.getTimestamp(), data.getType() == 1);
        dueypack.setMessage(data.getMessage());
        dueypack.setReceiverId(data.getReceiverid().intValue());

        return dueypack;
    }

    private static List<DueyPackage> loadPackages(Character chr) {
        List<DueyPackage> packages = new LinkedList<>();
        DueypackagesMapper mapper = SpringContextUtil.getBean(DueypackagesMapper.class);
        QueryWrapper query = QueryWrapper.create().where(DueypackagesDO::getReceiverid).eq(chr.getId());
        List<DueypackagesDO> results = mapper.selectListByQuery(query);

        for (DueypackagesDO result : results) {
            DueyPackage dueypack = getPackageFromDB(result);
            if (dueypack != null) {
                packages.add(dueypack);
            }
        }
        return packages;
    }

    private static int createPackage(int mesos, String message, String sender, int toCid, boolean quick) {
        DueypackagesMapper mapper = SpringContextUtil.getBean(DueypackagesMapper.class);
        DueypackagesDO newPackage = new DueypackagesDO();
        newPackage.setReceiverid((long) toCid);
        newPackage.setSendername(sender);
        newPackage.setMesos((long) mesos);
        newPackage.setTimestamp(new Timestamp(System.currentTimeMillis()));
        newPackage.setMessage(message);
        newPackage.setType(quick ? 1 : 0);
        newPackage.setChecked(1);

        if (mapper.insert(newPackage, true) > 0) {
            return newPackage.getPackageid().intValue();
        } else {
            log.error("创建包裹失败 [金币: {}, 发件人: {}, 快速: {}, 收件人角色ID: {}]", mesos, sender, quick, toCid);
            return -1;
        }
    }

    private static boolean insertPackageItem(int packageId, Item item) {
        Pair<Item, InventoryType> dueyItem = new Pair<>(item, InventoryType.getByType(item.getItemType()));
        ItemFactory.DUEY.saveItems(Collections.singletonList(dueyItem), packageId);
        return true;
    }

    private static int addPackageItemFromInventory(int packageId, Client c, byte invTypeId, short itemPos, short amount) {
        if (invTypeId > 0) {
            ItemInformationProvider ii = ItemInformationProvider.getInstance();

            InventoryType invType = InventoryType.getByType(invTypeId);
            Inventory inv = c.getPlayer().getInventory(invType);

            Item item;
            inv.lockInventory();
            try {
                item = inv.getItem(itemPos);
                if (item != null && item.getQuantity() >= amount) {
                    if (item.isUntradeable() || ii.isUnmerchable(item.getItemId())) {
                        return -1;
                    }

                    if (ItemConstants.isRechargeable(item.getItemId())) {
                        InventoryManipulator.removeFromSlot(c, invType, itemPos, item.getQuantity(), true);
                    } else {
                        InventoryManipulator.removeFromSlot(c, invType, itemPos, amount, true, false);
                    }

                    item = item.copy();
                } else {
                    return -2;
                }
            } finally {
                inv.unlockInventory();
            }

            KarmaManipulator.toggleKarmaFlagToUntradeable(item);
            item.setQuantity(amount);

            if (!insertPackageItem(packageId, item)) {
                return 1;
            }
        }

        return 0;
    }

    public static void dueySendItem(Client c, byte invTypeId, short itemPos, short amount, int sendMesos, String sendMessage, String recipient, boolean quick) {
        if (c.tryacquireClient()) {
            try {
                if (c.getPlayer().isGM() && c.getPlayer().gmLevel() < GameConfig.getServerInt("minimum_gm_level_to_use_duey")) {
                    c.getPlayer().message("您当前的GM等级无法使用快递。");
                    log.info("GM {} 尝试发送一个包裹给 {}", c.getPlayer().getName(), recipient);
                    c.sendPacket(PacketCreator.sendDueyMSG(DueyProcessor.Actions.TOCLIENT_SEND_INCORRECT_REQUEST.getCode()));
                    return;
                }

                if (sendMesos < 0) {
                    AutobanFactory.PACKET_EDIT.alert(c.getPlayer(), c.getPlayer().getName() + " 尝试在快递中修改金币。");
                    log.warn("角色 {} 尝试使用快递发送负数金币 {}", c.getPlayer().getName(), sendMesos);
                    c.disconnect(true, false);
                    return;
                }
                int fee = Trade.getFee(sendMesos);
                if (sendMessage != null && sendMessage.length() > 100) {
                    AutobanFactory.PACKET_EDIT.alert(c.getPlayer(), c.getPlayer().getName() + " 尝试在快递中修改快速配送。");
                    log.warn("角色 {} 尝试使用过长的文本发送快递", c.getPlayer().getName());
                    c.disconnect(true, false);
                    return;
                }
                if (!quick) {
                    fee += 5000;
                } else if (!c.getPlayer().haveItem(ItemId.QUICK_DELIVERY_TICKET)) {
                    AutobanFactory.PACKET_EDIT.alert(c.getPlayer(), c.getPlayer().getName() + " 尝试在没有快速配送券的情况下使用快速配送。");
                    log.warn("角色 {} 尝试在没有快速配送券的情况下使用快速配送，金币 {}，数量 {}", c.getPlayer().getName(), sendMesos, amount);
                    c.disconnect(true, false);
                    return;
                }

                long finalcost = (long) sendMesos + fee;
                if (finalcost < 0 || finalcost > Integer.MAX_VALUE || (amount < 1 && sendMesos == 0)) {
                    AutobanFactory.PACKET_EDIT.alert(c.getPlayer(), c.getPlayer().getName() + " 尝试修改快递数据包。");
                    log.warn("角色 {} 尝试使用快递发送金币 {} 和数量 {}", c.getPlayer().getName(), sendMesos, amount);
                    c.disconnect(true, false);
                    return;
                }

                if (c.getPlayer().getMeso() < finalcost) {
                    c.sendPacket(PacketCreator.sendDueyMSG(DueyProcessor.Actions.TOCLIENT_SEND_NOT_ENOUGH_MESOS.getCode()));
                    return;
                }

                var accIdCid = getAccountCharacterIdFromCNAME(recipient);
                var recipientAccId = accIdCid.getLeft();
                var recipientCid = accIdCid.getRight();

                if (recipientAccId == -1 || recipientCid == -1) {
                    c.sendPacket(PacketCreator.sendDueyMSG(DueyProcessor.Actions.TOCLIENT_SEND_NAME_DOES_NOT_EXIST.getCode()));
                    return;
                }

                if (recipientAccId == c.getAccID()) {
                    c.sendPacket(PacketCreator.sendDueyMSG(DueyProcessor.Actions.TOCLIENT_SEND_SAMEACC_ERROR.getCode()));
                    return;
                }

                if (quick) {
                    InventoryManipulator.removeById(c, InventoryType.CASH, ItemId.QUICK_DELIVERY_TICKET, (short) 1, false, false);
                }

                int packageId = createPackage(sendMesos, sendMessage, c.getPlayer().getName(), recipientCid, quick);
                if (packageId == -1) {
                    c.sendPacket(PacketCreator.sendDueyMSG(DueyProcessor.Actions.TOCLIENT_SEND_ENABLE_ACTIONS.getCode()));
                    return;
                }
                c.getPlayer().gainMeso((int) -finalcost, false);

                int res = addPackageItemFromInventory(packageId, c, invTypeId, itemPos, amount);
                if (res == 0) {
                    c.sendPacket(PacketCreator.sendDueyMSG(DueyProcessor.Actions.TOCLIENT_SEND_SUCCESSFULLY_SENT.getCode()));
                } else if (res > 0) {
                    c.sendPacket(PacketCreator.sendDueyMSG(DueyProcessor.Actions.TOCLIENT_SEND_ENABLE_ACTIONS.getCode()));
                } else {
                    c.sendPacket(PacketCreator.sendDueyMSG(DueyProcessor.Actions.TOCLIENT_SEND_INCORRECT_REQUEST.getCode()));
                }

                Client rClient = null;
                int channel = c.getWorldServer().find(recipient);
                if (channel > -1) {
                    Channel rcserv = c.getWorldServer().getChannel(channel);
                    if (rcserv != null) {
                        Character rChr = rcserv.getPlayerStorage().getCharacterByName(recipient);
                        if (rChr != null) {
                            rClient = rChr.getClient();
                        }
                    }
                }

                if (rClient != null && rClient.isLoggedIn() && !rClient.getPlayer().isAwayFromWorld()) {
                    showDueyNotification(rClient, rClient.getPlayer());
                }
            } finally {
                c.releaseClient();
            }
        }
    }

    public static void dueyRemovePackage(Client c, int packageid, boolean playerRemove) {
        if (c.tryacquireClient()) {
            try {
                removePackageFromDB(packageid);
                c.sendPacket(PacketCreator.removeItemFromDuey(playerRemove, packageid));
            } finally {
                c.releaseClient();
            }
        }
    }

    public static synchronized void dueyClaimPackage(Client c, int packageId) {
        DueypackagesMapper mapper = SpringContextUtil.getBean(DueypackagesMapper.class);
        DueypackagesDO dpData = mapper.selectOneById(packageId);

        if (dpData == null) {
            c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_RECV_UNKNOWN_ERROR.getCode()));
            log.warn("角色 {} 尝试接收一个不存在的快递包裹，ID {}", c.getPlayer().getName(), packageId);
            return;
        }

        DueyPackage dp = getPackageFromDB(dpData);
        if (dp == null) {
            c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_RECV_UNKNOWN_ERROR.getCode()));
            return;
        }

        if (!Objects.equals(dp.getReceiverId(), c.getPlayer().getId())) {
            AutobanFactory.PACKET_EDIT.alert(c.getPlayer(), c.getPlayer().getName() + " 尝试修改快递数据包。");
            c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_RECV_UNKNOWN_ERROR.getCode()));
            log.warn("角色 {} 尝试接收一个不属于自己的快递包裹，接收者ID {}", c.getPlayer().getName(), dp.getReceiverId());
            return;
        }

        if (dp.isDeliveringTime()) {
            c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_RECV_UNKNOWN_ERROR.getCode()));
            return;
        }

        Item dpItem = dp.getItem();
        if (dpItem != null) {
            if (!c.getPlayer().canHoldMeso(dp.getMesos())) {
                c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_RECV_UNKNOWN_ERROR.getCode()));
                return;
            }

            if (!InventoryManipulator.checkSpace(c, dpItem.getItemId(), dpItem.getQuantity(), dpItem.getOwner())) {
                int itemid = dpItem.getItemId();
                if (ItemInformationProvider.getInstance().isPickupRestricted(itemid) && c.getPlayer().getInventory(ItemConstants.getInventoryType(itemid)).findById(itemid) != null) {
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_RECV_RECEIVER_WITH_UNIQUE.getCode()));
                } else {
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_RECV_NO_FREE_SLOTS.getCode()));
                }
                return;
            } else {
                InventoryManipulator.addFromDrop(c, dpItem, false);
            }
        }

        c.getPlayer().gainMeso(dp.getMesos(), false);
        dueyRemovePackage(c, packageId, false);
    }

    public static void dueySendTalk(Client c, boolean quickDelivery) {
        if (c.tryacquireClient()) {
            try {
                long timeNow = System.currentTimeMillis();
                if (timeNow - c.getPlayer().getNpcCooldown() < GameConfig.getServerInt("block_npc_race_condition")) {
                    c.sendPacket(PacketCreator.enableActions());
                    return;
                }
                c.getPlayer().setNpcCooldown(timeNow);

                if (quickDelivery) {
                    c.sendPacket(PacketCreator.sendDuey(0x1A, null));
                } else {
                    c.sendPacket(PacketCreator.sendDuey(0x8, loadPackages(c.getPlayer())));
                }
            } finally {
                c.releaseClient();
            }
        }
    }

    public static void dueyCreatePackage(Item item, int mesos, String sender, int recipientCid) {
        int packageId = createPackage(mesos, null, sender, recipientCid, false);
        if (packageId != -1) {
            insertPackageItem(packageId, item);
        }
    }

    public static void runDueyExpireSchedule() {
        DueypackagesMapper mapper = SpringContextUtil.getBean(DueypackagesMapper.class);
        Calendar c = Calendar.getInstance();
        c.add(Calendar.DATE, -30);
        final Timestamp ts = new Timestamp(c.getTime().getTime());

        QueryWrapper query = QueryWrapper.create().select(DueypackagesDO::getPackageid).where(DueypackagesDO::getTimestamp).lt(ts);
        List<DueypackagesDO> toRemove = mapper.selectListByQuery(query);

        for (DueypackagesDO pkg : toRemove) {
            removePackageFromDB(pkg.getPackageid().intValue());
        }
    }
}
