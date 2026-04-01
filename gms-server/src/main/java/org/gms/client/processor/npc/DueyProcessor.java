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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mybatisflex.core.query.QueryWrapper;
import com.mybatisflex.core.update.UpdateChain;
import org.gms.client.Character;
import org.gms.client.Client;
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
import org.gms.manager.ServerManager;
import org.gms.model.dto.ItemInfoRtnDTO;
import org.gms.net.server.channel.Channel;
import org.gms.server.DueyPackage;
import org.gms.server.ItemInformationProvider;
import org.gms.server.Trade;
import org.gms.service.TraceabilityService;
import org.gms.util.ItemConverter;
import org.gms.util.PacketCreator;
import org.gms.util.Pair;
import org.gms.util.SnowflakeIdGenerator;
import org.gms.util.SpringContextUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

/**
 * 快递处理器
 * @author RonanLana - 同步Duey模块
 */
@SuppressWarnings("unchecked")
public class DueyProcessor {
    private static final Logger log = LoggerFactory.getLogger(DueyProcessor.class);
    private static final ObjectMapper objectMapper = SpringContextUtil.getBean(ObjectMapper.class);
    private static final String DUEY_NAME = "[北斗快递] ";
    private static final TraceabilityService traceabilityService = ServerManager.getApplicationContext().getBean(TraceabilityService.class);

    public enum Actions {
        TOSERVER_RECV_ITEM(0x00, "接收物品"),
        TOSERVER_SEND_ITEM(0x02, "发送物品"),
        TOSERVER_CLAIM_PACKAGE(0x04, "领取包裹"),
        TOSERVER_REMOVE_PACKAGE(0x05, "删除包裹"),
        TOSERVER_CLOSE_DUEY(0x07, "关闭快递"),
        TOCLIENT_OPEN_DUEY(0x08, "打开快递"),
        TOCLIENT_SEND_ENABLE_ACTIONS(0x09, "启用操作"),
        TOCLIENT_SEND_NOT_ENOUGH_MESOS(0x0A, "金币不足"),
        TOCLIENT_SEND_INCORRECT_REQUEST(0x0B, "请求错误"),
        TOCLIENT_SEND_NAME_DOES_NOT_EXIST(0x0C, "角色名不存在"),
        TOCLIENT_SEND_SAMEACC_ERROR(0x0D, "同账号错误"),
        TOCLIENT_SEND_RECEIVER_STORAGE_FULL(0x0E, "收件人仓库已满"),
        TOCLIENT_SEND_RECEIVER_UNABLE_TO_RECV(0x0F, "收件人无法接收"),
        TOCLIENT_SEND_RECEIVER_STORAGE_WITH_UNIQUE(0x10, "收件人有唯一物品"),
        TOCLIENT_SEND_MESO_LIMIT(0x11, "金币限制"),
        TOCLIENT_SEND_SUCCESSFULLY_SENT(0x12, "发送成功"),
        TOCLIENT_RECV_UNKNOWN_ERROR(0x13, "未知错误"),
        TOCLIENT_RECV_ENABLE_ACTIONS(0x14, "接收启用操作"),
        TOCLIENT_RECV_NO_FREE_SLOTS(0x15, "没有空闲槽位"),
        TOCLIENT_RECV_RECEIVER_WITH_UNIQUE(0x16, "接收者有唯一物品"),
        TOCLIENT_RECV_SUCCESSFUL_MSG(0x17, "接收成功消息"),
        TOCLIENT_RECV_PACKAGE_MSG(0x1B, "接收包裹消息");
        final byte code;
        final String desc;

        Actions(int code, String desc) {
            this.code = (byte) code;
            this.desc = desc;
        }

        public byte getCode() {
            return code;
        }

        public String getDesc() {
            return desc;
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

    public static void showDueyNotification(Client c, Character player) {
        DueypackagesMapper mapper = SpringContextUtil.getBean(DueypackagesMapper.class);
        QueryWrapper query = QueryWrapper.create()
                .select(DueypackagesDO::getSendername, DueypackagesDO::getType)
                .where(DueypackagesDO::getReceiverid).eq(player.getId())
                .and(DueypackagesDO::getChecked).eq(1)
                .orderBy(DueypackagesDO::getType, false);

        DueypackagesDO result = mapper.selectOneByQuery(query);
        if (result != null) {
            DueypackagesDO updateDO = new DueypackagesDO();
            updateDO.setChecked(0);
            QueryWrapper updateQuery = QueryWrapper.create()
                    .where(DueypackagesDO::getReceiverid).eq(player.getId())
                    .and(DueypackagesDO::getChecked).eq(1); // 仅更新未读包裹
            mapper.updateByQuery(updateDO, updateQuery);
            
            c.sendPacket(PacketCreator.sendDueyParcelReceived(result.getSendername(), result.getType() == 1));
        }
    }

    private static DueyPackage getPackageFromDB(DueypackagesDO data) {
        int packageId = data.getPackageid().intValue();
        Item item = null;

        // 优先从 item_data JSON 字段恢复
        if (data.getItemId() > 0 && data.getItemData() != null && !data.getItemData().isEmpty()) {
            try {
                ItemInfoRtnDTO itemDTO = objectMapper.readValue(data.getItemData(), ItemInfoRtnDTO.class);
                item = ItemConverter.restoreItemFromDTO(data.getItemId(), itemDTO);
            } catch (Exception e) {
                log.error("从JSON恢复包裹物品失败，包裹ID: " + packageId, e);
            }
        }

        // 如果JSON恢复失败或不存在，则尝试从旧的 inventoryitems 表加载（数据迁移逻辑）
        if (item == null && data.getItemId() > 0) {
            List<Pair<Item, InventoryType>> dueyItems = ItemFactory.DUEY.loadItems(packageId, false);
            if (!dueyItems.isEmpty()) {
                item = dueyItems.get(0).getLeft();
                try {
                    // 成功从旧表加载后，立即序列化到新字段，完成迁移
                    String json = objectMapper.writeValueAsString(item.toInfoRtnDTO(true));
                    UpdateChain.of(DueypackagesDO.class)
                            .set(DueypackagesDO::getItemData, json)
                            .where(DueypackagesDO::getPackageid).eq(packageId)
                            .update();
                    // 清理旧表数据
                    ItemFactory.DUEY.saveItems(new LinkedList<>(), packageId);
                    log.info("成功将包裹 {} 的物品从 inventoryitems 迁移到 item_data 字段。", packageId);
                } catch (Exception e) {
                    log.error("迁移包裹物品到JSON失败，包裹ID: " + packageId, e);
                }
            }
        }
        
        if (item != null) {
            if (data.getUid() != null && data.getUid() > 0) {
                item.setUid(data.getUid());
            } else if (item.getUid() <= 0) {
                item.setUid(SnowflakeIdGenerator.getInstance().nextId());
            }
        }

        DueyPackage dueypack = (item != null) ? new DueyPackage(packageId, item) : new DueyPackage(packageId);
        dueypack.setSender(data.getSendername());
        dueypack.setMesos(data.getMesos().intValue());
        dueypack.setSentTime(data.getTimestamp(), data.getType() == 1);
        dueypack.setMessage(data.getMessage());
        dueypack.setReceiverId(data.getReceiverid().intValue());
        dueypack.setQuick(data.getType() == 1);
        if (data.getExpireDate() != null) dueypack.setExpireTime(data.getExpireDate().getTime());
        if (data.getDeliveryTime() != null) dueypack.setDeliveryTime(data.getDeliveryTime().getTime());

        return dueypack;
    }

    private static List<DueyPackage> loadPackages(Character chr) {
        List<DueyPackage> packages = new LinkedList<>();
        DueypackagesMapper mapper = SpringContextUtil.getBean(DueypackagesMapper.class);
        CharactersMapper charMapper = SpringContextUtil.getBean(CharactersMapper.class);
        
        QueryWrapper query = QueryWrapper.create()
                .where(DueypackagesDO::getReceiverid).eq(chr.getId())
                .and(DueypackagesDO::getChecked).ne(2)
                .and(DueypackagesDO::getChecked).ne(4);
        List<DueypackagesDO> results = mapper.selectListByQuery(query);

        for (DueypackagesDO data : results) {
            boolean isExpired = data.getExpireDate() != null && System.currentTimeMillis() >= data.getExpireDate().getTime();
            
            if (data.getChecked() != 3 && data.getChecked() != 5 && isExpired) {
                data.setChecked(5);
                UpdateChain.of(DueypackagesDO.class).set(DueypackagesDO::getChecked, 5).where(DueypackagesDO::getPackageid).eq(data.getPackageid()).update();
            }
            
            if (data.getChecked() == 5) {
                processExpiredPackages(Collections.singletonList(data), mapper, charMapper);
                data.setChecked(3);
            }
            
            DueyPackage dueypack = getPackageFromDB(data);
            
            if (data.getChecked() == 3 || data.getChecked() == 5) {
                String originalMessage = dueypack.getMessage() == null ? "" : dueypack.getMessage() + "\n\n";
                String returnMessage = String.format("\r\n发件：%s\r\n时间：%s\r\n状态：已过期退回",
                        dueypack.getSender(), new SimpleDateFormat("yyyy-MM-dd HH:mm").format(data.getTimestamp()));
                dueypack.setMessage(originalMessage + returnMessage);
            }
            
            packages.add(dueypack);
        }
        return packages;
    }

    public static int createPackage(int mesos, String message, String sender, int toCid, boolean quick, Item item, int senderId, long expireTime) {
        return createPackage(mesos, message, sender, toCid, quick, item, senderId, expireTime, 0, 0);
    }

    public static int createPackage(int mesos, String message, String sender, int toCid, boolean quick, Item item, int senderId, long expireTime, long deliveryTime) {
        return createPackage(mesos, message, sender, toCid, quick, item, senderId, expireTime, deliveryTime, 0);
    }

    public static int createPackage(int mesos, String message, String sender, int toCid, boolean quick, Item item, int senderId, long expireTime, long deliveryTime, int type) {
        DueypackagesMapper mapper = SpringContextUtil.getBean(DueypackagesMapper.class);
        DueypackagesDO newPackage = new DueypackagesDO();
        newPackage.setReceiverid((long) toCid);
        newPackage.setSendername(sender);
        newPackage.setSenderid((long) senderId);
        newPackage.setMesos((long) mesos);
        newPackage.setTimestamp(new Timestamp(System.currentTimeMillis()));
        newPackage.setMessage(message);
        newPackage.setType(type == 2 ? 2 : (quick ? 1 : 0));
        newPackage.setChecked(1);
        newPackage.setStatusTime(new Timestamp(System.currentTimeMillis()));
        
        if (deliveryTime > 0) newPackage.setDeliveryTime(new Timestamp(deliveryTime));
        
        if (expireTime == -1) {
             long expireDuration = 3650L * 24 * 60 * 60 * 1000L; // 10年
             newPackage.setExpireDate(new Timestamp(System.currentTimeMillis() + expireDuration));
        } else if (expireTime > 0) {
             newPackage.setExpireDate(new Timestamp(expireTime));
        } else {
             long expireDuration = GameConfig.getServerInt("duey_expire_time", 43200) * 60 * 1000L; // 默认30天
             newPackage.setExpireDate(new Timestamp(System.currentTimeMillis() + expireDuration));
        }
        
        if (item != null) {
            try {
                // 快递系统，调用 toInfoRtnDTO(true) 以包含数量
                newPackage.setItemData(objectMapper.writeValueAsString(item.toInfoRtnDTO(true)));
            } catch (JsonProcessingException e) {
                log.error("序列化快递包裹物品数据失败", e);
            }
            if (item.getUid() <= 0) item.setUid(SnowflakeIdGenerator.getInstance().nextId());
            newPackage.setUid(item.getUid());
            newPackage.setItemId(item.getItemId());
        }

        if (mapper.insert(newPackage, true) > 0) {
            return newPackage.getPackageid().intValue();
        }
        log.error("创建包裹失败 [金币: {}, 发件人: {}, 快速: {}, 收件人角色ID: {}]", mesos, sender, quick, toCid);
        return -1;
    }

    private static Item addPackageItemFromInventory(int packageId, Client c, byte invTypeId, short itemPos, short amount, String recipient) {
        if (invTypeId <= 0) return null;

        ItemInformationProvider ii = ItemInformationProvider.getInstance();
        InventoryType invType = InventoryType.getByType(invTypeId);
        Inventory inv = c.getPlayer().getInventory(invType);

        Item item;
        inv.lockInventory();
        try {
            item = inv.getItem(itemPos);
            if (item == null || item.getQuantity() < amount) {
                return null;
            }
            if (item.isUntradeable() || ii.isUnmerchable(item.getItemId())) {
                return null;
            }
            
            Item itemToSend = item.copy();
            itemToSend.setQuantity(amount);

            InventoryManipulator.removeFromSlot(c, invType, itemPos, ItemConstants.isRechargeable(item.getItemId()) ? item.getQuantity() : amount, true, false);
            
            KarmaManipulator.toggleKarmaFlagToUntradeable(itemToSend);
            
            try {
                String itemDataJson = objectMapper.writeValueAsString(itemToSend.toInfoRtnDTO(true));
                if (itemToSend.getUid() <= 0) itemToSend.setUid(SnowflakeIdGenerator.getInstance().nextId());
                
                UpdateChain.of(DueypackagesDO.class)
                        .set(DueypackagesDO::getItemData, itemDataJson)
                        .set(DueypackagesDO::getUid, itemToSend.getUid())
                        .set(DueypackagesDO::getItemId, itemToSend.getItemId())
                        .where(DueypackagesDO::getPackageid).eq(packageId)
                        .update();
                
                // 溯源日志：记录发送操作
                var recipientIds = getAccountCharacterIdFromCNAME(recipient);
                traceabilityService.log(itemToSend, c.getPlayer(), TraceabilityService.ActionType.DUEY, TraceabilityService.ActionSourceType.DUEY_SEND, -amount, null, null, recipientIds.getRight(), recipient);
                
                return itemToSend;
            } catch (JsonProcessingException e) {
                log.error("更新快递包裹物品数据失败", e);
                // 如果序列化失败，需要将物品还给玩家
                InventoryManipulator.addFromDrop(c, itemToSend, false);
                return null;
            }
        } finally {
            inv.unlockInventory();
        }
    }

    private static int getNormalDeliveryTime() {
        return GameConfig.getServerInt("duey_normal_delivery_time", 1440);
    }

    private static String formatDuration(long totalMinutes) {
        if (totalMinutes <= 0) return "立即送达";
        long days = totalMinutes / 1440;
        long hours = (totalMinutes % 1440) / 60;
        long minutes = totalMinutes % 60;
        StringBuilder sb = new StringBuilder();
        if (days > 0) sb.append(days).append("天");
        if (hours > 0) sb.append(hours).append("小时");
        if (minutes > 0) sb.append(minutes).append("分钟");
        return sb.length() > 0 ? sb.toString() : "0分钟";
    }

    public static void dueySendItem(Client c, byte invTypeId, short itemPos, short amount, int sendMesos, String sendMessage, String recipient, boolean quick) {
        if (c.tryacquireClient()) {
            try {
                boolean isGM = c.getPlayer().isGM();
                int minGmLevel = GameConfig.getServerInt("minimum_gm_level_to_use_duey");

                if (isGM && c.getPlayer().gmLevel() < minGmLevel) {
                    c.getPlayer().message("您当前的GM等级无法使用快递。");
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_INCORRECT_REQUEST.getCode()));
                    return;
                }
                if (!isGM) {
                    if (!GameConfig.getServerBoolean("use_duey")) {
                        c.getPlayer().dropMessage(1,DUEY_NAME + "快递服务已经倒闭了，无法继续使用。");
                        c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOSERVER_CLOSE_DUEY.getCode()));
                        return;
                    }
                    if (c.getPlayer().getLevel() < GameConfig.getServerInt("duey_min_level")) {
                        c.getPlayer().message("您的等级不足，无法使用快递。");
                        c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_INCORRECT_REQUEST.getCode()));
                        return;
                    }
                }

                if ((quick && !GameConfig.getServerBoolean("enable_duey_quick_delivery")) || (!quick && !GameConfig.getServerBoolean("enable_duey_normal_delivery"))) {
                    c.getPlayer().message((quick ? "快速" : "普通") + "配送服务已禁用。");
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_INCORRECT_REQUEST.getCode()));
                    return;
                }

                if (sendMesos < 0 || (sendMessage != null && sendMessage.length() > 100)) {
                    log.warn("玩家 {} (ID: {}) 尝试发送非法快递 (金币: {}, 消息长度: {})", c.getPlayer().getName(), c.getPlayer().getId(), sendMesos, sendMessage != null ? sendMessage.length() : 0);
                    c.disconnect(true, false);
                    return;
                }

                int fee = Trade.getFee(sendMesos);
                if (!quick) {
                    fee += GameConfig.getServerInt("duey_normal_fee", 5000);
                } else if (!c.getPlayer().haveItem(ItemId.QUICK_DELIVERY_TICKET)) {
                    log.warn("玩家 {} (ID: {}) 尝试在没有快速配送券的情况下使用快速配送", c.getPlayer().getName(), c.getPlayer().getId());
                    c.disconnect(true, false);
                    return;
                }

                if (c.getPlayer().getMeso() < (long) sendMesos + fee) {
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_NOT_ENOUGH_MESOS.getCode()));
                    return;
                }

                var accIdCid = getAccountCharacterIdFromCNAME(recipient);
                if (accIdCid.getRight() == -1) {
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_NAME_DOES_NOT_EXIST.getCode()));
                    return;
                }
                if (accIdCid.getLeft() == c.getAccID()) {
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_SAMEACC_ERROR.getCode()));
                    return;
                }

                if (quick) InventoryManipulator.removeById(c, InventoryType.CASH, ItemId.QUICK_DELIVERY_TICKET, (short) 1, false, false);
                
                long deliveryTime = quick ? 0 : System.currentTimeMillis() + (long)getNormalDeliveryTime() * 60 * 1000L;
                int packageId = createPackage(sendMesos, sendMessage, c.getPlayer().getName(), accIdCid.getRight(), quick, null, c.getPlayer().getId(), 0, deliveryTime, 0);
                if (packageId == -1) {
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_ENABLE_ACTIONS.getCode()));
                    return;
                }
                c.getPlayer().gainMeso(-(sendMesos + fee), true);

                Item sentItem = addPackageItemFromInventory(packageId, c, invTypeId, itemPos, amount, recipient);
                if (sentItem != null) {
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_SUCCESSFULLY_SENT.getCode()));
                    if (!quick) c.getPlayer().dropMessage(5, DUEY_NAME + "您邮寄给 " + recipient + " 的普通包裹已邮寄成功，本次邮寄基本费用：" + fee + " 金币，预计送达时间：" + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(deliveryTime));
                } else if (invTypeId > 0) {
                    // 如果发送物品失败，需要回滚金币和费用
                    c.getPlayer().gainMeso(sendMesos + fee, true);
                    if (quick) InventoryManipulator.addById(c, ItemId.QUICK_DELIVERY_TICKET, (short) 1);
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_INCORRECT_REQUEST.getCode()));
                } else {
                    // 仅发送金币
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_SUCCESSFULLY_SENT.getCode()));
                }

                int channel = c.getWorldServer().find(recipient);
                if (channel > -1) {
                    Channel rcserv = c.getWorldServer().getChannel(channel);
                    if (rcserv != null) {
                        Character rChr = rcserv.getPlayerStorage().getCharacterByName(recipient);
                        if (rChr != null) showDueyNotification(rChr.getClient(), rChr);
                    }
                }
            } finally {
                c.releaseClient();
            }
        }
    }

    public static void dueyRemovePackage(Client c, int packageid, boolean playerRemove) {
        if (c.tryacquireClient()) {
            try {
                DueypackagesMapper mapper = SpringContextUtil.getBean(DueypackagesMapper.class);
                DueypackagesDO pkg = mapper.selectOneById(packageid);
                
                if (pkg != null && Objects.equals(pkg.getReceiverid(), (long)c.getPlayer().getId())) {
                    UpdateChain.of(DueypackagesDO.class)
                            .set(DueypackagesDO::getChecked, 4)
                            .set(DueypackagesDO::getStatusTime, new Timestamp(System.currentTimeMillis()))
                            .where(DueypackagesDO::getPackageid).eq(packageid).update();
                    
                    // 溯源日志：记录删除操作
                    traceabilityService.log(null, c.getPlayer(), TraceabilityService.ActionType.DUEY, TraceabilityService.ActionSourceType.DUEY_DELETE, 0, null, null, (long)pkg.getSenderid(), pkg.getSendername());
                    c.sendPacket(PacketCreator.removeItemFromDuey(playerRemove, packageid));
                }
            } finally {
                c.releaseClient();
            }
        }
    }

    public static synchronized void dueyClaimPackage(Client c, int packageId) {
        DueypackagesMapper mapper = SpringContextUtil.getBean(DueypackagesMapper.class);
        DueypackagesDO dpData = mapper.selectOneById(packageId);

        if (dpData == null || !Objects.equals(dpData.getReceiverid(), (long)c.getPlayer().getId())) {
            c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_RECV_UNKNOWN_ERROR.getCode()));
            return;
        }

        if (dpData.getChecked() == 3) {
            c.getPlayer().dropMessage(1, "该包裹已超过存放时间，已退回给发件人。");
            c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_RECV_ENABLE_ACTIONS.getCode()));
            return;
        }
        if (dpData.getChecked() == 2) {
            c.getPlayer().dropMessage(1, "该包裹已被领取，无法重复领取。");
            c.sendPacket(PacketCreator.removeItemFromDuey(false, packageId));
            return;
        }

        DueyPackage dp = getPackageFromDB(dpData);
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
                if (ItemInformationProvider.getInstance().isPickupRestricted(dpItem.getItemId()) && c.getPlayer().getInventory(ItemConstants.getInventoryType(dpItem.getItemId())).findById(dpItem.getItemId()) != null) {
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_RECV_RECEIVER_WITH_UNIQUE.getCode()));
                } else {
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_RECV_NO_FREE_SLOTS.getCode()));
                }
                return;
            }
            InventoryManipulator.addFromDrop(c, dpItem, false);
            
            // 溯源日志：记录接收操作
            traceabilityService.log(dpItem, c.getPlayer(), TraceabilityService.ActionType.DUEY, TraceabilityService.ActionSourceType.DUEY_RECEIVE, dpItem.getQuantity(), null, null, dpData.getSenderid(), dp.getSender());
        }

        c.getPlayer().gainMeso(dp.getMesos(), false);
        
        UpdateChain.of(DueypackagesDO.class)
                .set(DueypackagesDO::getChecked, 2)
                .set(DueypackagesDO::getStatusTime, new Timestamp(System.currentTimeMillis()))
                .where(DueypackagesDO::getPackageid).eq(packageId).update();
        
        if (dpData.getType() == 2 && dpData.getSenderid() != null && dpData.getSenderid() > 0) {
             UpdateChain.of(DueypackagesDO.class)
                     .set(DueypackagesDO::getChecked, 2)
                     .where(DueypackagesDO::getPackageid).eq(dpData.getSenderid())
                     .and(DueypackagesDO::getChecked).eq(3).update();
        }
        
        c.sendPacket(PacketCreator.removeItemFromDuey(false, packageId));
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
                    int normalFee = GameConfig.getServerInt("duey_normal_fee", 5000);
                    String formattedDeliveryTime = formatDuration(getNormalDeliveryTime());
                    c.getPlayer().dropMessage(0, DUEY_NAME + "欢迎使用快递服务，普通包裹邮费：" + normalFee + " 金币，配送时效：" + formattedDeliveryTime);
                }
            } finally {
                c.releaseClient();
            }
        }
    }

    public static void dueyCreatePackage(Item item, int mesos, String sender, int recipientCid) {
        int packageId = createPackage(mesos, null, sender, recipientCid, false, item, -1, 0);
    }

    public static void runDueyExpireSchedule() {
        DueypackagesMapper mapper = SpringContextUtil.getBean(DueypackagesMapper.class);
        CharactersMapper charMapper = SpringContextUtil.getBean(CharactersMapper.class);
        
        long now = System.currentTimeMillis();
        long defaultExpire = GameConfig.getServerLong("duey_expire_time", 43200L) * 60 * 1000L;
        Timestamp oldExpireTs = new Timestamp(now - defaultExpire);

        List<DueypackagesDO> toProcess = new LinkedList<>();
        toProcess.addAll(mapper.selectListByQuery(QueryWrapper.create().where(DueypackagesDO::getExpireDate).isNull().and(DueypackagesDO::getTimestamp).lt(oldExpireTs)));
        toProcess.addAll(mapper.selectListByQuery(QueryWrapper.create().where(DueypackagesDO::getExpireDate).le(new Timestamp(now)).and(DueypackagesDO::getChecked).in(0, 1)));

        if (!toProcess.isEmpty()) {
            processExpiredPackages(toProcess, mapper, charMapper);
            log.info("快递清理任务：处理了 {} 个过期包裹。", toProcess.size());
        }
        
        long retentionTime = GameConfig.getServerLong("duey_retention_days", 30L) * 24 * 60 * 60 * 1000L;
        Timestamp retentionTs = new Timestamp(now - retentionTime);
        
        int deletedCount = mapper.deleteByQuery(QueryWrapper.create().where(DueypackagesDO::getStatusTime).le(retentionTs).and(DueypackagesDO::getChecked).in(2, 3, 4));
        if (deletedCount > 0) {
            log.info("快递清理任务：物理删除了 {} 个历史包裹。", deletedCount);
        }
    }

    private static void processExpiredPackages(List<DueypackagesDO> packages, DueypackagesMapper mapper, CharactersMapper charMapper) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm");
        
        for (DueypackagesDO pkg : packages) {
            if (pkg.getChecked() == 2 || pkg.getChecked() == 3 || pkg.getChecked() == 4) continue;

            Item item = null;
            if (pkg.getItemId() > 0 && pkg.getItemData() != null && !pkg.getItemData().isEmpty()) {
                try {
                    item = ItemConverter.restoreItemFromDTO(pkg.getItemId(), objectMapper.readValue(pkg.getItemData(), ItemInfoRtnDTO.class));
                } catch (Exception e) {
                    log.error("从JSON恢复退回包裹的物品失败", e);
                }
            }

            if (pkg.getSenderid() != null && pkg.getSenderid() > 0 && pkg.getType() != 2) {
                CharactersDO sender = charMapper.selectOneById(pkg.getSenderid());
                if (sender != null) {
                    long count = mapper.selectCountByQuery(QueryWrapper.create().where(DueypackagesDO::getType).eq(2).and(DueypackagesDO::getSenderid).eq(pkg.getPackageid()));
                    if (count == 0) {
                        CharactersDO receiver = charMapper.selectOneById(pkg.getReceiverid());
                        String receiverName = (receiver != null) ? receiver.getName() : "未知";
                        String returnMessage = String.format("您于 %s 寄给 %s 的包裹超时未领取，已自动退回。", sdf.format(pkg.getTimestamp()), receiverName);
                        
                        // 溯源日志：记录退回操作
                        if (item != null) {
                            traceabilityService.log(item, sender.getAccountid(), sender.getId(), -1, TraceabilityService.ActionType.DUEY, TraceabilityService.ActionSourceType.DUEY_RETURN, item.getQuantity(), null, null, pkg.getReceiverid(), receiverName);
                        }

                        createPackage(pkg.getMesos().intValue(), returnMessage, "包裹超时退回", sender.getId(), false, item, pkg.getPackageid().intValue(), -1, 0, 2);
                    }
                }
            }

            UpdateChain.of(DueypackagesDO.class)
                    .set(DueypackagesDO::getChecked, 3)
                    .set(DueypackagesDO::getStatusTime, new Timestamp(System.currentTimeMillis()))
                    .where(DueypackagesDO::getPackageid).eq(pkg.getPackageid()).update();
        }
    }

    public static void showDueyNotification(Character player) {
        showDueyNotification(player.getClient(), player);
    }

    /**
     * 将 Item 对象转换为用于序列化的 DTO。
     * 这是一个兼容性方法，最终应被 item.toInfoRtnDTO() 替代。
     * @param item 物品对象
     * @return 物品信息DTO
     */
    public static ItemInfoRtnDTO convertItemToDTO(Item item) {
        return item.toInfoRtnDTO(true);
    }
}
