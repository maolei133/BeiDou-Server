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
import org.gms.client.autoban.AutobanFactory;
import org.gms.client.inventory.Equip;
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
import org.gms.model.dto.ItemInfoRtnDTO;
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
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * 快递处理器
 * @author RonanLana - synchronization of Duey modules
 */
@SuppressWarnings("unchecked")
public class DueyProcessor {
    private static final Logger log = LoggerFactory.getLogger(DueyProcessor.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final String DUEY_NAME = "[北斗快递] ";

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
        dueypack.setQuick(data.getType() == 1); // 设置 quick 属性
        
        if (data.getExpireDate() != null) {
            dueypack.setExpireTime(data.getExpireDate().getTime());
        }
        
        if (data.getDeliveryTime() != null) {
            dueypack.setDeliveryTime(data.getDeliveryTime().getTime());
        }

        return dueypack;
    }

    private static List<DueyPackage> loadPackages(Character chr) {
        List<DueyPackage> packages = new LinkedList<>();
        DueypackagesMapper mapper = SpringContextUtil.getBean(DueypackagesMapper.class);
        CharactersMapper charMapper = SpringContextUtil.getBean(CharactersMapper.class);
        
        QueryWrapper query = QueryWrapper.create()
                .where(DueypackagesDO::getReceiverid).eq(chr.getId())
                .and(DueypackagesDO::getChecked).ne(2) // 过滤掉已领取的包裹 (状态2)
                .and(DueypackagesDO::getChecked).ne(4); // 过滤掉已删除的包裹 (状态4)
        List<DueypackagesDO> results = mapper.selectListByQuery(query);

        for (DueypackagesDO data : results) {
            // 实时检查包裹是否已过期
            if (data.getChecked() != 3 && data.getExpireDate() != null && System.currentTimeMillis() >= data.getExpireDate().getTime()) {
                // 标记为已过期
                data.setChecked(3);
                
                // 执行退回逻辑
                processExpiredPackages(Collections.singletonList(data), mapper, charMapper);
                
                // 更新数据库状态 (processExpiredPackages 已经做了，但为了保险起见，这里不需要额外操作，除非 processExpiredPackages 没更新 checked)
                // processExpiredPackages 会更新 checked 为 3 并清理物品
            }
            
            DueyPackage dueypack = getPackageFromDB(data);
            
            // 如果是已过期状态，处理留言并清空物品/金币
            if (data.getChecked() == 3) {
                String originalMessage = dueypack.getMessage() == null ? "" : dueypack.getMessage() + "\n\n";
                String returnMessage = String.format("【玩家 %s 于 %s 给您邮寄的包裹已过期退回，您已无法领取该包裹】",
                        dueypack.getSender(), new SimpleDateFormat("yyyy-MM-dd HH:mm").format(data.getTimestamp()));
                
                // 创建一个新的 DueyPackage 对象，或者修改现有对象
                // 注意：getPackageFromDB 会尝试加载物品，但如果 processExpiredPackages 已经运行，物品可能已经被删除了
                // 所以我们需要手动清空
                dueypack = new DueyPackage(dueypack.getPackageId());
                dueypack.setMessage(originalMessage + returnMessage);
                dueypack.setSender(data.getSendername());
                dueypack.setMesos(0);
                dueypack.setReceiverId(data.getReceiverid().intValue());
                dueypack.setSentTime(data.getTimestamp(), data.getType() == 1);
                dueypack.setQuick(data.getType() == 1);
                if (data.getExpireDate() != null) dueypack.setExpireTime(data.getExpireDate().getTime());
                if (data.getDeliveryTime() != null) dueypack.setDeliveryTime(data.getDeliveryTime().getTime());
            }
            
            if (dueypack != null) {
                packages.add(dueypack);
            }
        }
        return packages;
    }

    public static int createPackage(int mesos, String message, String sender, int toCid, boolean quick, Item item, int senderId, long expireTime) {
        return createPackage(mesos, message, sender, toCid, quick, item, senderId, expireTime, 0);
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
        if (type == 2) {
            newPackage.setType(2); // 退回包裹
        } else {
            newPackage.setType(quick ? 1 : 0);
        }
        newPackage.setChecked(1);
        newPackage.setStatusTime(new Timestamp(System.currentTimeMillis()));
        
        if (deliveryTime > 0) {
            newPackage.setDeliveryTime(new Timestamp(deliveryTime));
        }
        
        // 设置过期时间
        if (expireTime == -1) {
             // 永久不过期 (设置一个极大的时间戳)
             long expireDuration = 3650L * 24 * 60 * 60 * 1000L; // 10年
             newPackage.setExpireDate(new Timestamp(System.currentTimeMillis() + expireDuration));
        } else if (expireTime > 0) {
             newPackage.setExpireDate(new Timestamp(expireTime));
        } else {
             // 默认过期时间 (配置单位为分钟)
             long expireDuration = GameConfig.getServerInt("duey_expire_time", 43200) * 60 * 1000L; // 默认30天
             newPackage.setExpireDate(new Timestamp(System.currentTimeMillis() + expireDuration));
        }
        
        // 序列化 itemData
        if (item != null) {
            ItemInfoRtnDTO itemDTO = convertItemToDTO(item);
            try {
                newPackage.setItemData(objectMapper.writeValueAsString(itemDTO));
            } catch (JsonProcessingException e) {
                log.error("序列化快递包裹物品数据失败", e);
            }
        }

        if (mapper.insert(newPackage, true) > 0) {
            return newPackage.getPackageid().intValue();
        } else {
            log.error("创建包裹失败 [金币: {}, 发件人: {}, 快速: {}, 收件人角色ID: {}]", mesos, sender, quick, toCid);
            return -1;
        }
    }
    
    public static ItemInfoRtnDTO convertItemToDTO(Item item) {
        ItemInfoRtnDTO itemDTO = new ItemInfoRtnDTO();
        itemDTO.setItemId(item.getItemId());
        itemDTO.setQuantity((int) item.getQuantity());
        itemDTO.setOwner(item.getOwner());
        itemDTO.setExpiration(item.getExpiration());
        
        String itemName = ItemInformationProvider.getInstance().getName(item.getItemId());
        itemDTO.setName(itemName != null ? itemName : String.valueOf(item.getItemId()));
        
        // 填充装备属性
        if (item instanceof Equip) {
            Equip equip = (Equip) item;
            itemDTO.setStr(equip.getStr());
            itemDTO.setDex(equip.getDex());
            itemDTO.setInt_(equip.getInt());
            itemDTO.setLuk(equip.getLuk());
            itemDTO.setHp(equip.getHp());
            itemDTO.setMp(equip.getMp());
            itemDTO.setWatk(equip.getWatk());
            itemDTO.setMatk(equip.getMatk());
            itemDTO.setWdef(equip.getWdef());
            itemDTO.setMdef(equip.getMdef());
            itemDTO.setAcc(equip.getAcc());
            itemDTO.setAvoid(equip.getAvoid());
            itemDTO.setHands(equip.getHands());
            itemDTO.setSpeed(equip.getSpeed());
            itemDTO.setJump(equip.getJump());
            itemDTO.setUpgradeSlots(equip.getUpgradeSlots());
            itemDTO.setLevel((byte) equip.getLevel());
            itemDTO.setItemLevel((byte) equip.getItemLevel());
            itemDTO.setFlag(equip.getFlag());
            itemDTO.setVicious(equip.getVicious());
        }
        return itemDTO;
    }

    public static boolean insertPackageItem(int packageId, Item item) {
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
            
            // 更新包裹的 itemData (因为创建包裹时可能还没有物品信息)
            // 这里需要更新数据库中的 itemData 字段
            ItemInfoRtnDTO itemDTO = convertItemToDTO(item);
            try {
                String itemDataJson = objectMapper.writeValueAsString(itemDTO);
                UpdateChain.of(DueypackagesDO.class)
                        .set(DueypackagesDO::getItemData, itemDataJson)
                        .where(DueypackagesDO::getPackageid).eq(packageId)
                        .update();
            } catch (JsonProcessingException e) {
                log.error("更新快递包裹物品数据失败", e);
            }

            if (!insertPackageItem(packageId, item)) {
                return 1;
            }
        }

        return 0;
    }

    private static int getNormalDeliveryTime() {
        return GameConfig.getServerInt("duey_normal_delivery_time", 1440);
    }

    private static String formatDuration(long totalMinutes) {
        if (totalMinutes <= 0) {
            return "立即送达";
        }

        long days = totalMinutes / (24 * 60);
        long remainingMinutesAfterDays = totalMinutes % (24 * 60);
        long hours = remainingMinutesAfterDays / 60;
        long minutes = remainingMinutesAfterDays % 60;

        StringBuilder sb = new StringBuilder();
        if (days > 0) {
            sb.append(days).append("天");
        }
        if (hours > 0) {
            sb.append(hours).append("小时");
        }
        if (minutes > 0) {
            sb.append(minutes).append("分钟");
        }

        if (sb.length() == 0) {
            return "0分钟";
        }
        return sb.toString();
    }

    public static void dueySendItem(Client c, byte invTypeId, short itemPos, short amount, int sendMesos, String sendMessage, String recipient, boolean quick) {
        if (c.tryacquireClient()) {
            try {
                // 优化流程：GM不受use_duey参数控制，仅受minimum_gm_level_to_use_duey参数控制
                boolean isGM = c.getPlayer().isGM();
                int gmLevel = c.getPlayer().gmLevel();
                int minGmLevel = GameConfig.getServerInt("minimum_gm_level_to_use_duey");

                if (isGM) {
                    if (gmLevel < minGmLevel) {
                        c.getPlayer().message("您当前的GM等级无法使用快递。");
                        log.info("GM {} 尝试发送一个包裹给 {}", c.getPlayer().getName(), recipient);
                        c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_INCORRECT_REQUEST.getCode()));
                        return;
                    }
                } else {
                    if (!GameConfig.getServerBoolean("use_duey")) {
                        c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOSERVER_CLOSE_DUEY.getCode()));
                        c.getPlayer().dropMessage(1,DUEY_NAME + "快递服务已经倒闭了，无法继续使用。");
                        return;
                    }
                    
                    if (c.getPlayer().getLevel() < GameConfig.getServerInt("duey_min_level")) {
                        c.getPlayer().message("您的等级不足，无法使用快递。");
                        c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_INCORRECT_REQUEST.getCode()));
                        return;
                    }
                }

                if (quick && !GameConfig.getServerBoolean("enable_duey_quick_delivery")) {
                    c.getPlayer().message("快速配送服务已禁用。");
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_INCORRECT_REQUEST.getCode()));
                    return;
                }

                if (!quick && !GameConfig.getServerBoolean("enable_duey_normal_delivery")) {
                    c.getPlayer().message("普通配送服务已禁用。");
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_INCORRECT_REQUEST.getCode()));
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
                    fee += GameConfig.getServerInt("duey_normal_fee", 5000);
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
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_NOT_ENOUGH_MESOS.getCode()));
                    return;
                }

                var accIdCid = getAccountCharacterIdFromCNAME(recipient);
                var recipientAccId = accIdCid.getLeft();
                var recipientCid = accIdCid.getRight();

                if (recipientAccId == -1 || recipientCid == -1) {
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_NAME_DOES_NOT_EXIST.getCode()));
                    return;
                }

                if (recipientAccId == c.getAccID()) {
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_SAMEACC_ERROR.getCode()));
                    return;
                }

                if (quick) {
                    InventoryManipulator.removeById(c, InventoryType.CASH, ItemId.QUICK_DELIVERY_TICKET, (short) 1, false, false);
                }
                
                // 计算送达时间
                long deliveryTime = 0;
                if (!quick) {
                    // 普通快递：当前时间 + 配置的送达时间 (单位：分钟)
                    long deliveryDuration = getNormalDeliveryTime() * 60 * 1000L;
                    deliveryTime = System.currentTimeMillis() + deliveryDuration;
                }

                // 修正：从游戏内发送快递时，expireTime 应该为 0，让 createPackage 使用默认配置
                int packageId = createPackage(sendMesos, sendMessage, c.getPlayer().getName(), recipientCid, quick, null, c.getPlayer().getId(), 0, deliveryTime);
                if (packageId == -1) {
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_ENABLE_ACTIONS.getCode()));
                    return;
                }
                c.getPlayer().gainMeso((int) -finalcost, true);

                int res = addPackageItemFromInventory(packageId, c, invTypeId, itemPos, amount);
                if (res == 0) {
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_SUCCESSFULLY_SENT.getCode()));
                    c.getPlayer().dropMessage(5, DUEY_NAME + "您邮寄给 " + recipient + " 的普通包裹已邮寄成功，本次邮寄基本费用：" + fee + " 金币，预计送达时间：" + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(deliveryTime));
                } else if (res > 0) {
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_ENABLE_ACTIONS.getCode()));
                } else {
                    c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_SEND_INCORRECT_REQUEST.getCode()));
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
                // 玩家删除包裹时，只是标记为已删除 (状态 4)
                // removePackageFromDB(packageid);
                
                UpdateChain.of(DueypackagesDO.class)
                        .set(DueypackagesDO::getChecked, 4) // 4 表示已删除
                        .set(DueypackagesDO::getStatusTime, new Timestamp(System.currentTimeMillis())) // 记录删除时间
                        .where(DueypackagesDO::getPackageid).eq(packageid)
                        .update();
                
                // 同时清理关联的物品数据，因为物品已经进入玩家背包或者被删除了
                // 恢复：清理物品数据，因为我们已经有了 JSON 备份
                deletePackageFromInventoryDB(packageid);

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

        // 检查包裹是否已过期 (状态 3)
        if (dpData.getChecked() == 3) {
            c.getPlayer().dropMessage(1, "该包裹已超过存放时间，已退回给发件人。");
            c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_RECV_ENABLE_ACTIONS.getCode()));
//            // 从客户端UI中移除该包裹显示
//            c.sendPacket(PacketCreator.removeItemFromDuey(false, packageId));
            return;
        }
        
        // 检查包裹是否已领取 (状态 2)
        if (dpData.getChecked() == 2) {
            c.getPlayer().dropMessage(1, "该包裹已被领取，无法重复领取。");
            c.sendPacket(PacketCreator.sendDueyMSG(Actions.TOCLIENT_RECV_UNKNOWN_ERROR.getCode()));
            // 从客户端UI中移除该包裹显示
            c.sendPacket(PacketCreator.removeItemFromDuey(false, packageId));
            log.warn("角色 {} 尝试重复接收已领取的快递包裹，ID {}", c.getPlayer().getName(), packageId);
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
        
        // 修改逻辑：不再删除包裹，而是更新状态为已领取 (checked = 2) 并更新状态变更时间为当前时间
        // dueyRemovePackage(c, packageId, false);
        
        UpdateChain.of(DueypackagesDO.class)
                .set(DueypackagesDO::getChecked, 2) // 2 表示已领取
                .set(DueypackagesDO::getStatusTime, new Timestamp(System.currentTimeMillis())) // 记录领取时间
                .where(DueypackagesDO::getPackageid).eq(packageId)
                .update();
        
        // 如果是退回的包裹 (type == 2)，需要将原包裹也标记为已领取
        if (dpData.getType() == 2 && dpData.getSenderid() != null && dpData.getSenderid() > 0) {
             // 退回包裹的 senderid 存储的是原包裹的 packageId
             long originalPackageId = dpData.getSenderid();
             UpdateChain.of(DueypackagesDO.class)
                     .set(DueypackagesDO::getChecked, 2)
                     .where(DueypackagesDO::getPackageid).eq(originalPackageId)
                     .and(DueypackagesDO::getChecked).eq(3) // 确保是已过期状态
                     .update();
        }
        
        // 从客户端UI中移除该包裹显示
        c.sendPacket(PacketCreator.removeItemFromDuey(false, packageId));
        
        // 同时需要清理关联的物品数据，因为物品已经进入玩家背包
        // 恢复：清理物品数据，因为我们已经有了 JSON 备份
        deletePackageFromInventoryDB(packageId);
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
                    
                    // 增加邮寄费用和税率的通知说明
                    int normalFee = GameConfig.getServerInt("duey_normal_fee", 5000);
                    String formattedDeliveryTime = formatDuration(getNormalDeliveryTime());
                    c.getPlayer().dropMessage(0, DUEY_NAME + "欢迎使用快递服务，普通包裹邮费：" + normalFee + " 金币，配送时效：" + formattedDeliveryTime);
                    c.getPlayer().dropMessage(1, "欢迎使用快递服务\r\n普快邮费：" + normalFee + " 金币\r\n普快时效：" + formattedDeliveryTime);
                }
            } finally {
                c.releaseClient();
            }
        }
    }

    public static void dueyCreatePackage(Item item, int mesos, String sender, int recipientCid) {
        int packageId = createPackage(mesos, null, sender, recipientCid, false, item, -1, 0);
        if (packageId != -1) {
            insertPackageItem(packageId, item);
        }
    }

    public static void runDueyExpireSchedule() {
        DueypackagesMapper mapper = SpringContextUtil.getBean(DueypackagesMapper.class);
        CharactersMapper charMapper = SpringContextUtil.getBean(CharactersMapper.class);
        
        int expiredCount = 0;
        int deletedCount = 0;
        
        // 1. 清理旧逻辑的过期包裹 (timestamp + duey_expire_time < now)
        // 兼容旧数据，如果 expire_date 为空，则使用 timestamp 计算
        Calendar c = Calendar.getInstance();
        // 配置单位为分钟
        c.setTimeInMillis(System.currentTimeMillis() - (GameConfig.getServerLong("duey_expire_time", 43200L) * 60 * 1000L));
        final Timestamp ts = new Timestamp(c.getTime().getTime());

        QueryWrapper queryOld = QueryWrapper.create()
                .where(DueypackagesDO::getExpireDate).isNull()
                .and(DueypackagesDO::getTimestamp).lt(ts);
        
        List<DueypackagesDO> toRemoveOld = mapper.selectListByQuery(queryOld);
        expiredCount += toRemoveOld.size();
        processExpiredPackages(toRemoveOld, mapper, charMapper);
        
        // 2. 清理新逻辑的过期包裹 (expire_date < now) 且未领取的 (checked != 2)
        QueryWrapper queryNew = QueryWrapper.create()
                .where(DueypackagesDO::getExpireDate).le(new Timestamp(System.currentTimeMillis()))
                .and(DueypackagesDO::getChecked).ne(2) // 已领取的(2)不处理，保持原状
                .and(DueypackagesDO::getChecked).ne(3) // 已经是过期的(3)不处理
                .and(DueypackagesDO::getChecked).ne(4); // 已删除的(4)不处理

        List<DueypackagesDO> toRemoveNew = mapper.selectListByQuery(queryNew);
        expiredCount += toRemoveNew.size();
        processExpiredPackages(toRemoveNew, mapper, charMapper);
        
        // 3. 物理删除已过期、已领取、已删除 N天以上的包裹记录
        long retentionTime = GameConfig.getServerLong("duey_retention_days", 30L) * 24 * 60 * 60 * 1000L;
        Timestamp retentionTs = new Timestamp(System.currentTimeMillis() - retentionTime);
        
        QueryWrapper queryDelete = QueryWrapper.create()
                .select(DueypackagesDO::getPackageid)
                .where(DueypackagesDO::getStatusTime).le(retentionTs)
                .and(DueypackagesDO::getChecked).in(2, 3, 4); // 2:已领取, 3:已过期, 4:已删除
        
        List<DueypackagesDO> toDelete = mapper.selectListByQuery(queryDelete);
        deletedCount = toDelete.size();
        for (DueypackagesDO pkg : toDelete) {
            mapper.deleteById(pkg.getPackageid());
            // 再次确保物品数据被清理
            deletePackageFromInventoryDB(pkg.getPackageid().intValue());
        }
        
        if (expiredCount > 0 || deletedCount > 0) {
            log.info("快递清理任务执行完毕：共处理过期包裹 {} 个，物理删除历史包裹 {} 个。", expiredCount, deletedCount);
        }
    }

    private static void processExpiredPackages(List<DueypackagesDO> packages, DueypackagesMapper mapper, CharactersMapper charMapper) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm");
        
        for (DueypackagesDO pkg : packages) {
            // 1. 尝试恢复物品 (在删除之前)
            Item item = null;
            ItemInfoRtnDTO itemDTO = null;
            // 优先从 JSON 恢复，因为它是最准确的快照
            if (pkg.getItemData() != null && !pkg.getItemData().isEmpty()) {
                try {
                    itemDTO = objectMapper.readValue(pkg.getItemData(), ItemInfoRtnDTO.class);
                    if (itemDTO != null) {
                        item = restoreItemFromDTO(itemDTO);
                    }
                } catch (Exception e) {
                    log.error("从JSON恢复退回包裹的物品失败", e);
                }
            }
            
            // 如果 JSON 恢复失败，尝试从 DB 加载
            if (item == null) {
                List<Pair<Item, InventoryType>> items = ItemFactory.DUEY.loadItems(pkg.getPackageid().intValue(), false);
                if (!items.isEmpty()) {
                    item = items.get(0).getLeft();
                    itemDTO = convertItemToDTO(item);
                }
            }

            // 2. 退回逻辑
            // 检查 senderid 是否有效 (大于 0)
            Long senderId = pkg.getSenderid();
            if (senderId != null && senderId > 0) {
                // 查找发件人是否存在
                CharactersDO sender = charMapper.selectOneById(senderId);
                
                if (sender != null) {
                    String receiverName = "未知";
                    CharactersDO receiver = charMapper.selectOneById(pkg.getReceiverid());
                    if (receiver != null) {
                        receiverName = receiver.getName();
                    }

                    String returnMessage = String.format("您于 %s 寄给 %s 的包裹超时未领取，已自动退回。", 
                            sdf.format(pkg.getTimestamp()), receiverName);
                    
                    // 创建退回包裹
                    // 发件人ID设为原包裹ID (pkg.getPackageid())，以便在领取时能关联回原包裹
                    // 类型设为 2 (退回包裹)
                    
                    int returnPackageId = createPackage(pkg.getMesos().intValue(), returnMessage, "包裹超时退回", sender.getId(), false, item, pkg.getPackageid().intValue(), -1, 0, 2);
                    if (returnPackageId != -1) {
                        if (item != null) {
                            insertPackageItem(returnPackageId, item);
                        }
                    }
                }
            }

            // 3. 标记原包裹为过期并清理数据
            UpdateChain.of(DueypackagesDO.class)
                    .set(DueypackagesDO::getChecked, 3)
                    .set(DueypackagesDO::getStatusTime, new Timestamp(System.currentTimeMillis()))
                    .where(DueypackagesDO::getPackageid).eq(pkg.getPackageid())
                    .update();
            
            deletePackageFromInventoryDB(pkg.getPackageid().intValue());
        }
    }

    private static Item restoreItemFromDTO(ItemInfoRtnDTO itemDTO) {
        Item item;
        if (ItemConstants.getInventoryType(itemDTO.getItemId()) == InventoryType.EQUIP) {
            Equip equip = new Equip(itemDTO.getItemId(), (byte)0, -1);
            equip.setQuantity(itemDTO.getQuantity().shortValue());
            if (itemDTO.getStr() != null) equip.setStr(itemDTO.getStr().shortValue());
            if (itemDTO.getDex() != null) equip.setDex(itemDTO.getDex().shortValue());
            if (itemDTO.getInt_() != null) equip.setInt(itemDTO.getInt_().shortValue());
            if (itemDTO.getLuk() != null) equip.setLuk(itemDTO.getLuk().shortValue());
            if (itemDTO.getHp() != null) equip.setHp(itemDTO.getHp().shortValue());
            if (itemDTO.getMp() != null) equip.setMp(itemDTO.getMp().shortValue());
            if (itemDTO.getWatk() != null) equip.setWatk(itemDTO.getWatk().shortValue());
            if (itemDTO.getMatk() != null) equip.setMatk(itemDTO.getMatk().shortValue());
            if (itemDTO.getWdef() != null) equip.setWdef(itemDTO.getWdef().shortValue());
            if (itemDTO.getMdef() != null) equip.setMdef(itemDTO.getMdef().shortValue());
            if (itemDTO.getAcc() != null) equip.setAcc(itemDTO.getAcc().shortValue());
            if (itemDTO.getAvoid() != null) equip.setAvoid(itemDTO.getAvoid().shortValue());
            if (itemDTO.getHands() != null) equip.setHands(itemDTO.getHands().shortValue());
            if (itemDTO.getSpeed() != null) equip.setSpeed(itemDTO.getSpeed().shortValue());
            if (itemDTO.getJump() != null) equip.setJump(itemDTO.getJump().shortValue());
            if (itemDTO.getUpgradeSlots() != null) equip.setUpgradeSlots(itemDTO.getUpgradeSlots().byteValue());
            if (itemDTO.getLevel() != null) equip.setLevel(itemDTO.getLevel().byteValue());
            if (itemDTO.getItemLevel() != null) equip.setItemLevel(itemDTO.getItemLevel().byteValue());
            if (itemDTO.getFlag() != null) equip.setFlag(itemDTO.getFlag().shortValue());
            if (itemDTO.getVicious() != null) equip.setVicious(itemDTO.getVicious().shortValue());
            if (itemDTO.getOwner() != null) equip.setOwner(itemDTO.getOwner());
            if (itemDTO.getExpiration() != null) equip.setExpiration(itemDTO.getExpiration());
            item = equip;
        } else {
            item = new Item(itemDTO.getItemId(), (byte)0, itemDTO.getQuantity().shortValue(), (byte)0);
            if (itemDTO.getOwner() != null) item.setOwner(itemDTO.getOwner());
            if (itemDTO.getExpiration() != null) item.setExpiration(itemDTO.getExpiration());
        }
        return item;
    }
}
