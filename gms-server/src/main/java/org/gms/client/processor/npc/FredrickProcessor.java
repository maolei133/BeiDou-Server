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
import org.gms.client.inventory.Inventory;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.ItemFactory;
import org.gms.client.inventory.manipulator.InventoryManipulator;
import org.gms.dao.entity.CharactersDO;
import org.gms.dao.entity.FredstorageDO;
import org.gms.dao.entity.HiredMerchantItemsDO;
import org.gms.dao.entity.HiredMerchantTransactionsDO;
import org.gms.dao.entity.HiredMerchantsDO;
import org.gms.dao.entity.InventoryitemsDO;
import org.gms.dao.entity.NotesDO;
import org.gms.dao.mapper.CharactersMapper;
import org.gms.dao.mapper.FredstorageMapper;
import org.gms.dao.mapper.InventoryitemsMapper;
import org.gms.dao.mapper.NotesMapper;
import org.gms.manager.ServerManager;
import org.gms.net.server.Server;
import org.gms.net.server.world.World;
import org.gms.service.HiredMerchantService;
import org.gms.service.TraceabilityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.gms.server.ItemInformationProvider;
import org.gms.server.maps.HiredMerchant;
import org.gms.service.NoteService;
import org.gms.util.PacketCreator;
import org.gms.util.Pair;
import org.gms.util.SpringContextUtil;
import org.springframework.transaction.annotation.Transactional;

import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.concurrent.TimeUnit.DAYS;

/**
 * 弗雷德里克（雇佣商人管理员）处理器
 * @author RonanLana - synchronization of Fredrick modules and operation results
 */
public class FredrickProcessor {
    private static final Logger log = LoggerFactory.getLogger(FredrickProcessor.class);
    private static final int[] dailyReminders = new int[]{2, 5, 10, 15, 30, 60, 90, Integer.MAX_VALUE};

    private final NoteService noteService;
    private static final HiredMerchantService hiredMerchantService = ServerManager.getApplicationContext().getBean(HiredMerchantService.class);
    private static final TraceabilityService traceabilityService = ServerManager.getApplicationContext().getBean(TraceabilityService.class);

    public FredrickProcessor(NoteService noteService) {
        this.noteService = noteService;
    }

    private static byte canRetrieveFromFredrick(Character chr, List<Pair<Item, InventoryType>> items) {
        if (!Inventory.checkSpotsAndOwnership(chr, items)) {
            List<Integer> itemids = new LinkedList<>();
            for (Pair<Item, InventoryType> it : items) {
                itemids.add(it.getLeft().getItemId());
            }

            if (chr.canHoldUniques(itemids)) {
                return 0x22;
            } else {
                return 0x20;
            }
        }

        int netMeso = chr.getMerchantNetMeso();
        if (netMeso > 0) {
            if (!chr.canHoldMeso(netMeso)) {
                return 0x1F;
            }
        } else {
            if (chr.getMeso() < -1 * netMeso) {
                return 0x21;
            }
        }

        return 0x0;
    }

    public static int timestampElapsedDays(Timestamp then, long timeNow) {
        if (then == null) {
            return 0;
        }
        return (int) ((timeNow - then.getTime()) / DAYS.toMillis(1));
    }

    private static String fredrickReminderMessage(int daynotes) {
        String msg;

        if (daynotes < 4) {
            msg = "您好，亲爱的顾客! 我是弗兰德里, 雇佣商人工会的主席. 您的店铺已经关闭" + dailyReminders[daynotes] + " 天了. 请到自由市场入口找我取回存储的物品.";
        } else {
            msg = "您好，亲爱的顾客! 我是弗兰德里, 雇佣商人工会的主席. 您的店铺已经关闭 " + dailyReminders[daynotes] + " 天了. 在我们撤走之前，请考虑索回这些物品";
        }

        return msg;
    }

    public static void removeFredrickLog(int cid) {
        FredstorageMapper mapper = SpringContextUtil.getBean(FredstorageMapper.class);
        QueryWrapper query = QueryWrapper.create()
                .where(FredstorageDO::getCid).eq(cid);
        mapper.deleteByQuery(query);
    }

    public static void insertFredrickLog(int cid) {
        FredstorageMapper mapper = SpringContextUtil.getBean(FredstorageMapper.class);
        
        QueryWrapper query = QueryWrapper.create()
                .where(FredstorageDO::getCid).eq(cid);
        FredstorageDO existing = mapper.selectOneByQuery(query);
        
        if (existing != null) {
            existing.setTimestamp(new Timestamp(System.currentTimeMillis()));
            mapper.update(existing);
        } else {
            FredstorageDO logEntry = new FredstorageDO();
            logEntry.setCid((long) cid);
            logEntry.setDaynotes(0L);
            logEntry.setTimestamp(new Timestamp(System.currentTimeMillis()));
            mapper.insert(logEntry);
        }
    }

    private static void removeFredrickReminders(List<Pair<Integer, Integer>> expiredCids) {
        NotesMapper mapper = SpringContextUtil.getBean(NotesMapper.class);
        List<String> expiredCnames = expiredCids.stream()
                .map(p -> Character.getNameById(p.getLeft()))
                .filter(name -> name != null)
                .collect(Collectors.toList());

        if (!expiredCnames.isEmpty()) {
            QueryWrapper query = QueryWrapper.create()
                    .where(NotesDO::getFrom).eq("FREDRICK")
                    .and(NotesDO::getTo).in(expiredCnames);
            mapper.deleteByQuery(query);
        }
    }

    @Transactional
    public void runFredrickSchedule() {
        FredstorageMapper fredstorageMapper = SpringContextUtil.getBean(FredstorageMapper.class);
        InventoryitemsMapper inventoryitemsMapper = SpringContextUtil.getBean(InventoryitemsMapper.class);

        List<Pair<Integer, Integer>> expiredCids = new LinkedList<>();
        List<Pair<Pair<Integer, String>, Integer>> notifCids = new LinkedList<>();

        QueryWrapper query = QueryWrapper.create()
                .select("f.*", "c.name", "c.world", "c.lastLogoutTime")
                .from(FredstorageDO.class).as("f")
                .leftJoin(CharactersDO.class).as("c").on("c.id = f.cid");

        List<FredrickStorageInfoDTO> results = fredstorageMapper.selectListByQueryAs(query, FredrickStorageInfoDTO.class);
        long curTime = System.currentTimeMillis();

        for (FredrickStorageInfoDTO fredData : results) {
            int cid = fredData.getCid();
            int world = fredData.getWorld();
            Timestamp ts = fredData.getTimestamp();
            int daynotes = Math.min(dailyReminders.length - 1, fredData.getDaynotes());

            int elapsedDays = timestampElapsedDays(ts, curTime);
            if (elapsedDays > 100) {
                expiredCids.add(new Pair<>(cid, world));
            } else {
                int notifDay = dailyReminders[daynotes];
                if (elapsedDays >= notifDay) {
                    do {
                        daynotes++;
                        notifDay = dailyReminders[daynotes];
                    } while (elapsedDays >= notifDay);

                    Timestamp logoutTs = fredData.getLastLogoutTime();
                    int inactivityDays = timestampElapsedDays(logoutTs, curTime);

                    if (inactivityDays < 7 || daynotes >= dailyReminders.length - 1) {
                        String name = fredData.getName();
                        notifCids.add(new Pair<>(new Pair<>(cid, name), daynotes));
                    }
                }
            }
        }

        if (!expiredCids.isEmpty()) {
            List<Integer> cidsToRemove = expiredCids.stream().map(Pair::getLeft).collect(Collectors.toList());

            QueryWrapper deleteItemsQuery = QueryWrapper.create()
                    .where(InventoryitemsDO::getType).eq(ItemFactory.MERCHANT.getValue())
                    .and(InventoryitemsDO::getCharacterid).in(cidsToRemove);
            inventoryitemsMapper.deleteByQuery(deleteItemsQuery);

            UpdateChain.of(CharactersDO.class)
                    .set(CharactersDO::getMerchantmesos, 0)
                    .where(CharactersDO::getId).in(cidsToRemove)
                    .update();

            for (Pair<Integer, Integer> cidPair : expiredCids) {
                World wserv = Server.getInstance().getWorld(cidPair.getRight());
                if (wserv != null) {
                    Character chr = wserv.getPlayerStorage().getCharacterById(cidPair.getLeft());
                    if (chr != null) {
                        chr.setMerchantMeso(0);
                    }
                }
            }

            removeFredrickReminders(expiredCids);
            
            QueryWrapper deleteFredstorageQuery = QueryWrapper.create()
                    .where(FredstorageDO::getCid).in(cidsToRemove);
            fredstorageMapper.deleteByQuery(deleteFredstorageQuery);
        }

        if (!notifCids.isEmpty()) {
            for (Pair<Pair<Integer, String>, Integer> cidInfo : notifCids) {
                UpdateChain.of(FredstorageDO.class)
                        .set(FredstorageDO::getDaynotes, (long) cidInfo.getRight())
                        .where(FredstorageDO::getCid).eq(cidInfo.getLeft().getLeft())
                        .update();

                String msg = fredrickReminderMessage(cidInfo.getRight() - 1);
                noteService.sendNormal(msg, "FREDRICK", cidInfo.getLeft().getRight());
            }
        }
    }

    private static boolean deleteFredrickItems(int cid) {
        InventoryitemsMapper mapper = SpringContextUtil.getBean(InventoryitemsMapper.class);
        QueryWrapper query = QueryWrapper.create()
                .where(InventoryitemsDO::getType).eq(ItemFactory.MERCHANT.getValue())
                .and(InventoryitemsDO::getCharacterid).eq(cid);
        return mapper.deleteByQuery(query) > 0;
    }

    public void fredrickRetrieveItems(Client c) {
        if (c.tryacquireClient()) {
            try {
                Character chr = c.getPlayer();

                List<HiredMerchantsDO> zombieMerchants = hiredMerchantService.getZombieMerchants(chr.getId());
                for (HiredMerchantsDO zombie : zombieMerchants) {
                    World world = Server.getInstance().getWorld(zombie.getWorldId());
                    if (world == null || world.getHiredMerchant(chr.getId()) == null) {
                        zombie.setStatus(HiredMerchantsDO.STATUS_CLOSED);
                        zombie.setCloseTime(System.currentTimeMillis());
                        hiredMerchantService.updateMerchant(zombie);
                        log.info("修复了玩家 {} 的僵尸商店 (ID: {})", chr.getName(), zombie.getId());
                    }
                }

                List<HiredMerchantsDO> merchants = hiredMerchantService.getRetrieveableMerchants(chr.getId());
                List<Pair<Item, InventoryType>> items = new ArrayList<>();
                long totalMesos = 0;

                for (HiredMerchantsDO merchant : merchants) {
                    totalMesos += merchant.getMesos();
                    List<HiredMerchantItemsDO> merchantItems = hiredMerchantService.getRetrieveableItems(merchant.getId());
                    for (HiredMerchantItemsDO itemDO : merchantItems) {
                        short quantity = itemDO.getQuantity() != null ? itemDO.getQuantity().shortValue() : 1;
                        Item item = hiredMerchantService.deserializeItem(itemDO.getItemData(), itemDO.getItemId(), quantity);
                        if (item != null) {
                            if (itemDO.getUid() != null && itemDO.getUid() > 0) {
                                item.setUid(itemDO.getUid());
                            }
                            
                            int remaining = itemDO.getBundles() - itemDO.getSoldQuantity();
                            if (remaining > 0) {
                                item.setQuantity((short) (item.getQuantity() * remaining));
                                items.add(new Pair<>(item, item.getInventoryType()));
                            }
                        }
                    }
                }
                
                List<Pair<Item, InventoryType>> oldItems = ItemFactory.MERCHANT.loadItems(chr.getId(), false);
                items.addAll(oldItems);
                totalMesos += chr.getMerchantNetMeso();

                if (!Inventory.checkSpotsAndOwnership(chr, items)) {
                    chr.sendPacket(PacketCreator.fredrickMessage((byte) 0x20));
                    return;
                }
                
                if (totalMesos > 0 && !chr.canHoldMeso((int) totalMesos)) {
                    chr.sendPacket(PacketCreator.fredrickMessage((byte) 0x1F));
                    return;
                }

                if (totalMesos > 0) {
                    chr.gainMeso((int) totalMesos, false);
                }
                
                for (Pair<Item, InventoryType> it : items) {
                    Item item = it.getLeft();
                    InventoryManipulator.addFromDrop(chr.getClient(), item, false);
                    traceabilityService.log(item, chr, TraceabilityService.ActionType.HIRED_MERCHANT_RETURN, "弗雷德里克取回");
                }

                for (HiredMerchantsDO merchant : merchants) {
                    merchant.setMesos(0L);
                    hiredMerchantService.updateMerchant(merchant);
                    
                    List<HiredMerchantItemsDO> merchantItems = hiredMerchantService.getRetrieveableItems(merchant.getId());
                    for (HiredMerchantItemsDO itemDO : merchantItems) {
                        itemDO.setStatus(HiredMerchantItemsDO.STATUS_RETURNED);
                        hiredMerchantService.updateItem(itemDO);

                        HiredMerchantTransactionsDO transaction = HiredMerchantTransactionsDO.builder()
                                .merchantId(merchant.getId())
                                .itemId(itemDO.getItemId())
                                .buyerId(chr.getId())
                                .type(HiredMerchantTransactionsDO.TYPE_RETURN)
                                .quantity(itemDO.getQuantity() * (itemDO.getBundles() - itemDO.getSoldQuantity()))
                                .timestamp(System.currentTimeMillis())
                                .uid(itemDO.getUid())
                                .build();
                        hiredMerchantService.addTransaction(transaction);
                    }
                }
                
                if (!oldItems.isEmpty()) {
                    deleteFredrickItems(chr.getId());
                }
                chr.setMerchantMeso(0);
                removeFredrickLog(chr.getId());

                chr.sendPacket(PacketCreator.fredrickMessage((byte) 0x1E));

            } catch (Exception e) {
                log.error("从弗雷德里克处检索物品时发生错误", e);
                c.getPlayer().message("发生未知错误。");
            } finally {
                c.releaseClient();
            }
        }
    }

    public static class FredrickStorageInfoDTO {
        private Integer cid;
        private Integer daynotes;
        private Timestamp timestamp;
        private String name;
        private Integer world;
        private Timestamp lastLogoutTime;

        public Integer getCid() { return cid; }
        public void setCid(Integer cid) { this.cid = cid; }
        public Integer getDaynotes() { return daynotes; }
        public void setDaynotes(Integer daynotes) { this.daynotes = daynotes; }
        public Timestamp getTimestamp() { return timestamp; }
        public void setTimestamp(Timestamp timestamp) { this.timestamp = timestamp; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public Integer getWorld() { return world; }
        public void setWorld(Integer world) { this.world = world; }
        public Timestamp getLastLogoutTime() { return lastLogoutTime; }
        public void setLastLogoutTime(Timestamp lastLogoutTime) { this.lastLogoutTime = lastLogoutTime; }
    }
}
