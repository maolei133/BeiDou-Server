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

import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.autoban.AutobanFactory;
import org.gms.client.inventory.Inventory;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.manipulator.InventoryManipulator;
import org.gms.client.inventory.manipulator.KarmaManipulator;
import org.gms.config.GameConfig;
import org.gms.constants.game.GameConstants;
import org.gms.constants.id.ItemId;
import org.gms.constants.inventory.ItemConstants;
import org.gms.dao.entity.HiredMerchantItemsDO;
import org.gms.dao.entity.HiredMerchantsDO;
import org.gms.manager.ServerManager;
import org.gms.net.AbstractPacketHandler;
import org.gms.net.packet.InPacket;
import org.gms.service.HiredMerchantService;
import org.gms.service.TraceabilityService;
import org.gms.util.I18nUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.gms.server.ItemInformationProvider;
import org.gms.server.Trade;
import org.gms.server.maps.FieldLimit;
import org.gms.server.maps.HiredMerchant;
import org.gms.server.maps.MapObject;
import org.gms.server.maps.MapObjectType;
import org.gms.server.maps.MiniGame;
import org.gms.server.maps.MiniGame.MiniGameType;
import org.gms.server.maps.PlayerShop;
import org.gms.server.maps.PlayerShopItem;
import org.gms.server.maps.Portal;
import org.gms.util.PacketCreator;
import org.gms.util.SnowflakeIdGenerator;

import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * @author Matze
 * @author Ronan - concurrency safety and reviewed minigames
 */
public final class PlayerInteractionHandler extends AbstractPacketHandler {
    private static final Logger log = LoggerFactory.getLogger(PlayerInteractionHandler.class);
    private static final HiredMerchantService hiredMerchantService = ServerManager.getApplicationContext().getBean(HiredMerchantService.class);

    public enum Action {
        CREATE(0, "创建"),
        INVITE(2, "邀请"),
        DECLINE(3, "拒绝"),
        VISIT(4, "访问"),
        ROOM(5, "房间"),
        CHAT(6, "聊天"),
        CHAT_THING(8, "聊天相关"),
        EXIT(0xA, "退出"),
        OPEN_STORE(0xB, "开店"),
        OPEN_CASH(0xE, "打开现金商店"),
        SET_ITEMS(0xF, "设置物品"),
        SET_MESO(0x10, "设置金币"),
        CONFIRM(0x11, "确认"),
        TRANSACTION(0x14, "交易"),
        ADD_ITEM(0x16, "添加物品"),
        BUY(0x17, "购买"),
        UPDATE_MERCHANT(0x19, "更新雇佣商人"),
        UPDATE_PLAYERSHOP(0x1A, "更新玩家商店"),
        REMOVE_ITEM(0x1B, "移除物品"),
        BAN_PLAYER(0x1C, "封禁玩家"),
        MERCHANT_THING(0x1D, "雇佣商人相关"),
        OPEN_THING(0x1E, "打开相关"),
        PUT_ITEM(0x21, "放置物品"),
        MERCHANT_BUY(0x22, "雇佣商人购买"),
        TAKE_ITEM_BACK(0x26, "取回物品"),
        MAINTENANCE_OFF(0x27, "维护结束"),
        MERCHANT_ORGANIZE(0x28, "整理雇佣商人"),
        CLOSE_MERCHANT(0x29, "关闭雇佣商人"),
        REAL_CLOSE_MERCHANT(0x2A, "真正关闭雇佣商人"),
        MERCHANT_MESO(0x2B, "雇佣商人金币"),
        SOMETHING(0x2D, "其他"),
        VIEW_VISITORS(0x2E, "查看访客"),
        VIEW_BLACKLIST(0x2F, "查看黑名单"),
        ADD_TO_BLACKLIST(0x30, "添加到黑名单"),
        REMOVE_FROM_BLACKLIST(0x31, "从黑名单移除"),
        REQUEST_TIE(0x32, "请求平局"),
        ANSWER_TIE(0x33, "回应平局"),
        GIVE_UP(0x34, "放弃"),
        EXIT_AFTER_GAME(0x38, "游戏后退出"),
        CANCEL_EXIT_AFTER_GAME(0x39, "取消游戏后退出"),
        READY(0x3A, "准备"),
        UN_READY(0x3B, "取消准备"),
        EXPEL(0x3C, "驱逐"),
        START(0x3D, "开始"),
        GET_RESULT(0x3E, "获取结果"),
        SKIP(0x3F, "跳过"),
        MOVE_OMOK(0x40, "移动五子棋"),
        SELECT_CARD(0x44, "选择卡片");
        final byte code;
        final String name;

        Action(int code, String name) {
            this.code = (byte) code;
            this.name = name;
        }

        public byte getCode() {
            return code;
        }

        public String getName() {
            return name;
        }
    }

    private static int establishMiniroomStatus(Character chr, boolean isMinigame) {
        if (isMinigame && FieldLimit.CANNOTMINIGAME.check(chr.getMap().getFieldLimit())) {
            return 11;
        }

        if (chr.getChalkboard() != null) {
            return 13;
        }

        if (chr.getEventInstance() != null) {
            return 5;
        }

        return 0;
    }

    @Override
    public final void handlePacket(InPacket p, Client c) {
        if (!c.tryacquireClient()) {    // thanks GabrielSin for pointing dupes within player interactions // 感谢 GabrielSin 指出玩家交互中的复制漏洞
            c.sendPacket(PacketCreator.enableActions());
            return;
        }

        try {
            byte mode = p.readByte();
            final Character chr = c.getPlayer();

            if (mode == Action.CREATE.getCode()) {
                if (!chr.isAlive()) {    // thanks GabrielSin for pointing this // 感谢 GabrielSin 指出这一点
                    chr.sendPacket(PacketCreator.getMiniRoomError(4));
                    return;
                }

                byte createType = p.readByte();
                if (createType == 3) {  // trade // 交易
                    Trade.startTrade(chr);
                } else if (createType == 1) { // omok mini game // 五子棋小游戏
                    int status = establishMiniroomStatus(chr, true);
                    if (status > 0) {
                        chr.sendPacket(PacketCreator.getMiniRoomError(status));
                        return;
                    }

                    String desc = p.readString();
                    String pw;

                    if (p.readByte() != 0) {
                        pw = p.readString();
                    } else {
                        pw = "";
                    }

                    int type = p.readByte();
                    if (type > 11) {
                        type = 11;
                    } else if (type < 0) {
                        type = 0;
                    }
                    if (!chr.haveItem(ItemId.MINI_GAME_BASE + type)) {
                        chr.sendPacket(PacketCreator.getMiniRoomError(6));
                        return;
                    }

                    MiniGame game = new MiniGame(chr, desc, pw);
                    chr.setMiniGame(game);
                    game.setPieceType(type);
                    game.setGameType(MiniGameType.OMOK);
                    chr.getMap().addMapObject(game);
                    chr.getMap().broadcastMessage(PacketCreator.addOmokBox(chr, 1, 0));
                    game.sendOmok(c, type);
                } else if (createType == 2) { // matchcard // 记忆卡片
                    int status = establishMiniroomStatus(chr, true);
                    if (status > 0) {
                        chr.sendPacket(PacketCreator.getMiniRoomError(status));
                        return;
                    }

                    String desc = p.readString();
                    String pw;

                    if (p.readByte() != 0) {
                        pw = p.readString();
                    } else {
                        pw = "";
                    }

                    int type = p.readByte();
                    if (type > 2) {
                        type = 2;
                    } else if (type < 0) {
                        type = 0;
                    }
                    if (!chr.haveItem(ItemId.MATCH_CARDS)) {
                        chr.sendPacket(PacketCreator.getMiniRoomError(6));
                        return;
                    }

                    MiniGame game = new MiniGame(chr, desc, pw);
                    game.setPieceType(type);
                    if (type == 0) {
                        game.setMatchesToWin(6);
                    } else if (type == 1) {
                        game.setMatchesToWin(10);
                    } else if (type == 2) {
                        game.setMatchesToWin(15);
                    }
                    game.setGameType(MiniGameType.MATCH_CARD);
                    chr.setMiniGame(game);
                    chr.getMap().addMapObject(game);
                    chr.getMap().broadcastMessage(PacketCreator.addMatchCardBox(chr, 1, 0));
                    game.sendMatchCard(c, type);
                } else if (createType == 4 || createType == 5) { // shop // 商店
                    if (!GameConstants.isFreeMarketRoom(chr.getMapId())) {
                        chr.sendPacket(PacketCreator.getMiniRoomError(15));
                        return;
                    }

                    int status = establishMiniroomStatus(chr, false);
                    if (status > 0) {
                        chr.sendPacket(PacketCreator.getMiniRoomError(status));
                        return;
                    }

                    if (!canPlaceStore(chr)) {
                        return;
                    }

                    String desc = p.readString();
                    p.skip(3);
                    int itemId = p.readInt();
                    if (chr.getInventory(InventoryType.CASH).countById(itemId) < 1) {
                        chr.sendPacket(PacketCreator.getMiniRoomError(6));
                        return;
                    }

                    if (ItemConstants.isPlayerShop(itemId)) {
                        PlayerShop shop = new PlayerShop(chr, desc, itemId);
                        chr.setPlayerShop(shop);
                        chr.getMap().addMapObject(shop);
                        shop.sendShop(c);
                        c.getWorldServer().registerPlayerShop(shop);
                        //c.sendPacket(PacketCreator.getPlayerShopRemoveVisitor(1));
                    } else if (ItemConstants.isHiredMerchant(itemId)) {
                        // 0. 检查是否有未领取的物品或金币
                        List<HiredMerchantsDO> retrieveableMerchants = hiredMerchantService.getRetrieveableMerchants(chr.getId());
                        if (!retrieveableMerchants.isEmpty()) {
                            boolean hasItemsOrMesos = false;
                            for (HiredMerchantsDO merchant : retrieveableMerchants) {
                                if (merchant.getMesos() > 0) {
                                    hasItemsOrMesos = true;
                                    break;
                                }
                                List<HiredMerchantItemsDO> items = hiredMerchantService.getRetrieveableItems(merchant.getId());
                                if (!items.isEmpty()) {
                                    hasItemsOrMesos = true;
                                    break;
                                }
                            }
                            
                            if (hasItemsOrMesos) {
                                chr.dropMessage(1, "您有未领取的物品或金币，请先前往弗雷德里克处领取。");
                                return;
                            }
                        }

                        // 1. 检查是否有已开业的商店 (ACTIVE)
                        HiredMerchantsDO activeMerchant = hiredMerchantService.getActiveMerchantByOwnerId(chr.getId());
                        if (activeMerchant != null) {
                            // 检查内存中是否存在该商店
                            HiredMerchant memoryMerchant = c.getWorldServer().getHiredMerchant(chr.getId());
                            if (memoryMerchant == null) {
                                // 尝试从数据库恢复
                                try {
                                    HiredMerchant restoredMerchant = new HiredMerchant(activeMerchant, chr.getName());
                                    
                                    // 检查地图是否匹配
                                    if (chr.getMapId() != activeMerchant.getMapId()) {
                                        // 如果玩家不在商店地图，无法直接恢复可见性，提示玩家前往
                                        chr.dropMessage(1, "您已经有一家商店开业了 (在频道 " + activeMerchant.getChannel() + "，地图 " + activeMerchant.getMapId() + ")。");
                                        return;
                                    }
                                    
                                    restoredMerchant.setMap(chr.getMap());
                                    
                                    // 加载物品
                                    List<HiredMerchantItemsDO> items = hiredMerchantService.getMerchantItems(activeMerchant.getId());
                                    restoredMerchant.loadItemsFromDb(items);
                                    
                                    // 注册到服务器
                                    boolean merchantAdded = chr.getClient().getChannelServer().addHiredMerchant(chr.getId(), restoredMerchant);
                                    if (merchantAdded) {
                                        c.getWorldServer().registerHiredMerchant(restoredMerchant);
                                        chr.getMap().addMapObject(restoredMerchant);
                                        chr.getMap().broadcastMessage(PacketCreator.spawnHiredMerchantBox(restoredMerchant));
                                        
                                        // 恢复定时任务
                                        restoredMerchant.rescheduleClose();
                                        
                                        chr.dropMessage(1, "您的商店已成功恢复。");
                                        return;
                                    } else {
                                        // 注册失败，回退到关闭逻辑
                                        throw new RuntimeException("无法注册恢复的商店");
                                    }
                                } catch (Exception e) {
                                    log.error("尝试恢复 ACTIVE 商店失败，转为关闭流程", e);
                                    // 恢复失败，判定为僵尸商店，执行关闭
                                    activeMerchant.setStatus(HiredMerchantsDO.STATUS_CLOSED);
                                    activeMerchant.setCloseTime(System.currentTimeMillis());
                                    hiredMerchantService.updateMerchant(activeMerchant);
                                    chr.dropMessage(1, "检测到异常关闭的商店且无法恢复，已自动将其关闭。请通过弗雷德里克取回物品。");
                                    return;
                                }
                            }

                            // 内存中存在商店，修正状态并提示
                            if (!chr.hasMerchant()) {
                                chr.setHasMerchant(true);
                            }
                            
                            // 尝试恢复可见性 (如果对象存在但未显示)
                            if (memoryMerchant.getMap() == null) {
                                memoryMerchant.setMap(chr.getMap());
                            }
                            if (memoryMerchant.getMap().getMapObject(memoryMerchant.getObjectId()) == null) {
                                if (chr.getMapId() == memoryMerchant.getMapId()) {
                                    memoryMerchant.setPosition(chr.getPosition());
                                    memoryMerchant.getMap().addMapObject(memoryMerchant);
                                    memoryMerchant.getMap().broadcastMessage(PacketCreator.spawnHiredMerchantBox(memoryMerchant));
                                }
                            }

                            String msg = "您已经有一家商店开业了";
                            if (memoryMerchant.getChannel() != c.getChannel()) {
                                msg += " (在频道 " + memoryMerchant.getChannel() + ")";
                            }
                            chr.dropMessage(1, msg);
                            return;
                        }

                        // 2. 检查是否有预开业的商店 (PREPARING) - 用于断线恢复
                        HiredMerchantsDO preparingMerchant = hiredMerchantService.getPreparingMerchantByOwnerId(chr.getId());
                        if (preparingMerchant != null) {
                            // 尝试恢复商店
                            
                            // 1. 检查地图是否匹配
                            if (chr.getMapId() != preparingMerchant.getMapId()) {
                                // 地图不匹配，无法原地恢复，只能关闭
                                preparingMerchant.setStatus(HiredMerchantsDO.STATUS_CLOSED);
                                preparingMerchant.setCloseTime(System.currentTimeMillis());
                                hiredMerchantService.updateMerchant(preparingMerchant);
                                chr.dropMessage(1, "您在其他地图有未完成的商店，已自动关闭。请通过弗雷德里克取回物品。");
                                return;
                            }

                            // ----------------------------------------------------------------
                            // 关键修改：优先复用内存中的旧对象，而不是盲目重建
                            // ----------------------------------------------------------------
                            HiredMerchant oldMerchant = c.getWorldServer().getHiredMerchant(chr.getId());
                            HiredMerchant restoredMerchant;

                            if (oldMerchant != null) {
                                // 如果内存中已有对象，直接复用它
                                restoredMerchant = oldMerchant;
                                
                                // 确保它在当前地图（如果不在，可能需要迁移或者报错，但这里假设地图ID匹配）
                                if (restoredMerchant.getMap() == null) {
                                    restoredMerchant.setMap(chr.getMap());
                                }
                                
                                // 更新坐标到当前玩家位置
                                restoredMerchant.setPosition(chr.getPosition());
                                
                                // 如果它不在地图中显示（例如掉线被移除了），重新加入地图
                                if (restoredMerchant.getMap().getMapObject(restoredMerchant.getObjectId()) == null) {
                                    // 注意：这里不广播 spawnHiredMerchantBox，因为还没 open
                                    // 但为了让 canPlaceStore 能检测到它（如果需要），或者为了后续逻辑
                                    // 其实 PREPARING 状态的商店不应该显示给别人，所以不加到地图也没关系
                                    // 只要它在 ChannelServer 的 hiredMerchants 列表里就行
                                }
                                
                                log.info("复用已存在的 HiredMerchant 对象: {}, 招牌: {} -> {}, 店主: {}",
                                    restoredMerchant.getMerchantId(), restoredMerchant.getDescription(),desc, chr.getName());
                            } else {
                                // 内存中没有，才重建
                                restoredMerchant = new HiredMerchant(preparingMerchant, chr.getName());
                                restoredMerchant.setMap(chr.getMap());
                                restoredMerchant.setPosition(chr.getPosition());
                                
                                // 加载物品
                                List<HiredMerchantItemsDO> items = hiredMerchantService.getMerchantItems(preparingMerchant.getId());
                                restoredMerchant.loadItemsFromDb(items);
                                
                                // 注册到服务器内存
                                boolean merchantAdded = chr.getClient().getChannelServer().addHiredMerchant(chr.getId(), restoredMerchant);
                                if (merchantAdded) {
                                    c.getWorldServer().registerHiredMerchant(restoredMerchant);
                                } else {
                                    // 注册失败（理论上不应该，因为我们已经检查了 oldMerchant 为 null）
                                    preparingMerchant.setStatus(HiredMerchantsDO.STATUS_CLOSED);
                                    preparingMerchant.setCloseTime(System.currentTimeMillis());
                                    hiredMerchantService.updateMerchant(preparingMerchant);
                                    chr.dropMessage(1, "无法恢复商店，已自动关闭。请通过弗雷德里克取回物品。");
                                    return;
                                }
                            }

                            // 更新商店信息
                            preparingMerchant.setDescription(desc);
                            // 更新数据库坐标
                            preparingMerchant.setX(chr.getPosition().x);
                            preparingMerchant.setY(chr.getPosition().y);
                            hiredMerchantService.updateMerchant(preparingMerchant);

                            // 绑定到当前角色
                            chr.setHiredMerchant(restoredMerchant);
                            
                            // 发送恢复包
                            chr.sendPacket(PacketCreator.getHiredMerchant(chr, restoredMerchant, true));
                            chr.dropMessage(1, "已恢复您上次未完成的商店设置。");
                            return;
                        }

                        if (chr.hasMerchant() && c.getWorldServer().getHiredMerchant(chr.getId()) == null) {
                            chr.setHasMerchant(false);
                        }

                        // ----------------------------------------------------------------
                        // 新开店流程：同样先检查内存清理
                        // ----------------------------------------------------------------
                        HiredMerchant ghostMerchant = c.getWorldServer().getHiredMerchant(chr.getId());
                        if (ghostMerchant != null) {
                            // 如果内存中有残留对象（但数据库没有 ACTIVE/PREPARING），说明是脏数据
                            // 必须清理，否则新对象无法注册
                            if (ghostMerchant.getMap() != null) {
                                ghostMerchant.getMap().removeMapObject(ghostMerchant);
                                ghostMerchant.getMap().broadcastMessage(PacketCreator.removeHiredMerchantBox(chr.getId()));
                            }
                            c.getChannelServer().removeHiredMerchant(chr.getId());
                            c.getWorldServer().unregisterHiredMerchant(ghostMerchant);
                        }

                        HiredMerchant merchant = new HiredMerchant(chr, desc, itemId);

                        HiredMerchantsDO newMerchantDO = HiredMerchantsDO.builder()
                                .ownerId(chr.getId())
                                .channel(c.getChannel())
                                .worldId(chr.getWorld())
                                .mapId(chr.getMapId())
                                .x(chr.getPosition().x)
                                .y(chr.getPosition().y)
                                .description(desc)
                                .itemId(itemId)
                                .status(HiredMerchantsDO.STATUS_PREPARING) // 初始状态设为 PREPARING
                                .startTime(System.currentTimeMillis())
                                .mesos(0L)
                                .build();

                        hiredMerchantService.createMerchant(newMerchantDO);
                        merchant.setMerchantId(newMerchantDO.getId());

                        boolean merchantAdded = chr.getClient().getChannelServer().addHiredMerchant(chr.getId(), merchant);
                        if (merchantAdded) {
                            chr.setHiredMerchant(merchant);
                            c.getWorldServer().registerHiredMerchant(merchant);
                            chr.sendPacket(PacketCreator.getHiredMerchant(chr, merchant, true));
                        } else {
                            newMerchantDO.setStatus(HiredMerchantsDO.STATUS_CLOSED);
                            newMerchantDO.setCloseTime(System.currentTimeMillis());
                            hiredMerchantService.updateMerchant(newMerchantDO);
                            chr.dropMessage(1, "无法开设商店，请稍后再试。");
                        }
                    }
                }
            } else if (mode == Action.INVITE.getCode()) {
                int otherCid = p.readInt();
                Character other = chr.getMap().getCharacterById(otherCid);
                if (other == null || chr.getId() == other.getId()) {
                    return;
                }

                Trade.inviteTrade(chr, other);
            } else if (mode == Action.DECLINE.getCode()) {
                Trade.declineTrade(chr);
            } else if (mode == Action.VISIT.getCode()) {
                if (chr.getTrade() != null && chr.getTrade().getPartner() != null) {
                    if (!chr.getTrade().isFullTrade() && !chr.getTrade().getPartner().isFullTrade()) {
                        Trade.visitTrade(chr, chr.getTrade().getPartner().getChr());
                    } else {
                        chr.sendPacket(PacketCreator.getMiniRoomError(2));
                        return;
                    }
                } else {
                    if (isTradeOpen(chr)) {
                        return;
                    }

                    int oid = p.readInt();
                    MapObject ob = chr.getMap().getMapObject(oid);
                    if (ob instanceof PlayerShop shop) {
                        shop.visitShop(chr);
                    } else if (ob instanceof MiniGame game) {
                        p.skip(1);
                        String pw = p.available() > 1 ? p.readString() : "";

                        if (game.checkPassword(pw)) {
                            if (game.hasFreeSlot() && !game.isVisitor(chr)) {
                                game.addVisitor(chr);
                                chr.setMiniGame(game);
                                switch (game.getGameType()) {
                                    case OMOK:
                                        game.sendOmok(c, game.getPieceType());
                                        break;
                                    case MATCH_CARD:
                                        game.sendMatchCard(c, game.getPieceType());
                                        break;
                                }
                            } else {
                                chr.sendPacket(PacketCreator.getMiniRoomError(2));
                            }
                        } else {
                            chr.sendPacket(PacketCreator.getMiniRoomError(22));
                        }
                    } else if (ob instanceof HiredMerchant merchant && chr.getHiredMerchant() == null) {
                        if (!GameConfig.getServerBoolean("hired_merchant_allow_remote", true)) {
                            // 如果不允许远程打开，且玩家不在商店所在地图，则拒绝访问
                            // 注意：这里假设远程访问是通过其他方式触发的，如果是直接点击地图上的商店，则不需要此检查
                            // 但为了安全起见，可以在这里添加检查，或者在 RemoteStoreHandler 中处理
                            // 这里主要处理的是点击地图上的商店，所以通常不需要检查 allow_remote
                            // 但如果是通过某种方式伪造包来访问非当前地图的商店，则需要检查
                            if (chr.getMapId() != merchant.getMapId()) {
                                chr.dropMessage(1, "不允许远程访问商店。");
                                return;
                            }
                        }
                        merchant.visitShop(chr);
                    }
                }
            } else if (mode == Action.CHAT.getCode()) { // chat lol // 聊天
                HiredMerchant merchant = chr.getHiredMerchant();
                if (chr.getTrade() != null) {
                    chr.getTrade().chat(p.readString());
                } else if (chr.getPlayerShop() != null) { //mini game // 迷你游戏
                    PlayerShop shop = chr.getPlayerShop();
                    if (shop != null) {
                        shop.chat(c, p.readString());
                    }
                } else if (chr.getMiniGame() != null) {
                    MiniGame game = chr.getMiniGame();
                    if (game != null) {
                        game.chat(c, p.readString());
                    }
                } else if (merchant != null) {
                    merchant.sendMessage(chr, p.readString());
                }
            } else if (mode == Action.EXIT.getCode()) {
                if (chr.getTrade() != null) {
                    Trade.cancelTrade(chr, Trade.TradeResult.PARTNER_CANCEL);
                } else {
                    chr.closePlayerShop();
                    chr.closeMiniGame(false);
                    chr.closeHiredMerchant(true);
                }
            } else if (mode == Action.OPEN_STORE.getCode() || mode == Action.OPEN_CASH.getCode()) {
                if (isTradeOpen(chr)) {
                    return;
                }

                if (mode == Action.OPEN_STORE.getCode()) {
                    p.readByte();    //01
                } else {
                    p.readShort();
                    int birthday = p.readInt();
                    if (!CashOperationHandler.checkBirthday(c, birthday)) { // birthday check here found thanks to lucasziron //感谢lucasziron，生日验证在这里找到了
                        c.sendPacket(PacketCreator.serverNotice(1, I18nUtil.getMessage("PlayerInteractionHandler.message1")));
                        return;
                    }

                    c.sendPacket(PacketCreator.hiredMerchantOwnerMaintenanceLeave());
                }

                if (!canPlaceStore(chr)) {    // thanks Ari for noticing player shops overlapping on opening time   //感谢阿里注意到玩家商店在开放时间重叠
                    return;
                }

                PlayerShop shop = chr.getPlayerShop();
                HiredMerchant merchant = chr.getHiredMerchant();
                if (shop != null && shop.isOwner(chr)) {
                    if (GameConfig.getServerBoolean("use_erase_permit_on_open_shop")) {
                        try {
                            InventoryManipulator.removeById(c, InventoryType.CASH, shop.getItemId(), 1, true, false);
                        } catch (RuntimeException re) {
                        } // fella does not have a player shop permit... //这家伙没有玩家商店许可证。。。
                    }

                    chr.getMap().broadcastMessage(PacketCreator.updatePlayerShopBox(shop));
                    shop.setOpen(true);
                } else if (merchant != null && merchant.isOwner(chr)) {
                    chr.setHasMerchant(true);
                    merchant.setOpen(true);
                    chr.getMap().addMapObject(merchant);
                    chr.setHiredMerchant(null);
                    chr.getMap().broadcastMessage(PacketCreator.spawnHiredMerchantBox(merchant));
                    
                    // 关键修改：正式开店时，将状态从 PREPARING 更新为 ACTIVE
                    if (merchant.getMerchantId() > 0) {
                        HiredMerchantsDO merchantDO = hiredMerchantService.getMerchantById(merchant.getMerchantId());
                        if (merchantDO != null) {
                            merchantDO.setStatus(HiredMerchantsDO.STATUS_ACTIVE);
                            hiredMerchantService.updateMerchant(merchantDO);
                            
                            // 商店开办成功后，发送通知
                            String merchantItemName = ItemInformationProvider.getInstance().getName(merchant.getItemId());
                            long durationMillis = GameConfig.getServerInt("hired_merchant_duration", 1440) * 60 * 1000L;
                            long endTime = System.currentTimeMillis() + durationMillis;
                            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                            String endTimeStr = sdf.format(new Date(endTime));
                            
                            chr.dropMessage(6, "[雇佣商店] 您的商店开办成功，雇员为 " + merchantItemName + " ，预计最晚到期时间 " + endTimeStr);
                        }
                    }
                }
            } else if (mode == Action.READY.getCode()) {
                MiniGame game = chr.getMiniGame();
                game.broadcast(PacketCreator.getMiniGameReady(game));
            } else if (mode == Action.UN_READY.getCode()) {
                MiniGame game = chr.getMiniGame();
                game.broadcast(PacketCreator.getMiniGameUnReady(game));
            } else if (mode == Action.START.getCode()) {
                MiniGame game = chr.getMiniGame();
                if (game.getGameType().equals(MiniGameType.OMOK)) {
                    game.minigameMatchStarted();
                    game.broadcast(PacketCreator.getMiniGameStart(game, game.getLoser()));
                    chr.getMap().broadcastMessage(PacketCreator.addOmokBox(game.getOwner(), 2, 1));
                } else if (game.getGameType().equals(MiniGameType.MATCH_CARD)) {
                    game.minigameMatchStarted();
                    game.shuffleList();
                    game.broadcast(PacketCreator.getMatchCardStart(game, game.getLoser()));
                    chr.getMap().broadcastMessage(PacketCreator.addMatchCardBox(game.getOwner(), 2, 1));
                }
            } else if (mode == Action.GIVE_UP.getCode()) {
                MiniGame game = chr.getMiniGame();
                if (game.getGameType().equals(MiniGameType.OMOK)) {
                    if (game.isOwner(chr)) {
                        game.minigameMatchVisitorWins(true);
                    } else {
                        game.minigameMatchOwnerWins(true);
                    }
                } else if (game.getGameType().equals(MiniGameType.MATCH_CARD)) {
                    if (game.isOwner(chr)) {
                        game.minigameMatchVisitorWins(true);
                    } else {
                        game.minigameMatchOwnerWins(true);
                    }
                }
            } else if (mode == Action.REQUEST_TIE.getCode()) {
                MiniGame game = chr.getMiniGame();
                if (!game.isTieDenied(chr)) {
                    if (game.isOwner(chr)) {
                        game.broadcastToVisitor(PacketCreator.getMiniGameRequestTie(game));
                    } else {
                        game.broadcastToOwner(PacketCreator.getMiniGameRequestTie(game));
                    }
                }
            } else if (mode == Action.ANSWER_TIE.getCode()) {
                MiniGame game = chr.getMiniGame();
                if (p.readByte() != 0) {
                    game.minigameMatchDraw();
                } else {
                    game.denyTie(chr);

                    if (game.isOwner(chr)) {
                        game.broadcastToVisitor(PacketCreator.getMiniGameDenyTie(game));
                    } else {
                        game.broadcastToOwner(PacketCreator.getMiniGameDenyTie(game));
                    }
                }
            } else if (mode == Action.SKIP.getCode()) {
                MiniGame game = chr.getMiniGame();
                if (game.isOwner(chr)) {
                    game.broadcast(PacketCreator.getMiniGameSkipOwner(game));
                } else {
                    game.broadcast(PacketCreator.getMiniGameSkipVisitor(game));
                }
            } else if (mode == Action.MOVE_OMOK.getCode()) {
                int x = p.readInt(); // x point
                int y = p.readInt(); // y point
                int type = p.readByte(); // piece ( 1 or 2; Owner has one piece, visitor has another, it switches every game.)  //棋子（1或2；所有者有一个棋子，访问者有另一个，它会切换每个游戏。）
                chr.getMiniGame().setPiece(x, y, type, chr);
            } else if (mode == Action.SELECT_CARD.getCode()) {
                int turn = p.readByte(); // 第一轮 = 1; 第二轮 = 0
                int slot = p.readByte(); // 槽位
                MiniGame game = chr.getMiniGame();
                int firstslot = game.getFirstSlot();
                if (turn == 1) {
                    game.setFirstSlot(slot);
                    if (game.isOwner(chr)) {
                        game.broadcastToVisitor(PacketCreator.getMatchCardSelect(game, turn, slot, firstslot, turn));
                    } else {
                        game.getOwner().sendPacket(PacketCreator.getMatchCardSelect(game, turn, slot, firstslot, turn));
                    }
                } else if ((game.getCardId(firstslot)) == (game.getCardId(slot))) {
                    if (game.isOwner(chr)) {
                        game.broadcast(PacketCreator.getMatchCardSelect(game, turn, slot, firstslot, 2));
                        game.setOwnerPoints();
                    } else {
                        game.broadcast(PacketCreator.getMatchCardSelect(game, turn, slot, firstslot, 3));
                        game.setVisitorPoints();
                    }
                } else if (game.isOwner(chr)) {
                    game.broadcast(PacketCreator.getMatchCardSelect(game, turn, slot, firstslot, 0));
                } else {
                    game.broadcast(PacketCreator.getMatchCardSelect(game, turn, slot, firstslot, 1));
                }
            } else if (mode == Action.SET_MESO.getCode()) {
                chr.getTrade().setMeso(p.readInt());
            } else if (mode == Action.SET_ITEMS.getCode()) {
                ItemInformationProvider ii = ItemInformationProvider.getInstance();
                InventoryType ivType = InventoryType.getByType(p.readByte());
                short pos = p.readShort();
                Item item = chr.getInventory(ivType).getItem(pos);
                short quantity = p.readShort();
                byte targetSlot = p.readByte();

                if (targetSlot < 1 || targetSlot > 9) {
                    log.warn(I18nUtil.getLogMessage("PlayerInteractionHandler.warn1"), chr.getName());
                    c.sendPacket(PacketCreator.enableActions());
                    return;
                }

                if (item == null) {
                    c.sendPacket(PacketCreator.serverNotice(1, I18nUtil.getMessage("PlayerInteractionHandler.message2")));
                    c.sendPacket(PacketCreator.enableActions());
                    return;
                }
                //此处判断是否为宠物或者其他现金物品
                if (!GameConfig.getServerBoolean("trade_limit_item_cash") && ii.isUnmerchable(item.getItemId())) {
                    if (ItemConstants.isPet(item.getItemId())) {
                        c.sendPacket(PacketCreator.serverNotice(1, I18nUtil.getMessage("PlayerInteractionHandler.message3")));
                    } else {
                        c.sendPacket(PacketCreator.serverNotice(1, I18nUtil.getMessage("PlayerInteractionHandler.message4")));
                    }
                    log.warn(I18nUtil.getLogMessage("PlayerInteractionHandler.warn2"), chr.getName(),item.getInventoryType().getName(),ItemInformationProvider.getInstance().getName(item.getItemId()),item.getItemId());
                    c.sendPacket(PacketCreator.enableActions());
                    return;
                }

                if (quantity < 1 || quantity > item.getQuantity()) {
                    c.sendPacket(PacketCreator.serverNotice(1, I18nUtil.getMessage("PlayerInteractionHandler.message5")));  //交易物品数量不足
                    c.sendPacket(PacketCreator.enableActions());
                    return;
                }

                Trade trade = chr.getTrade();
                if (trade != null) {
                    if ((quantity <= item.getQuantity() && quantity >= 0) || ItemConstants.isRechargeable(item.getItemId())) {
                        //此处判断不可交易/不可丢弃物品是否允许交易
                        if (!GameConfig.getServerBoolean("trade_limit_item_nodrop") && ii.isDropRestricted(item.getItemId())) { // ensure that undroppable items do not make it to the trade window    //确保不可丢弃的物品不会进入交易窗口
                            if (!KarmaManipulator.hasKarmaFlag(item)) {
                                log.warn(I18nUtil.getLogMessage("PlayerInteractionHandler.warn3"), chr.getName(),item.getInventoryType().getName(),item.getItemId());
                                c.sendPacket(PacketCreator.serverNotice(1, I18nUtil.getMessage("PlayerInteractionHandler.message6")));
                                c.sendPacket(PacketCreator.enableActions());
                                return;
                            }
                        }

                        Inventory inv = chr.getInventory(ivType);
                        inv.lockInventory();
                        try {
                            Item checkItem = chr.getInventory(ivType).getItem(pos);
                            if (checkItem != item || checkItem.getPosition() != item.getPosition()) {
                                c.sendPacket(PacketCreator.serverNotice(1, I18nUtil.getMessage("PlayerInteractionHandler.message2")));
                                c.sendPacket(PacketCreator.enableActions());
                                return;
                            }

                            Item tradeItem = item.copy();
                            if (ItemConstants.isRechargeable(item.getItemId())) {
                                quantity = item.getQuantity();
                            }

                            tradeItem.setQuantity(quantity);
                            tradeItem.setPosition(targetSlot);

                            if (trade.addItem(tradeItem)) {
                                InventoryManipulator.removeFromSlot(c, ivType, item.getPosition(), quantity, true);

                                trade.getChr().sendPacket(PacketCreator.getTradeItemAdd((byte) 0, tradeItem));
                                if (trade.getPartner() != null) {
                                    trade.getPartner().getChr().sendPacket(PacketCreator.getTradeItemAdd((byte) 1, tradeItem));
                                }
                            }
                        } catch (Exception e) {
                            log.warn(I18nUtil.getLogMessage("PlayerInteractionHandler.warn4"), chr, ii.getName(item.getItemId()), item.getQuantity(), targetSlot, e);
                        } finally {
                            inv.unlockInventory();
                        }
                    }
                }
            } else if (mode == Action.CONFIRM.getCode()) {
                Trade.completeTrade(chr);
            } else if (mode == Action.ADD_ITEM.getCode() || mode == Action.PUT_ITEM.getCode()) {
                if (isTradeOpen(chr)) {
                    return;
                }

                InventoryType ivType = InventoryType.getByType(p.readByte());
                short slot = p.readShort();
                short bundles = p.readShort();
                Item ivItem = chr.getInventory(ivType).getItem(slot);

                if (ivItem == null || ivItem.isUntradeable()) {
                    c.sendPacket(PacketCreator.serverNotice(1, I18nUtil.getMessage("PlayerInteractionHandler.message7")));
                    c.sendPacket(PacketCreator.enableActions());
                    return;
                } else if (ItemInformationProvider.getInstance().isUnmerchable(ivItem.getItemId())) {
                    if (ItemConstants.isPet(ivItem.getItemId())) {
                        c.sendPacket(PacketCreator.serverNotice(1, I18nUtil.getMessage("PlayerInteractionHandler.message8")));
                    } else {
                        c.sendPacket(PacketCreator.serverNotice(1, I18nUtil.getMessage("PlayerInteractionHandler.message9")));
                    }

                    c.sendPacket(PacketCreator.enableActions());
                    return;
                }

                short perBundle = p.readShort();

                if (ItemConstants.isRechargeable(ivItem.getItemId())) {
                    perBundle = 1;
                    bundles = 1;
                } else if (ivItem.getQuantity() < (bundles * perBundle)) {     // thanks GabrielSin for finding a dupe here //感谢GabrielSin在这里找到了一个复制漏洞
                    c.sendPacket(PacketCreator.serverNotice(1, I18nUtil.getMessage("PlayerInteractionHandler.message7")));
                    c.sendPacket(PacketCreator.enableActions());
                    return;
                }

                int price = p.readInt();
                short slotMax = ItemInformationProvider.getInstance().getSlotMax(c,ivItem.getItemId());
                
                // 检查价格上限
                long priceLimit = GameConfig.getServerLong("hired_merchant_price_limit", 2147483647L);
                if (price > priceLimit) {
                    c.getPlayer().dropMessage(1, "物品价格超过上限。");
                    c.sendPacket(PacketCreator.enableActions());
                    return;
                }

                if (perBundle <= 0 || perBundle * bundles > slotMax || bundles <= 0 || price <= 0 || price > Integer.MAX_VALUE) {
                    AutobanFactory.PACKET_EDIT.alert(chr, chr.getName() + I18nUtil.getMessage("PlayerInteractionHandler.message10"));
                    log.warn(I18nUtil.getLogMessage("PlayerInteractionHandler.warn5"),
                            chr.getName(), perBundle, slotMax,perBundle * bundles, bundles, price);
                    return;
                }

                Item sellItem = ivItem.copy();
                if (!ItemConstants.isRechargeable(ivItem.getItemId())) {
                    sellItem.setQuantity(perBundle);
                }
                
                // ----------------------------------------------------------------
                // 关键修改：UID 处理逻辑
                // ----------------------------------------------------------------
                if (ItemConstants.isEquipment(ivItem.getItemId())) {
                    // 装备：必须保留原 UID，确保溯源链完整
                    sellItem.setUid(ivItem.getUid());
                } else {
                    // 堆叠物品：
                    // 1. 如果是部分上架（拆分），必须生成新 UID，因为这是新的实体
                    // 2. 如果是全部上架，理论上可以保留原 UID，但为了简化逻辑且避免潜在的并发问题，
                    //    对于堆叠物品，我们统一生成新 UID。
                    //    注意：如果商店里已有同类物品，HiredMerchant.addItem 会处理合并逻辑，
                    //    届时这个新生成的 UID 会被丢弃，保留商店内原有物品的 UID。
                    sellItem.setUid(SnowflakeIdGenerator.getInstance().nextId());
                }

                PlayerShopItem shopItem = new PlayerShopItem(sellItem, bundles, price);
                PlayerShop shop = chr.getPlayerShop();
                HiredMerchant merchant = chr.getHiredMerchant();
                if (shop != null && shop.isOwner(chr)) {
                    if (shop.isOpen() || !shop.addItem(shopItem,ivItem)) { // thanks Vcoc for pointing an exploit with unlimited shop slots    //感谢Vcoc指出了一个具有无限商店插槽的漏洞
                        c.sendPacket(PacketCreator.serverNotice(1, I18nUtil.getMessage("PlayerInteractionHandler.message11")));
                        c.getPlayer().enableActions();
                        return;
                    }

                    short quantity = ItemConstants.isRechargeable(ivItem.getItemId()) ? ivItem.getQuantity() : (short) (bundles * perBundle);
                    InventoryManipulator.removeFromSlot(c, ivType, slot, quantity, true);
                    c.sendPacket(PacketCreator.getPlayerShopItemUpdate(shop));
                } else if (merchant != null && merchant.isOwner(chr)) {
                    if (ivType.equals(InventoryType.CASH) && merchant.isPublished()) {
                        c.sendPacket(PacketCreator.serverNotice(1, I18nUtil.getMessage("PlayerInteractionHandler.message12")));
                        c.getPlayer().enableActions();
                        return;
                    }

                    // 尝试添加到商店（包括数据库操作）
                    if (merchant.isOpen() || !merchant.addItem(shopItem,ivItem)) {
                        c.sendPacket(PacketCreator.serverNotice(1, I18nUtil.getMessage("PlayerInteractionHandler.message11")));
                        c.getPlayer().enableActions();
                        return;
                    }

                    // 只有在 addItem 成功后，才从背包移除物品
                    if (ItemConstants.isRechargeable(ivItem.getItemId())) {
                        InventoryManipulator.removeFromSlot(c, ivType, slot, ivItem.getQuantity(), true);
                    } else {
                        InventoryManipulator.removeFromSlot(c, ivType, slot, (short) (bundles * perBundle), true);
                    }

                    c.sendPacket(PacketCreator.updateHiredMerchant(merchant, chr));

                    if (GameConfig.getServerBoolean("use_enforce_merchant_save")) {
                        chr.saveCharToDB(false);
                    }

                    try {
                        merchant.saveItems(false);   // thanks Masterrulax for realizing yet another dupe with merchants/Fredrick   //感谢Masterrulax再次发现商家/弗雷德里克的复制漏洞
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                } else {
                    c.sendPacket(PacketCreator.serverNotice(1, I18nUtil.getMessage("PlayerInteractionHandler.message13")));
                }
            } else if (mode == Action.REMOVE_ITEM.getCode()) {
                if (isTradeOpen(chr)) {
                    return;
                }

                PlayerShop shop = chr.getPlayerShop();
                if (shop != null && shop.isOwner(chr)) {
                    if (shop.isOpen()) {
                        c.sendPacket(PacketCreator.serverNotice(1, I18nUtil.getMessage("PlayerInteractionHandler.message14")));
                        c.getPlayer().enableActions();
                        return;
                    }

                    int slot = p.readShort();
                    if (slot >= shop.getItems().size() || slot < 0) {
                        AutobanFactory.PACKET_EDIT.alert(chr, chr.getName() + I18nUtil.getMessage("PlayerInteractionHandler.message15"));
                        log.warn(I18nUtil.getLogMessage("PlayerInteractionHandler.warn6"), chr.getName(), slot);
                        c.disconnect(true, false);
                        return;
                    }

                    shop.takeItemBack(slot, chr);
                }
            } else if (mode == Action.MERCHANT_MESO.getCode()) {
                HiredMerchant merchant = chr.getHiredMerchant();
                if (merchant == null) {
                    return;
                }

                merchant.withdrawMesos(chr);

            } else if (mode == Action.VIEW_VISITORS.getCode()) {
                HiredMerchant merchant = chr.getHiredMerchant();
                if (merchant == null || !merchant.isOwner(chr)) {
                    return;
                }
                c.sendPacket(PacketCreator.viewMerchantVisitorHistory(merchant.getVisitorHistory()));
            } else if (mode == Action.VIEW_BLACKLIST.getCode()) {
                HiredMerchant merchant = chr.getHiredMerchant();
                if (merchant == null || !merchant.isOwner(chr)) {
                    return;
                }

                c.sendPacket(PacketCreator.viewMerchantBlacklist(merchant.getBlacklist()));
            } else if (mode == Action.ADD_TO_BLACKLIST.getCode()) {
                HiredMerchant merchant = chr.getHiredMerchant();
                if (merchant == null || !merchant.isOwner(chr)) {
                    return;
                }
                String chrName = p.readString();
                merchant.addToBlacklist(chrName);
            } else if (mode == Action.REMOVE_FROM_BLACKLIST.getCode()) {
                HiredMerchant merchant = chr.getHiredMerchant();
                if (merchant == null || !merchant.isOwner(chr)) {
                    return;
                }
                String chrName = p.readString();
                merchant.removeFromBlacklist(chrName);
            } else if (mode == Action.MERCHANT_ORGANIZE.getCode()) {
                HiredMerchant merchant = chr.getHiredMerchant();
                if (merchant == null || !merchant.isOwner(chr)) {
                    return;
                }

                merchant.withdrawMesos(chr);
                merchant.clearInexistentItems();

                if (merchant.getItems().isEmpty()) {
                    merchant.closeOwnerMerchant(chr);
                    return;
                }
                c.sendPacket(PacketCreator.updateHiredMerchant(merchant, chr));

            } else if (mode == Action.BUY.getCode() || mode == Action.MERCHANT_BUY.getCode()) {
                if (isTradeOpen(chr)) {
                    return;
                }

                int itemid = p.readByte();
                short quantity = p.readShort();
                if (quantity < 1) {
                    AutobanFactory.PACKET_EDIT.alert(chr, chr.getName() + I18nUtil.getMessage("PlayerInteractionHandler.message16"));
                    log.warn(I18nUtil.getLogMessage("PlayerInteractionHandler.warn7"), chr.getName(), itemid, quantity);
                    c.disconnect(true, false);
                    return;
                }
                PlayerShop shop = chr.getPlayerShop();
                HiredMerchant merchant = chr.getHiredMerchant();
                if (shop != null && shop.isVisitor(chr)) {
                    if (shop.buy(c, itemid, quantity)) {
                        shop.broadcast(PacketCreator.getPlayerShopItemUpdate(shop));
                    }
                } else if (merchant != null && !merchant.isOwner(chr)) {
                    merchant.buy(c, itemid, quantity);
                    merchant.broadcastToVisitorsThreadsafe(PacketCreator.updateHiredMerchant(merchant, chr));
                }
            } else if (mode == Action.TAKE_ITEM_BACK.getCode()) {
                if (isTradeOpen(chr)) {
                    return;
                }

                HiredMerchant merchant = chr.getHiredMerchant();
                if (merchant != null && merchant.isOwner(chr)) {
                    if (merchant.isOpen()) {
                        c.sendPacket(PacketCreator.serverNotice(1, I18nUtil.getMessage("PlayerInteractionHandler.message14")));
                        return;
                    }

                    int slot = p.readShort();
                    if (slot >= merchant.getItems().size() || slot < 0) {
                        AutobanFactory.PACKET_EDIT.alert(chr, chr.getName() + I18nUtil.getMessage("PlayerInteractionHandler.message17"));
                        log.warn(I18nUtil.getLogMessage("PlayerInteractionHandler.warn6", chr.getName(), slot));
                        c.disconnect(true, false);
                        return;
                    }

                    merchant.takeItemBack(slot, chr);
                }
            } else if (mode == Action.CLOSE_MERCHANT.getCode()) {
                if (isTradeOpen(chr)) {
                    return;
                }

                HiredMerchant merchant = chr.getHiredMerchant();
                if (merchant != null) {
                    merchant.closeOwnerMerchant(chr);
                }
            } else if (mode == Action.MAINTENANCE_OFF.getCode()) {
                if (isTradeOpen(chr)) {
                    return;
                }

                HiredMerchant merchant = chr.getHiredMerchant();
                if (merchant != null) {
                    if (merchant.isOwner(chr)) {
                        if (merchant.getItems().isEmpty()) {
                            merchant.closeOwnerMerchant(chr);
                        } else {
                            merchant.clearMessages();
                            merchant.setOpen(true);
                            merchant.getMap().broadcastMessage(PacketCreator.updateHiredMerchantBox(merchant));
                        }
                    }
                }

                chr.setHiredMerchant(null);
                c.sendPacket(PacketCreator.enableActions());
            } else if (mode == Action.BAN_PLAYER.getCode()) {
                p.skip(1);

                PlayerShop shop = chr.getPlayerShop();
                if (shop != null && shop.isOwner(chr)) {
                    shop.banPlayer(p.readString());
                }
            } else if (mode == Action.EXPEL.getCode()) {
                MiniGame miniGame = chr.getMiniGame();
                if (miniGame != null && miniGame.isOwner(chr)) {
                    Character visitor = miniGame.getVisitor();

                    if (visitor != null) {
                        visitor.closeMiniGame(false);
                        visitor.sendPacket(PacketCreator.getMiniGameClose(true, 5));
                    }
                }
            } else if (mode == Action.EXIT_AFTER_GAME.getCode()) {
                MiniGame miniGame = chr.getMiniGame();
                if (miniGame != null) {
                    miniGame.setQuitAfterGame(chr, true);
                }
            } else if (mode == Action.CANCEL_EXIT_AFTER_GAME.getCode()) {
                MiniGame miniGame = chr.getMiniGame();
                if (miniGame != null) {
                    miniGame.setQuitAfterGame(chr, false);
                }
            }
        } finally {
            c.releaseClient();
        }
    }

    private static boolean isTradeOpen(Character chr) {
        if (chr.getTrade() != null) {   // thanks to Rien dev team  //感谢Rien开发团队
            //Apparently there is a dupe exploit that causes racing conditions when saving/retrieving from the db with stuff like trade open.
            //显然，在使用诸如trade open之类的东西从数据库中保存/检索时，有一个复制漏洞会导致竞争条件。
            chr.sendPacket(PacketCreator.enableActions());
            return true;
        }

        return false;
    }

    private static boolean canPlaceStore(Character chr) {
        try {
            for (MapObject mmo : chr.getMap().getMapObjectsInRange(chr.getPosition(), 23000, Arrays.asList(MapObjectType.HIRED_MERCHANT, MapObjectType.PLAYER))) {
                if (mmo instanceof Character mc) {
                    if (mc.getId() == chr.getId()) {
                        continue;
                    }

                    PlayerShop shop = mc.getPlayerShop();
                    if (shop != null && shop.isOwner(mc)) {
                        chr.sendPacket(PacketCreator.getMiniRoomError(13));
                        return false;
                    }
                } else if (mmo instanceof HiredMerchant hm) {
                    // 新增：如果是玩家自己的商店，则忽略
                    if (hm.getOwnerId() == chr.getId()) {
                        continue;
                    }

                    chr.sendPacket(PacketCreator.getMiniRoomError(13));
                    return false;
                } else {
                    chr.sendPacket(PacketCreator.getMiniRoomError(13));
                    return false;
                }
            }

            Point cpos = chr.getPosition();
            Portal portal = chr.getMap().findClosestTeleportPortal(cpos);
            if (portal != null && portal.getPosition().distance(cpos) < 120.0) {
                chr.sendPacket(PacketCreator.getMiniRoomError(10));
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return true;
    }
}
