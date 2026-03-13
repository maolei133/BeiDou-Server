package org.gms.util.packets;

import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.dao.entity.HiredMerchantItemsDO;
import org.gms.dao.entity.HiredMerchantsDO;
import org.gms.manager.ServerManager;
import org.gms.net.opcodes.SendOpcode;
import org.gms.net.packet.OutPacket;
import org.gms.net.packet.Packet;
import org.gms.net.server.channel.handlers.PlayerInteractionHandler;
import org.gms.server.ItemInformationProvider;
import org.gms.server.maps.AbstractMapObject;
import org.gms.server.maps.HiredMerchant;
import org.gms.server.maps.MiniGame;
import org.gms.server.maps.MiniGame.MiniGameResult;
import org.gms.server.maps.PlayerShop;
import org.gms.server.maps.PlayerShopItem;
import org.gms.service.HiredMerchantService;
import org.gms.util.Pair;
import org.gms.constants.id.NpcId;
import org.gms.constants.inventory.ItemConstants;
import org.gms.client.inventory.ItemFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * MiniGamePackets
 * 处理小游戏、雇佣商人、玩家商店、RPS、猫头鹰等相关的数据包构建
 */
public class MiniGamePackets {

    /**
     * 获取小游戏包
     *
     * @param c        客户端对象
     * @param minigame 小游戏对象
     * @param owner    是否是房主
     * @param piece    棋子类型
     * @return 小游戏包
     */
    public static Packet getMiniGame(Client c, MiniGame minigame, boolean owner, int piece) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.ROOM.getCode());
        p.writeByte(1);
        p.writeByte(0);
        p.writeBool(!owner);
        p.writeByte(0);
        PacketHelper.addCharLook(p, minigame.getOwner(), false);
        p.writeString(minigame.getOwner().getName());
        if (minigame.getVisitor() != null) {
            Character visitor = minigame.getVisitor();
            p.writeByte(1);
            PacketHelper.addCharLook(p, visitor, false);
            p.writeString(visitor.getName());
        }
        p.writeByte(0xFF);
        p.writeByte(0);
        p.writeInt(1);
        p.writeInt(minigame.getOwner().getMiniGamePoints(MiniGameResult.WIN, true));
        p.writeInt(minigame.getOwner().getMiniGamePoints(MiniGameResult.TIE, true));
        p.writeInt(minigame.getOwner().getMiniGamePoints(MiniGameResult.LOSS, true));
        p.writeInt(minigame.getOwnerScore());
        if (minigame.getVisitor() != null) {
            Character visitor = minigame.getVisitor();
            p.writeByte(1);
            p.writeInt(1);
            p.writeInt(visitor.getMiniGamePoints(MiniGameResult.WIN, true));
            p.writeInt(visitor.getMiniGamePoints(MiniGameResult.TIE, true));
            p.writeInt(visitor.getMiniGamePoints(MiniGameResult.LOSS, true));
            p.writeInt(minigame.getVisitorScore());
        }
        p.writeByte(0xFF);
        p.writeString(minigame.getDescription());
        p.writeByte(piece);
        p.writeByte(0);
        return p;
    }

    /**
     * 获取小游戏准备包
     *
     * @param game 小游戏对象
     * @return 小游戏准备包
     */
    public static Packet getMiniGameReady(MiniGame game) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.READY.getCode());
        return p;
    }

    /**
     * 获取小游戏取消准备包
     *
     * @param game 小游戏对象
     * @return 小游戏取消准备包
     */
    public static Packet getMiniGameUnReady(MiniGame game) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.UN_READY.getCode());
        return p;
    }

    /**
     * 获取小游戏开始包
     *
     * @param game  小游戏对象
     * @param loser 输家
     * @return 小游戏开始包
     */
    public static Packet getMiniGameStart(MiniGame game, int loser) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.START.getCode());
        p.writeByte(loser);
        return p;
    }

    /**
     * 获取小游戏房主跳过包
     *
     * @param game 小游戏对象
     * @return 小游戏房主跳过包
     */
    public static Packet getMiniGameSkipOwner(MiniGame game) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.SKIP.getCode());
        p.writeByte(0x01);
        return p;
    }

    /**
     * 获取小游戏访客跳过包
     *
     * @param game 小游戏对象
     * @return 小游戏访客跳过包
     */
    public static Packet getMiniGameSkipVisitor(MiniGame game) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeShort(PlayerInteractionHandler.Action.SKIP.getCode());
        return p;
    }

    /**
     * 获取小游戏请求平局包
     *
     * @param game 小游戏对象
     * @return 小游戏请求平局包
     */
    public static Packet getMiniGameRequestTie(MiniGame game) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.REQUEST_TIE.getCode());
        return p;
    }

    /**
     * 获取小游戏拒绝平局包
     *
     * @param game 小游戏对象
     * @return 小游戏拒绝平局包
     */
    public static Packet getMiniGameDenyTie(MiniGame game) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.ANSWER_TIE.getCode());
        return p;
    }

    /**
     * 获取小游戏移动五子棋包
     *
     * @param game  小游戏对象
     * @param move1 移动坐标1
     * @param move2 移动坐标2
     * @param move3 移动坐标3
     * @return 小游戏移动五子棋包
     */
    public static Packet getMiniGameMoveOmok(MiniGame game, int move1, int move2, int move3) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.MOVE_OMOK.getCode());
        p.writeInt(move1);
        p.writeInt(move2);
        p.writeByte(move3);
        return p;
    }

    /**
     * 获取小游戏新访客包
     *
     * @param minigame 小游戏对象
     * @param chr      角色对象
     * @param slot     槽位
     * @return 小游戏新访客包
     */
    public static Packet getMiniGameNewVisitor(MiniGame minigame, Character chr, int slot) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.VISIT.getCode());
        p.writeByte(slot);
        PacketHelper.addCharLook(p, chr, false);
        p.writeString(chr.getName());
        p.writeInt(1);
        p.writeInt(chr.getMiniGamePoints(MiniGameResult.WIN, true));
        p.writeInt(chr.getMiniGamePoints(MiniGameResult.TIE, true));
        p.writeInt(chr.getMiniGamePoints(MiniGameResult.LOSS, true));
        p.writeInt(minigame.getVisitorScore());
        return p;
    }

    /**
     * 获取小游戏移除访客包
     *
     * @return 小游戏移除访客包
     */
    public static Packet getMiniGameRemoveVisitor() {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.EXIT.getCode());
        p.writeByte(1);
        return p;
    }

    /**
     * 获取小游戏房主胜利包
     *
     * @param game    小游戏对象
     * @param forfeit 是否弃权
     * @return 小游戏房主胜利包
     */
    public static Packet getMiniGameOwnerWin(MiniGame game, boolean forfeit) {
        return getMiniGameResult(game, 0, 1, forfeit ? 1 : 0);
    }

    /**
     * 获取小游戏访客胜利包
     *
     * @param game    小游戏对象
     * @param forfeit 是否弃权
     * @return 小游戏访客胜利包
     */
    public static Packet getMiniGameVisitorWin(MiniGame game, boolean forfeit) {
        return getMiniGameResult(game, 0, 2, forfeit ? 1 : 0);
    }

    /**
     * 获取小游戏平局包
     *
     * @param game 小游戏对象
     * @return 小游戏平局包
     */
    public static Packet getMiniGameTie(MiniGame game) {
        return getMiniGameResult(game, 1, 3, 0);
    }

    /**
     * 获取小游戏结果包
     *
     * @param game    小游戏对象
     * @param tie     是否平局
     * @param result  结果
     * @param forfeit 是否弃权
     * @return 小游戏结果包
     */
    private static Packet getMiniGameResult(MiniGame game, int tie, int result, int forfeit) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.GET_RESULT.getCode());

        int matchResultType;
        if (tie == 0 && forfeit != 1) {
            matchResultType = 0;
        } else if (tie != 0) {
            matchResultType = 1;
        } else {
            matchResultType = 2;
        }

        p.writeByte(matchResultType);
        p.writeBool(result == 2); // host/visitor wins

        boolean omok = game.isOmok();
        if (matchResultType == 1) {
            p.writeByte(0);
            p.writeShort(0);
            p.writeInt(game.getOwner().getMiniGamePoints(MiniGameResult.WIN, omok)); // wins
            p.writeInt(game.getOwner().getMiniGamePoints(MiniGameResult.TIE, omok)); // ties
            p.writeInt(game.getOwner().getMiniGamePoints(MiniGameResult.LOSS, omok)); // losses
            p.writeInt(game.getOwnerScore()); // points

            p.writeInt(0); // unknown
            p.writeInt(game.getVisitor().getMiniGamePoints(MiniGameResult.WIN, omok)); // wins
            p.writeInt(game.getVisitor().getMiniGamePoints(MiniGameResult.TIE, omok)); // ties
            p.writeInt(game.getVisitor().getMiniGamePoints(MiniGameResult.LOSS, omok)); // losses
            p.writeInt(game.getVisitorScore()); // points
            p.writeByte(0);
        } else {
            p.writeInt(0);
            p.writeInt(game.getOwner().getMiniGamePoints(MiniGameResult.WIN, omok)); // wins
            p.writeInt(game.getOwner().getMiniGamePoints(MiniGameResult.TIE, omok)); // ties
            p.writeInt(game.getOwner().getMiniGamePoints(MiniGameResult.LOSS, omok)); // losses
            p.writeInt(game.getOwnerScore()); // points
            p.writeInt(0);
            p.writeInt(game.getVisitor().getMiniGamePoints(MiniGameResult.WIN, omok)); // wins
            p.writeInt(game.getVisitor().getMiniGamePoints(MiniGameResult.TIE, omok)); // ties
            p.writeInt(game.getVisitor().getMiniGamePoints(MiniGameResult.LOSS, omok)); // losses
            p.writeInt(game.getVisitorScore()); // points
        }

        return p;
    }

    /**
     * 获取小游戏关闭包
     *
     * @param visitor 是否是访客
     * @param type    类型
     * @return 小游戏关闭包
     */
    public static Packet getMiniGameClose(boolean visitor, int type) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.EXIT.getCode());
        p.writeBool(visitor);
        p.writeByte(type); /* 2 : CRASH 3 : The room has been closed 4 : You have left the room 5 : You have been expelled  */
        return p;
    }

    /**
     * 获取配对卡包
     *
     * @param c        客户端对象
     * @param minigame 小游戏对象
     * @param owner    是否是房主
     * @param piece    棋子类型
     * @return 配对卡包
     */
    public static Packet getMatchCard(Client c, MiniGame minigame, boolean owner, int piece) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.ROOM.getCode());
        p.writeByte(2);
        p.writeByte(2);
        p.writeBool(!owner);
        p.writeByte(0);
        PacketHelper.addCharLook(p, minigame.getOwner(), false);
        p.writeString(minigame.getOwner().getName());
        if (minigame.getVisitor() != null) {
            Character visitor = minigame.getVisitor();
            p.writeByte(1);
            PacketHelper.addCharLook(p, visitor, false);
            p.writeString(visitor.getName());
        }
        p.writeByte(0xFF);
        p.writeByte(0);
        p.writeInt(2);
        p.writeInt(minigame.getOwner().getMiniGamePoints(MiniGameResult.WIN, false));
        p.writeInt(minigame.getOwner().getMiniGamePoints(MiniGameResult.TIE, false));
        p.writeInt(minigame.getOwner().getMiniGamePoints(MiniGameResult.LOSS, false));

        //set vs
        p.writeInt(minigame.getOwnerScore());
        if (minigame.getVisitor() != null) {
            Character visitor = minigame.getVisitor();
            p.writeByte(1);
            p.writeInt(2);
            p.writeInt(visitor.getMiniGamePoints(MiniGameResult.WIN, false));
            p.writeInt(visitor.getMiniGamePoints(MiniGameResult.TIE, false));
            p.writeInt(visitor.getMiniGamePoints(MiniGameResult.LOSS, false));
            p.writeInt(minigame.getVisitorScore());
        }
        p.writeByte(0xFF);
        p.writeString(minigame.getDescription());
        p.writeByte(piece);
        p.writeByte(0);
        return p;
    }

    /**
     * 获取配对卡开始包
     *
     * @param game  小游戏对象
     * @param loser 输家
     * @return 配对卡开始包
     */
    public static Packet getMatchCardStart(MiniGame game, int loser) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.START.getCode());
        p.writeByte(loser);

        int last;
        if (game.getMatchesToWin() > 10) {
            last = 30;
        } else if (game.getMatchesToWin() > 6) {
            last = 20;
        } else {
            last = 12;
        }

        p.writeByte(last);
        for (int i = 0; i < last; i++) {
            p.writeInt(game.getCardId(i));
        }
        return p;
    }

    /**
     * 获取配对卡新访客包
     *
     * @param minigame 小游戏对象
     * @param chr      角色对象
     * @param slot     槽位
     * @return 配对卡新访客包
     */
    public static Packet getMatchCardNewVisitor(MiniGame minigame, Character chr, int slot) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.VISIT.getCode());
        p.writeByte(slot);
        PacketHelper.addCharLook(p, chr, false);
        p.writeString(chr.getName());
        p.writeInt(1);
        p.writeInt(chr.getMiniGamePoints(MiniGameResult.WIN, false));
        p.writeInt(chr.getMiniGamePoints(MiniGameResult.TIE, false));
        p.writeInt(chr.getMiniGamePoints(MiniGameResult.LOSS, false));
        p.writeInt(minigame.getVisitorScore());
        return p;
    }

    /**
     * 获取配对卡选择包
     *
     * @param game      小游戏对象
     * @param turn      回合
     * @param slot      槽位
     * @param firstslot 第一张卡槽位
     * @param type      类型
     * @return 配对卡选择包
     */
    public static Packet getMatchCardSelect(MiniGame game, int turn, int slot, int firstslot, int type) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.SELECT_CARD.getCode());
        p.writeByte(turn);
        if (turn == 1) {
            p.writeByte(slot);
        } else if (turn == 0) {
            p.writeByte(slot);
            p.writeByte(firstslot);
            p.writeByte(type);
        }
        return p;
    }

    /**
     * 获取迷你房间错误包
     * 1 = Room already closed  2 = Can't enter due full cappacity 3 = Other requests at this minute
     * 4 = Can't do while dead 5 = Can't do while middle event 6 = This character unable to do it
     * 7, 20 = Not allowed to trade anymore 9 = Can only trade on same map 10 = May not open store near portal
     * 11, 14 = Can't start game here 12 = Can't open store at this channel 13 = Can't estabilish miniroom
     * 15 = Stores only an the free market 16 = Lists the rooms at FM (?) 17 = You may not enter this store
     * 18 = Owner undergoing store maintenance 19 = Unable to enter tournament room 21 = Not enough mesos to enter
     * 22 = Incorrect password
     * 1 = 房间已关闭 2 = 房间已满无法进入 3 = 此刻有其他请求
     * 4 = 死亡状态无法操作 5 = 活动进行中无法操作 6 = 此角色无法操作
     * 7, 20 = 不允许再交易 9 = 只能在同一地图交易 10 = 不能在传送门附近开店
     * 11, 14 = 无法在此处开始游戏 12 = 无法在此频道开店 13 = 无法建立迷你房间
     * 15 = 商店只能在自由市场 16 = 列出自由市场的房间 (?) 17 = 您不能进入此商店
     * 18 = 店主正在进行商店维护 19 = 无法进入锦标赛房间 21 = 金币不足无法进入
     * 22 = 密码错误
     *
     * @param status 状态码
     * @return 迷你房间错误包
     */
    public static Packet getMiniRoomError(int status) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.ROOM.getCode());
        p.writeByte(0);
        p.writeByte(status);
        return p;
    }

    /**
     * 添加五子棋盒包
     *
     * @param chr    角色对象
     * @param amount 数量
     * @param type   类型
     * @return 添加五子棋盒包
     */
    public static Packet addOmokBox(Character chr, int amount, int type) {
        OutPacket p = OutPacket.create(SendOpcode.UPDATE_CHAR_BOX);
        p.writeInt(chr.getId());
        PacketHelper.addAnnounceBox(p, chr.getMiniGame(), amount, type);
        return p;
    }

    /**
     * 添加配对卡盒包
     *
     * @param chr    角色对象
     * @param amount 数量
     * @param type   类型
     * @return 添加配对卡盒包
     */
    public static Packet addMatchCardBox(Character chr, int amount, int type) {
        OutPacket p = OutPacket.create(SendOpcode.UPDATE_CHAR_BOX);
        p.writeInt(chr.getId());
        PacketHelper.addAnnounceBox(p, chr.getMiniGame(), amount, type);
        return p;
    }

    /**
     * 移除小游戏盒包
     *
     * @param chr 角色对象
     * @return 移除小游戏盒包
     */
    public static Packet removeMinigameBox(Character chr) {
        OutPacket p = OutPacket.create(SendOpcode.UPDATE_CHAR_BOX);
        p.writeInt(chr.getId());
        p.writeByte(0);
        return p;
    }

    /**
     * 获取玩家商店包
     *
     * @param shop  玩家商店对象
     * @param owner 是否是店主
     * @return 玩家商店包
     */
    public static Packet getPlayerShop(PlayerShop shop, boolean owner) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.ROOM.getCode());
        p.writeByte(4);
        p.writeByte(4);
        p.writeByte(owner ? 0 : 1);

        if (owner) {
            List<PlayerShop.SoldItem> sold = shop.getSold();
            p.writeByte(sold.size());
            for (PlayerShop.SoldItem s : sold) {
                p.writeInt(s.getItemId());
                p.writeShort(s.getQuantity());
                p.writeInt(s.getMesos());
                p.writeString(s.getBuyer());
            }
        } else {
            p.writeByte(0);
        }

        PacketHelper.addCharLook(p, shop.getOwner(), false);
        p.writeString(shop.getOwner().getName());

        Character[] visitors = shop.getVisitors();
        for (int i = 0; i < 3; i++) {
            Character visitor = visitors[i];
            if (visitor != null) {
                if (visitor.getClient().getChannel() == shop.getChannel() && visitor.getMapId() == shop.getMapId()) {
                    p.writeByte(i + 1);
                    PacketHelper.addCharLook(p, visitor, false);
                    p.writeString(visitor.getName());
                } else {
                    shop.removeVisitor(visitor);
                }
            }
        }

        p.writeByte(0xFF);
        p.writeString(shop.getDescription());
        List<PlayerShopItem> items = shop.getItems();
        p.writeByte(0x10);
        p.writeByte(items.size());
        for (PlayerShopItem item : items) {
            p.writeShort(item.getBundles());
            p.writeShort(item.getItem().getQuantity());
            p.writeInt(item.getPrice());
            PacketHelper.addItemInfo(p, item.getItem(), true);
        }
        return p;
    }

    /**
     * 获取玩家商店聊天包
     *
     * @param chr   角色对象
     * @param chat  聊天内容
     * @param owner 是否是店主
     * @return 玩家商店聊天包
     */
    public static Packet getPlayerShopChat(Character chr, String chat, boolean owner) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.CHAT.getCode());
        p.writeByte(PlayerInteractionHandler.Action.CHAT_THING.getCode());
        p.writeBool(!owner);
        p.writeString(chr.getName() + " : " + chat);
        return p;
    }

    /**
     * 获取玩家商店聊天包（带槽位）
     *
     * @param chr  角色对象
     * @param chat 聊天内容
     * @param slot 槽位
     * @return 玩家商店聊天包
     */
    public static Packet getPlayerShopChat(Character chr, String chat, byte slot) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.CHAT.getCode());
        p.writeByte(PlayerInteractionHandler.Action.CHAT_THING.getCode());
        p.writeByte(slot);
        p.writeString(chr.getName() + " : " + chat);
        return p;
    }

    /**
     * 获取玩家商店新访客包
     *
     * @param chr  角色对象
     * @param slot 槽位
     * @return 玩家商店新访客包
     */
    public static Packet getPlayerShopNewVisitor(Character chr, int slot) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.VISIT.getCode());
        p.writeByte(slot);
        PacketHelper.addCharLook(p, chr, false);
        p.writeString(chr.getName());
        return p;
    }

    /**
     * 获取玩家商店移除访客包
     *
     * @param slot 槽位
     * @return 玩家商店移除访客包
     */
    public static Packet getPlayerShopRemoveVisitor(int slot) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.EXIT.getCode());
        if (slot != 0) {
            p.writeShort(slot);
        }
        return p;
    }

    /**
     * 获取玩家商店物品更新包
     *
     * @param shop 玩家商店对象
     * @return 玩家商店物品更新包
     */
    public static Packet getPlayerShopItemUpdate(PlayerShop shop) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.UPDATE_MERCHANT.getCode());
        p.writeByte(shop.getItems().size());
        for (PlayerShopItem item : shop.getItems()) {
            p.writeShort(item.getBundles());
            p.writeShort(item.getItem().getQuantity());
            p.writeInt(item.getPrice());
            PacketHelper.addItemInfo(p, item.getItem(), true);
        }
        return p;
    }

    /**
     * 获取玩家商店店主更新包
     *
     * @param item     售出物品
     * @param position 位置
     * @return 玩家商店店主更新包
     */
    public static Packet getPlayerShopOwnerUpdate(PlayerShop.SoldItem item, int position) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.UPDATE_PLAYERSHOP.getCode());
        p.writeByte(position);
        p.writeShort(item.getQuantity());
        p.writeString(item.getBuyer());

        return p;
    }

    /**
     * 更新玩家商店盒包
     *
     * @param shop 玩家商店对象
     * @return 更新玩家商店盒包
     */
    public static Packet updatePlayerShopBox(PlayerShop shop) {
        final OutPacket p = OutPacket.create(SendOpcode.UPDATE_CHAR_BOX);
        p.writeInt(shop.getOwner().getId());
        PacketHelper.updatePlayerShopBoxInfo(p, shop);
        return p;
    }

    /**
     * 移除玩家商店盒包
     *
     * @param shop 玩家商店对象
     * @return 移除玩家商店盒包
     */
    public static Packet removePlayerShopBox(PlayerShop shop) {
        OutPacket p = OutPacket.create(SendOpcode.UPDATE_CHAR_BOX);
        p.writeInt(shop.getOwner().getId());
        p.writeByte(0);
        return p;
    }

    /**
     * 获取交易开始包
     *
     * @param c      客户端对象
     * @param trade  交易对象
     * @param number 编号
     * @return 交易开始包
     */
    public static Packet getTradeStart(Client c, org.gms.server.Trade trade, byte number) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.ROOM.getCode());
        p.writeByte(3);
        p.writeByte(2);
        p.writeByte(number);
        if (number == 1) {
            p.writeByte(0);
            PacketHelper.addCharLook(p, trade.getPartner().getChr(), false);
            p.writeString(trade.getPartner().getChr().getName());
        }
        p.writeByte(number);
        PacketHelper.addCharLook(p, c.getPlayer(), false);
        p.writeString(c.getPlayer().getName());
        p.writeByte(0xFF);
        return p;
    }

    /**
     * 获取交易确认包
     *
     * @return 交易确认包
     */
    public static Packet getTradeConfirmation() {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.CONFIRM.getCode());
        return p;
    }

    /**
     * 获取交易结果包
     * Possible values for <code>operation</code>:<br> 2: Trade cancelled, by the
     * other character<br> 7: Trade successful<br> 8: Trade unsuccessful<br>
     * 9: Cannot carry more one-of-a-kind items<br> 12: Cannot trade on different maps<br>
     * 13: Cannot trade, game files damaged<br>
     * operation 可能的值:<br> 2: 交易被对方取消<br> 7: 交易成功<br> 8: 交易失败<br>
     * 9: 无法携带更多唯一物品<br> 12: 无法在不同地图交易<br>
     * 13: 无法交易，游戏文件损坏<br>
     *
     * @param number    编号
     * @param operation 操作码
     * @return 交易结果包
     */
    public static Packet getTradeResult(byte number, byte operation) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.EXIT.getCode());
        p.writeByte(number);
        p.writeByte(operation);
        return p;
    }

    /**
     * 获取交易伙伴添加包
     *
     * @param chr 角色对象
     * @return 交易伙伴添加包
     */
    public static Packet getTradePartnerAdd(Character chr) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.VISIT.getCode());
        p.writeByte(1);
        PacketHelper.addCharLook(p, chr, false);
        p.writeString(chr.getName());
        return p;
    }

    /**
     * 交易邀请包
     *
     * @param chr 角色对象
     * @return 交易邀请包
     */
    public static Packet tradeInvite(Character chr) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.INVITE.getCode());
        p.writeByte(3);
        p.writeString(chr.getName());
        p.writeBytes(new byte[]{(byte) 0xB7, (byte) 0x50, 0, 0});
        return p;
    }

    /**
     * 获取交易金币设置包
     *
     * @param number 编号
     * @param meso   金币
     * @return 交易金币设置包
     */
    public static Packet getTradeMesoSet(byte number, int meso) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.SET_MESO.getCode());
        p.writeByte(number);
        p.writeInt(meso);
        return p;
    }

    /**
     * 获取交易物品添加包
     *
     * @param number 编号
     * @param item   物品对象
     * @return 交易物品添加包
     */
    public static Packet getTradeItemAdd(byte number, Item item) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.SET_ITEMS.getCode());
        p.writeByte(number);
        p.writeByte(item.getPosition());
        PacketHelper.addItemInfo(p, item, true);
        return p;
    }

    /**
     * 获取交易聊天包
     *
     * @param chr   角色对象
     * @param chat  聊天内容
     * @param owner 是否是房主
     * @return 交易聊天包
     */
    public static Packet getTradeChat(Character chr, String chat, boolean owner) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.CHAT.getCode());
        p.writeByte(PlayerInteractionHandler.Action.CHAT_THING.getCode());
        p.writeByte(owner ? 0 : 1);
        p.writeString(chr.getName() + " : " + chat);
        return p;
    }

    /**
     * 雇佣商人盒包
     *
     * @return 雇佣商人盒包
     */
    public static Packet hiredMerchantBox() {
        final OutPacket p = OutPacket.create(SendOpcode.ENTRUSTED_SHOP_CHECK_RESULT); // header.
        p.writeByte(0x07);
        return p;
    }

    /**
     * 获取雇佣商人包
     *
     * @param chr       角色对象
     * @param hm        雇佣商人对象
     * @param firstTime 是否首次
     * @return 雇佣商人包
     */
    public static Packet getHiredMerchant(Character chr, HiredMerchant hm, boolean firstTime) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.ROOM.getCode());
        p.writeByte(0x05);
        p.writeByte(0x04);
        p.writeShort(hm.getVisitorSlotThreadsafe(chr) + 1);     //玩家顾客列表
        p.writeInt(hm.getItemId());     //雇佣商人ID
        p.writeString(ItemInformationProvider.getInstance().getName(hm.getItemId()));   //雇佣商人显示名称

        Character[] visitors = hm.getVisitorCharacters();
        for (int i = 0; i < 3; i++) {
            Character visitor = visitors[i];
            if (visitor != null) {
                if (visitor.getClient().getChannel() == chr.getClient().getChannel() && visitor.getMapId() == chr.getMapId()) {
                    p.writeByte(i + 1);
                    PacketHelper.addCharLook(p, visitor, false);
                    p.writeString(visitor.getName());
                } else {
                    hm.removeVisitor(visitor);
                }
            }
        }
        p.writeByte(-1);
        if (hm.isOwner(chr)) {
            List<Pair<String, Byte>> msgList = hm.getMessages();

            p.writeShort(msgList.size());
            for (Pair<String, Byte> stringBytePair : msgList) {
                p.writeString(stringBytePair.getLeft());
                p.writeByte(stringBytePair.getRight());
            }
        } else {
            p.writeShort(0);
        }
        p.writeString(hm.getOwner());
        if (hm.isOwner(chr)) {
            p.writeShort(0);
            p.writeShort(hm.getTimeOpen());
            p.writeByte(firstTime ? 1 : 0);
            List<HiredMerchant.SoldItem> sold = hm.getSold();
            p.writeByte(sold.size());
            for (HiredMerchant.SoldItem s : sold) {
                p.writeInt(s.getItemId());
                p.writeShort(s.getQuantity());
                p.writeInt(s.getMesos());
                p.writeString(s.getBuyer());
            }
            p.writeInt((int) hm.getTotalRevenue());
            String description = hm.getDescription();
            String days = "  |  剩余 " + hm.getRemainingDays() + " 天";
            p.writeString(description + (hm.getRemainingDays() > 0 ? days : ""));
        } else {
            p.writeString(hm.getDescription());
        }
        p.writeByte(hm.getOnSaleSlotMax());
        p.writeInt(hm.isOwner(chr) ? hm.getMesos() : chr.getMeso());
        p.writeByte(hm.getItems().size());
        if (hm.getItems().isEmpty()) {
            p.writeByte(0);
        } else {
            for (PlayerShopItem item : hm.getItems()) {
                p.writeShort(item.getBundles());
                p.writeShort(item.getItem().getQuantity());
                p.writeInt(item.getPrice());
                PacketHelper.addItemInfo(p, item.getItem(), true);
            }
        }
        return p;
    }

    /**
     * 更新雇佣商人包
     *
     * @param hm  雇佣商人对象
     * @param chr 角色对象
     * @return 更新雇佣商人包
     */
    public static Packet updateHiredMerchant(HiredMerchant hm, Character chr) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.UPDATE_MERCHANT.getCode());
        p.writeInt(hm.isOwner(chr) ? hm.getMesos() : chr.getMeso());
        p.writeByte(hm.getItems().size());
        for (PlayerShopItem item : hm.getItems()) {
            p.writeShort(item.getBundles());
            p.writeShort(item.getItem().getQuantity());
            p.writeInt(item.getPrice());
            PacketHelper.addItemInfo(p, item.getItem(), true);
        }
        return p;
    }

    /**
     * 雇佣商人聊天包
     *
     * @param message 消息
     * @param slot    槽位
     * @return 雇佣商人聊天包
     */
    public static Packet hiredMerchantChat(String message, byte slot) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.CHAT.getCode());
        p.writeByte(PlayerInteractionHandler.Action.CHAT_THING.getCode());
        p.writeByte(slot);
        p.writeString(message);
        return p;
    }

    /**
     * 雇佣商人访客离开包
     *
     * @param slot 槽位
     * @return 雇佣商人访客离开包
     */
    public static Packet hiredMerchantVisitorLeave(int slot) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.EXIT.getCode());
        if (slot != 0) {
            p.writeByte(slot);
        }
        return p;
    }

    /**
     * 雇佣商人店主离开包
     *
     * @return 雇佣商人店主离开包
     */
    public static Packet hiredMerchantOwnerLeave() {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.REAL_CLOSE_MERCHANT.getCode());
        p.writeByte(0);
        return p;
    }

    /**
     * 雇佣商人店主维护离开包
     *
     * @return 雇佣商人店主维护离开包
     */
    public static Packet hiredMerchantOwnerMaintenanceLeave() {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.REAL_CLOSE_MERCHANT.getCode());
        p.writeByte(5);
        return p;
    }

    /**
     * 雇佣商人维护消息包
     *
     * @return 雇佣商人维护消息包
     */
    public static Packet hiredMerchantMaintenanceMessage() {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.ROOM.getCode());
        p.writeByte(0x00);
        p.writeByte(0x12);
        return p;
    }

    /**
     * 离开雇佣商人包
     *
     * @param slot    槽位
     * @param status2 状态2
     * @return 离开雇佣商人包
     */
    public static Packet leaveHiredMerchant(int slot, int status2) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.EXIT.getCode());
        p.writeByte(slot);
        p.writeByte(status2);
        return p;
    }

    /**
     * 查看商人访客历史包
     *
     * @param pastVisitors 访客历史列表
     * @return 查看商人访客历史包
     */
    public static Packet viewMerchantVisitorHistory(List<HiredMerchant.PastVisitor> pastVisitors) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.VIEW_VISITORS.getCode());
        p.writeShort(pastVisitors.size());
        for (HiredMerchant.PastVisitor pastVisitor : pastVisitors) {
            p.writeString(pastVisitor.chrName());
            p.writeInt((int) pastVisitor.visitDuration().toMillis());
        }
        return p;
    }

    /**
     * 查看商人黑名单包
     *
     * @param chrNames 角色名集合
     * @return 查看商人黑名单包
     */
    public static Packet viewMerchantBlacklist(Set<String> chrNames) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.VIEW_BLACKLIST.getCode());
        p.writeShort(chrNames.size());
        for (String chrName : chrNames) {
            p.writeString(chrName);
        }
        return p;
    }

    /**
     * 雇佣商人添加访客包
     *
     * @param chr  角色对象
     * @param slot 槽位
     * @return 雇佣商人添加访客包
     */
    public static Packet hiredMerchantVisitorAdd(Character chr, int slot) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.VISIT.getCode());
        p.writeByte(slot);
        PacketHelper.addCharLook(p, chr, false);
        p.writeString(chr.getName());
        return p;
    }

    /**
     * 生成雇佣商人盒包
     *
     * @param hm 雇佣商人对象
     * @return 生成雇佣商人盒包
     */
    public static Packet spawnHiredMerchantBox(HiredMerchant hm) {
        final OutPacket p = OutPacket.create(SendOpcode.SPAWN_HIRED_MERCHANT);
        p.writeInt(hm.getOwnerId());
        p.writeInt(hm.getItemId());
        p.writeShort((short) hm.getPosition().getX());
        p.writeShort((short) hm.getPosition().getY());
        p.writeShort(0);
        p.writeString(hm.getOwner());
        p.writeByte(0x05);
        p.writeInt(hm.getObjectId());
        p.writeString(hm.getDescription());
        p.writeByte(hm.getItemId() % 100);
        p.writeBytes(new byte[]{1, 4});
        return p;
    }

    /**
     * 移除雇佣商人盒包
     *
     * @param id ID
     * @return 移除雇佣商人盒包
     */
    public static Packet removeHiredMerchantBox(int id) {
        final OutPacket p = OutPacket.create(SendOpcode.DESTROY_HIRED_MERCHANT);
        p.writeInt(id);
        return p;
    }

    /**
     * 更新雇佣商人盒包
     *
     * @param hm 雇佣商人对象
     * @return 更新雇佣商人盒包
     */
    public static Packet updateHiredMerchantBox(HiredMerchant hm) {
        final OutPacket p = OutPacket.create(SendOpcode.UPDATE_HIRED_MERCHANT);
        p.writeInt(hm.getOwnerId());
        PacketHelper.updateHiredMerchantBoxInfo(p, hm);
        return p;
    }

    /**
     * 获取弗雷德里克包
     *
     * @param op 操作码
     * @return 弗雷德里克包
     */
    public static Packet getFredrick(byte op) {
        final OutPacket p = OutPacket.create(SendOpcode.FREDRICK);
        p.writeByte(op);

        switch (op) {
            case 0x24:
                p.skip(8);
                break;
            default:
                p.writeByte(0);
                break;
        }

        return p;
    }

    /**
     * 获取弗雷德里克包（带物品）
     *
     * @param chr       角色对象
     * @param merchants 商人列表
     * @return 弗雷德里克包
     */
    public static Packet getFredrick(Character chr, List<HiredMerchantsDO> merchants) {
        final OutPacket p = OutPacket.create(SendOpcode.FREDRICK);
        p.writeByte(0x23);
        p.writeInt(NpcId.FREDRICK);
        p.writeInt(32272); //id
        p.skip(5);

        long totalMesos = chr.getMerchantNetMeso();
        List<Pair<Item, InventoryType>> allItems = new ArrayList<>();

        // 1. 加载旧系统物品
        allItems.addAll(ItemFactory.MERCHANT.loadItems(chr.getId(), false));

        // 2. 加载新系统物品和金币
        HiredMerchantService hmService = ServerManager.getApplicationContext().getBean(HiredMerchantService.class);
        for (HiredMerchantsDO merchant : merchants) {
            totalMesos += merchant.getMesos();
            List<HiredMerchantItemsDO> merchantItems = hmService.getRetrieveableItems(merchant.getId());
            for (HiredMerchantItemsDO itemDO : merchantItems) {
                short quantity = itemDO.getQuantity() != null ? itemDO.getQuantity().shortValue() : 1;
                Item item = hmService.deserializeItem(itemDO.getItemData(), itemDO.getItemId(), quantity);
                if (item != null) {
                    int remaining = itemDO.getBundles() - itemDO.getSoldQuantity();
                    if (remaining > 0) {
                        item.setQuantity((short) (item.getQuantity() * remaining));
                        allItems.add(new Pair<>(item, item.getInventoryType()));
                    }
                }
            }
        }

        p.writeInt((int) Math.min(totalMesos, Integer.MAX_VALUE));
        p.writeByte(0);
        p.writeByte(allItems.size());

        for (Pair<Item, InventoryType> item : allItems) {
            PacketHelper.addItemInfo(p, item.getLeft(), true);
        }
        p.skip(3);
        return p;
    }

    /**
     * 弗雷德里克消息包
     *
     * @param operation 操作码
     * @return 弗雷德里克消息包
     */
    public static Packet fredrickMessage(byte operation) {
        final OutPacket p = OutPacket.create(SendOpcode.FREDRICK_MESSAGE);
        p.writeByte(operation);
        return p;
    }

    /**
     * 打开 RPS NPC 包
     *
     * @return 打开 RPS NPC 包
     */
    public static Packet openRPSNPC() {
        OutPacket p = OutPacket.create(SendOpcode.RPS_GAME);
        p.writeByte(8);// open npc
        p.writeInt(NpcId.RPS_ADMIN);
        return p;
    }

    /**
     * RPS 金币错误包
     *
     * @param mesos 金币
     * @return RPS 金币错误包
     */
    public static Packet rpsMesoError(int mesos) {
        OutPacket p = OutPacket.create(SendOpcode.RPS_GAME);
        p.writeByte(0x06);
        if (mesos != -1) {
            p.writeInt(mesos);
        }
        return p;
    }

    /**
     * RPS 选择包
     *
     * @param selection 选择
     * @param answer    答案
     * @return RPS 选择包
     */
    public static Packet rpsSelection(byte selection, byte answer) {
        OutPacket p = OutPacket.create(SendOpcode.RPS_GAME);
        p.writeByte(0x0B);// 11l
        p.writeByte(selection);
        p.writeByte(answer);
        return p;
    }

    /**
     * RPS 模式包
     *
     * @param mode 模式
     * @return RPS 模式包
     */
    public static Packet rpsMode(byte mode) {
        OutPacket p = OutPacket.create(SendOpcode.RPS_GAME);
        p.writeByte(mode);
        return p;
    }

    /**
     * 获取猫头鹰消息包
     * 获取猫头鹰商店操作结果消息包
     *
     * @param msg 消息代码
     * @return 猫头鹰消息包
     * @description 根据传入的消息代码返回对应的操作结果提示包。
     * 消息代码含义：
     * 0: 操作成功
     * 1: 房间已关闭
     * 2: 房间人数已满，无法进入
     * 3: 当前分钟有其他请求正在处理
     * 4: 死亡状态下无法执行此操作
     * 7: 当前不允许交易其他物品
     * 17: 无权进入此商店
     * 18: 店主正在进行商店维护，请稍后再试
     * 23: 此功能只能在自由市场内使用
     * default: 角色无法执行此操作
     */
    public static Packet getOwlMessage(int msg) {
        OutPacket p = OutPacket.create(SendOpcode.SHOP_LINK_RESULT);
        p.writeByte(msg);
        return p;
    }

    /**
     * 密涅瓦猫头鹰包
     *
     * @param c            客户端对象
     * @param itemId       物品ID
     * @param hmsAvailable 可用商人列表
     * @return 密涅瓦猫头鹰包
     */
    public static Packet owlOfMinerva(Client c, int itemId, List<Pair<PlayerShopItem, AbstractMapObject>> hmsAvailable) {
        byte itemType = ItemConstants.getInventoryType(itemId).getType();

        OutPacket p = OutPacket.create(SendOpcode.SHOP_SCANNER_RESULT);
        p.writeByte(6);
        p.writeInt(0);
        p.writeInt(itemId);
        p.writeInt(hmsAvailable.size());
        for (Pair<PlayerShopItem, AbstractMapObject> hme : hmsAvailable) {
            PlayerShopItem item = hme.getLeft();
            AbstractMapObject mo = hme.getRight();

            if (mo instanceof PlayerShop ps) {
                Character owner = ps.getOwner();

                p.writeString(owner.getName());
                p.writeInt(owner.getMapId());
                p.writeString(ps.getDescription());
                p.writeInt(item.getBundles());
                p.writeInt(item.getItem().getQuantity());
                p.writeInt(item.getPrice());
                p.writeInt(owner.getId());
                p.writeByte(owner.getClient().getChannel() - 1);
            } else {
                HiredMerchant hm = (HiredMerchant) mo;

                p.writeString(hm.getOwner());
                p.writeInt(hm.getMapId());
                p.writeString(hm.getDescription());
                p.writeInt(item.getBundles());
                p.writeInt(item.getItem().getQuantity());
                p.writeInt(item.getPrice());
                p.writeInt(hm.getOwnerId());
                p.writeByte(hm.getChannel() - 1);
            }

            p.writeByte(itemType);
            if (itemType == InventoryType.EQUIP.getType()) {
                PacketHelper.addItemInfo(p, item.getItem(), true);
            }
        }
        return p;
    }

    /**
     * 获取猫头鹰打开包
     *
     * @param owlLeaderboards 排行榜
     * @return 猫头鹰打开包
     */
    public static Packet getOwlOpen(List<Integer> owlLeaderboards) {
        OutPacket p = OutPacket.create(SendOpcode.SHOP_SCANNER_RESULT);
        p.writeByte(7);
        p.writeByte(owlLeaderboards.size());
        for (Integer i : owlLeaderboards) {
            p.writeInt(i);
        }

        return p;
    }

    /**
     * 检索第一条消息包
     *
     * @return 检索第一条消息包
     */
    public static Packet retrieveFirstMessage() {
        final OutPacket p = OutPacket.create(SendOpcode.ENTRUSTED_SHOP_CHECK_RESULT); // header.
        p.writeByte(0x09);
        return p;
    }

    /**
     * 远程频道更改包
     * 创建远程频道切换数据包
     * <p>
     * ENTRUSTED_SHOP_CHECK_RESULT 可能的值说明：
     * 0x0E = 00 = 重命名失败 - 找不到商店, 01 = 重命名成功
     * 0x10 = 切换到商店所在频道（商店在频道1开放，是否要切换频道？）
     * 0x11 = 管理期间无法出售物品...等提示
     * 0x12 = 弹出窗口提示
     *
     * @param ch 目标频道号
     * @return 远程频道更改包
     */
    public static Packet remoteChannelChange(byte ch) {
        final OutPacket p = OutPacket.create(SendOpcode.ENTRUSTED_SHOP_CHECK_RESULT);
        p.writeByte(0x10);
        p.writeInt(0);
        p.writeByte(ch);
        return p;
    }
}
