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

    public static Packet getMiniGameReady(MiniGame game) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.READY.getCode());
        return p;
    }

    public static Packet getMiniGameUnReady(MiniGame game) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.UN_READY.getCode());
        return p;
    }

    public static Packet getMiniGameStart(MiniGame game, int loser) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.START.getCode());
        p.writeByte(loser);
        return p;
    }

    public static Packet getMiniGameSkipOwner(MiniGame game) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.SKIP.getCode());
        p.writeByte(0x01);
        return p;
    }

    public static Packet getMiniGameSkipVisitor(MiniGame game) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeShort(PlayerInteractionHandler.Action.SKIP.getCode());
        return p;
    }

    public static Packet getMiniGameRequestTie(MiniGame game) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.REQUEST_TIE.getCode());
        return p;
    }

    public static Packet getMiniGameDenyTie(MiniGame game) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.ANSWER_TIE.getCode());
        return p;
    }

    public static Packet getMiniGameMoveOmok(MiniGame game, int move1, int move2, int move3) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.MOVE_OMOK.getCode());
        p.writeInt(move1);
        p.writeInt(move2);
        p.writeByte(move3);
        return p;
    }

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

    public static Packet getMiniGameRemoveVisitor() {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.EXIT.getCode());
        p.writeByte(1);
        return p;
    }

    public static Packet getMiniGameOwnerWin(MiniGame game, boolean forfeit) {
        return getMiniGameResult(game, 0, 1, forfeit ? 1 : 0);
    }

    public static Packet getMiniGameVisitorWin(MiniGame game, boolean forfeit) {
        return getMiniGameResult(game, 0, 2, forfeit ? 1 : 0);
    }

    public static Packet getMiniGameTie(MiniGame game) {
        return getMiniGameResult(game, 1, 3, 0);
    }

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

    public static Packet getMiniGameClose(boolean visitor, int type) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.EXIT.getCode());
        p.writeBool(visitor);
        p.writeByte(type); /* 2 : CRASH 3 : The room has been closed 4 : You have left the room 5 : You have been expelled  */
        return p;
    }

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

    public static Packet getMiniRoomError(int status) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.ROOM.getCode());
        p.writeByte(0);
        p.writeByte(status);
        return p;
    }

    public static Packet addOmokBox(Character chr, int amount, int type) {
        OutPacket p = OutPacket.create(SendOpcode.UPDATE_CHAR_BOX);
        p.writeInt(chr.getId());
        PacketHelper.addAnnounceBox(p, chr.getMiniGame(), amount, type);
        return p;
    }

    public static Packet addMatchCardBox(Character chr, int amount, int type) {
        OutPacket p = OutPacket.create(SendOpcode.UPDATE_CHAR_BOX);
        p.writeInt(chr.getId());
        PacketHelper.addAnnounceBox(p, chr.getMiniGame(), amount, type);
        return p;
    }

    public static Packet removeMinigameBox(Character chr) {
        OutPacket p = OutPacket.create(SendOpcode.UPDATE_CHAR_BOX);
        p.writeInt(chr.getId());
        p.writeByte(0);
        return p;
    }

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

    public static Packet getPlayerShopChat(Character chr, String chat, boolean owner) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.CHAT.getCode());
        p.writeByte(PlayerInteractionHandler.Action.CHAT_THING.getCode());
        p.writeBool(!owner);
        p.writeString(chr.getName() + " : " + chat);
        return p;
    }

    public static Packet getPlayerShopChat(Character chr, String chat, byte slot) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.CHAT.getCode());
        p.writeByte(PlayerInteractionHandler.Action.CHAT_THING.getCode());
        p.writeByte(slot);
        p.writeString(chr.getName() + " : " + chat);
        return p;
    }

    public static Packet getPlayerShopNewVisitor(Character chr, int slot) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.VISIT.getCode());
        p.writeByte(slot);
        PacketHelper.addCharLook(p, chr, false);
        p.writeString(chr.getName());
        return p;
    }

    public static Packet getPlayerShopRemoveVisitor(int slot) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.EXIT.getCode());
        if (slot != 0) {
            p.writeShort(slot);
        }
        return p;
    }

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

    public static Packet getPlayerShopOwnerUpdate(PlayerShop.SoldItem item, int position) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.UPDATE_PLAYERSHOP.getCode());
        p.writeByte(position);
        p.writeShort(item.getQuantity());
        p.writeString(item.getBuyer());

        return p;
    }

    public static Packet updatePlayerShopBox(PlayerShop shop) {
        final OutPacket p = OutPacket.create(SendOpcode.UPDATE_CHAR_BOX);
        p.writeInt(shop.getOwner().getId());
        PacketHelper.updatePlayerShopBoxInfo(p, shop);
        return p;
    }

    public static Packet removePlayerShopBox(PlayerShop shop) {
        OutPacket p = OutPacket.create(SendOpcode.UPDATE_CHAR_BOX);
        p.writeInt(shop.getOwner().getId());
        p.writeByte(0);
        return p;
    }

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

    public static Packet getTradeConfirmation() {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.CONFIRM.getCode());
        return p;
    }

    public static Packet getTradeResult(byte number, byte operation) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.EXIT.getCode());
        p.writeByte(number);
        p.writeByte(operation);
        return p;
    }

    public static Packet getTradePartnerAdd(Character chr) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.VISIT.getCode());
        p.writeByte(1);
        PacketHelper.addCharLook(p, chr, false);
        p.writeString(chr.getName());
        return p;
    }

    public static Packet tradeInvite(Character chr) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.INVITE.getCode());
        p.writeByte(3);
        p.writeString(chr.getName());
        p.writeBytes(new byte[]{(byte) 0xB7, (byte) 0x50, 0, 0});
        return p;
    }

    public static Packet getTradeMesoSet(byte number, int meso) {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.SET_MESO.getCode());
        p.writeByte(number);
        p.writeInt(meso);
        return p;
    }

    public static Packet getTradeItemAdd(byte number, Item item) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.SET_ITEMS.getCode());
        p.writeByte(number);
        p.writeByte(item.getPosition());
        PacketHelper.addItemInfo(p, item, true);
        return p;
    }

    public static Packet getTradeChat(Character chr, String chat, boolean owner) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.CHAT.getCode());
        p.writeByte(PlayerInteractionHandler.Action.CHAT_THING.getCode());
        p.writeByte(owner ? 0 : 1);
        p.writeString(chr.getName() + " : " + chat);
        return p;
    }

    public static Packet hiredMerchantBox() {
        final OutPacket p = OutPacket.create(SendOpcode.ENTRUSTED_SHOP_CHECK_RESULT); // header.
        p.writeByte(0x07);
        return p;
    }

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

    public static Packet hiredMerchantChat(String message, byte slot) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.CHAT.getCode());
        p.writeByte(PlayerInteractionHandler.Action.CHAT_THING.getCode());
        p.writeByte(slot);
        p.writeString(message);
        return p;
    }

    public static Packet hiredMerchantVisitorLeave(int slot) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.EXIT.getCode());
        if (slot != 0) {
            p.writeByte(slot);
        }
        return p;
    }

    public static Packet hiredMerchantOwnerLeave() {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.REAL_CLOSE_MERCHANT.getCode());
        p.writeByte(0);
        return p;
    }

    public static Packet hiredMerchantOwnerMaintenanceLeave() {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.REAL_CLOSE_MERCHANT.getCode());
        p.writeByte(5);
        return p;
    }

    public static Packet hiredMerchantMaintenanceMessage() {
        OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.ROOM.getCode());
        p.writeByte(0x00);
        p.writeByte(0x12);
        return p;
    }

    public static Packet leaveHiredMerchant(int slot, int status2) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.EXIT.getCode());
        p.writeByte(slot);
        p.writeByte(status2);
        return p;
    }

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

    public static Packet viewMerchantBlacklist(Set<String> chrNames) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.VIEW_BLACKLIST.getCode());
        p.writeShort(chrNames.size());
        for (String chrName : chrNames) {
            p.writeString(chrName);
        }
        return p;
    }

    public static Packet hiredMerchantVisitorAdd(Character chr, int slot) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(PlayerInteractionHandler.Action.VISIT.getCode());
        p.writeByte(slot);
        PacketHelper.addCharLook(p, chr, false);
        p.writeString(chr.getName());
        return p;
    }

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

    public static Packet removeHiredMerchantBox(int id) {
        final OutPacket p = OutPacket.create(SendOpcode.DESTROY_HIRED_MERCHANT);
        p.writeInt(id);
        return p;
    }

    public static Packet updateHiredMerchantBox(HiredMerchant hm) {
        final OutPacket p = OutPacket.create(SendOpcode.UPDATE_HIRED_MERCHANT);
        p.writeInt(hm.getOwnerId());
        PacketHelper.updateHiredMerchantBoxInfo(p, hm);
        return p;
    }

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
                Item item = hmService.deserializeItem(itemDO.getItemData());
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

    public static Packet fredrickMessage(byte operation) {
        final OutPacket p = OutPacket.create(SendOpcode.FREDRICK_MESSAGE);
        p.writeByte(operation);
        return p;
    }

    public static Packet openRPSNPC() {
        OutPacket p = OutPacket.create(SendOpcode.RPS_GAME);
        p.writeByte(8);// open npc
        p.writeInt(NpcId.RPS_ADMIN);
        return p;
    }

    public static Packet rpsMesoError(int mesos) {
        OutPacket p = OutPacket.create(SendOpcode.RPS_GAME);
        p.writeByte(0x06);
        if (mesos != -1) {
            p.writeInt(mesos);
        }
        return p;
    }

    public static Packet rpsSelection(byte selection, byte answer) {
        OutPacket p = OutPacket.create(SendOpcode.RPS_GAME);
        p.writeByte(0x0B);// 11l
        p.writeByte(selection);
        p.writeByte(answer);
        return p;
    }

    public static Packet rpsMode(byte mode) {
        OutPacket p = OutPacket.create(SendOpcode.RPS_GAME);
        p.writeByte(mode);
        return p;
    }

    public static Packet getOwlMessage(int msg) {
        OutPacket p = OutPacket.create(SendOpcode.SHOP_LINK_RESULT);
        p.writeByte(msg);
        return p;
    }

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

    public static Packet getOwlOpen(List<Integer> owlLeaderboards) {
        OutPacket p = OutPacket.create(SendOpcode.SHOP_SCANNER_RESULT);
        p.writeByte(7);
        p.writeByte(owlLeaderboards.size());
        for (Integer i : owlLeaderboards) {
            p.writeInt(i);
        }

        return p;
    }

    public static Packet retrieveFirstMessage() {
        final OutPacket p = OutPacket.create(SendOpcode.ENTRUSTED_SHOP_CHECK_RESULT); // header.
        p.writeByte(0x09);
        return p;
    }

    public static Packet remoteChannelChange(byte ch) {
        final OutPacket p = OutPacket.create(SendOpcode.ENTRUSTED_SHOP_CHECK_RESULT);
        p.writeByte(0x10);
        p.writeInt(0);
        p.writeByte(ch);
        return p;
    }
}
