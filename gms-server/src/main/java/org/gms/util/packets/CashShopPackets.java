package org.gms.util.packets;

import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.constants.game.GameConstants;
import org.gms.constants.inventory.ItemConstants;
import org.gms.dao.entity.ModifiedCashItemDO;
import org.gms.net.opcodes.SendOpcode;
import org.gms.net.packet.OutPacket;
import org.gms.net.packet.Packet;
import org.gms.net.server.Server;
import org.gms.net.server.world.World;
import org.gms.server.CashShop;
import org.gms.server.CashShop.CashItemFactory;
import org.gms.server.MTSItemInfo;
import org.gms.util.Pair;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * CashShopPackets
 * 处理商城操作、礼物、扩充栏位、MTS 等相关的数据包构建
 */
public class CashShopPackets {

    public static Packet openCashShop(Client c, boolean mts) throws Exception {
        final OutPacket p = OutPacket.create(mts ? SendOpcode.SET_ITC : SendOpcode.SET_CASH_SHOP);

        PacketHelper.addCharacterInfo(p, c.getPlayer());

        if (!mts) {
            p.writeByte(1);
        }

        p.writeString(c.getAccountName());
        if (mts) {
            p.writeBytes(new byte[]{(byte) 0x88, 19, 0, 0,
                    7, 0, 0, 0,
                    (byte) 0xF4, 1, 0, 0,
                    (byte) 0x18, 0, 0, 0,
                    (byte) 0xA8, 0, 0, 0,
                    (byte) 0x70, (byte) 0xAA, (byte) 0xA7, (byte) 0xC5,
                    (byte) 0x4E, (byte) 0xC1, (byte) 0xCA, 1});
        } else {
            p.writeInt(0);
            // 使用 Stream 按优先级顺序合并和滤重
            Map<Integer, ModifiedCashItemDO> itemMap = Stream.of(//生效的优先级从高到低，确保控制台商城管理的优先级最高，并且减少重复的现金道具。
                            CashItemFactory.getDiscontinuedCashItems().values(), // 合并已下架现金道具列表
                            CashItemFactory.getModifiedCashItems().values(),  // 获取修改过的现金道具信息
                            CashItemFactory.getPermanentCashItems().values() // 合并永久现金道具列表
                    )
                    .flatMap(Collection::stream)
                    .collect(Collectors.toMap(
                            ModifiedCashItemDO::getSn,
                            item -> item,
                            (existing, replacement) -> existing, // 保留先出现的（高优先级）
                            LinkedHashMap::new // 保持插入顺序
                    ));
            Collection<ModifiedCashItemDO> items = itemMap.values();
            p.writeShort(items.size());//Guess what
            for (ModifiedCashItemDO item : items) {
                PacketHelper.writeModifiedCashItem(p, item);
            }
            p.skip(121);

            List<List<Integer>> mostSellers = c.getWorldServer().getMostSellerCashItems();  //获取热门销售现金道具
            for (int i = 1; i <= 8; i++) {
                List<Integer> mostSellersTab = mostSellers.get(i);

                for (int j = 0; j < 2; j++) {
                    for (Integer snid : mostSellersTab) {
                        p.writeInt(i);
                        p.writeInt(j);
                        p.writeInt(snid);
                    }
                }
            }

            p.writeInt(0);
            p.writeShort(0);
            p.writeByte(0);
            p.writeInt(75);
        }
        return p;
    }

    public static Packet showCash(Character mc) {
        final OutPacket p = OutPacket.create(SendOpcode.QUERY_CASH_RESULT);
        p.writeInt(mc.getCashShop().getCash(CashShop.NX_CREDIT));
        p.writeInt(mc.getCashShop().getCash(CashShop.MAPLE_POINT));
        p.writeInt(mc.getCashShop().getCash(CashShop.NX_PREPAID));
        return p;
    }

    public static Packet enableCSUse(Character mc) {
        return showCash(mc);
    }

    public static Packet showCashInventory(Client c) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);

        p.writeByte(0x4B);
        p.writeShort(c.getPlayer().getCashShop().getInventory().size());

        for (Item item : c.getPlayer().getCashShop().getInventory()) {
            PacketHelper.addCashItemInformation(p, item, c.getAccID());
        }

        p.writeShort(c.getPlayer().getStorage().getSlots());
        p.writeShort(c.getCharacterSlots());

        return p;
    }

    public static Packet showBoughtCashItem(Item item, int accountId) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);

        p.writeByte(0x57);
        PacketHelper.addCashItemInformation(p, item, accountId);

        return p;
    }

    public static Packet showBoughtCashPackage(List<Item> cashPackage, int accountId) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);

        p.writeByte(0x89);
        p.writeByte(cashPackage.size());

        for (Item item : cashPackage) {
            PacketHelper.addCashItemInformation(p, item, accountId);
        }

        p.writeShort(0);

        return p;
    }

    public static Packet showBoughtCashRing(Item ring, String recipient, int accountId) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);
        p.writeByte(0x87);
        PacketHelper.addCashItemInformation(p, ring, accountId);
        p.writeString(recipient);
        p.writeInt(ring.getItemId());
        p.writeShort(1); //quantity
        return p;
    }

    public static Packet showBoughtQuestItem(int itemId) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);
        p.writeByte(0x8D);
        p.writeInt(1);
        p.writeShort(1);
        p.writeByte(0x0B);
        p.writeByte(0);
        p.writeInt(itemId);
        return p;
    }

    public static Packet showBoughtInventorySlots(int type, short slots) {
        OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);

        p.writeByte(0x60);
        p.writeByte(type);
        p.writeShort(slots);

        return p;
    }

    public static Packet showBoughtStorageSlots(short slots) {
        OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);

        p.writeByte(0x62);
        p.writeShort(slots);

        return p;
    }

    public static Packet showBoughtCharacterSlot(short slots) {
        OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);

        p.writeByte(0x64);
        p.writeShort(slots);

        return p;
    }

    public static Packet showGiftSucceed(String to, ModifiedCashItemDO item) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);

        p.writeByte(0x5E); //0x5D, Couldn't be sent
        p.writeString(to);
        p.writeInt(item.getItemId());
        p.writeShort(item.getCount());
        p.writeInt(item.getPrice());

        return p;
    }

    public static Packet showGifts(List<Pair<Item, String>> gifts) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);

        p.writeByte(0x4D);
        p.writeShort(gifts.size());

        for (Pair<Item, String> gift : gifts) {
            PacketHelper.addCashItemInformation(p, gift.getLeft(), 0, gift.getRight());
        }

        return p;
    }

    public static Packet takeFromCashInventory(Item item) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);

        p.writeByte(0x68);
        p.writeShort(item.getPosition());
        PacketHelper.addItemInfo(p, item, true);

        return p;
    }

    public static Packet putIntoCashInventory(Item item, int accountId) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);

        p.writeByte(0x6A);
        PacketHelper.addCashItemInformation(p, item, accountId);

        return p;
    }

    public static Packet deleteCashItem(Item item) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);
        p.writeByte(0x6C);
        p.writeLong(item.getCashId());
        return p;
    }

    public static Packet refundCashItem(Item item, int maplePoints) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);
        p.writeByte(0x85);
        p.writeLong(item.getCashId());
        p.writeInt(maplePoints);
        return p;
    }

    public static Packet showCashShopMessage(byte message) {
        OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);
        p.writeByte(0x5C);
        p.writeByte(message);
        return p;
    }

    public static Packet showWishList(Character mc, boolean update) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);

        if (update) {
            p.writeByte(0x55);
        } else {
            p.writeByte(0x4F);
        }

        for (int sn : mc.getCashShop().getWishList()) {
            p.writeInt(sn);
        }

        for (int i = mc.getCashShop().getWishList().size(); i < 10; i++) {
            p.writeInt(0);
        }

        return p;
    }

    public static Packet showCouponRedeemedItems(int accountId, int maplePoints, int mesos, List<Item> cashItems, List<Pair<Integer, Integer>> items) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);
        p.writeByte(0x59);
        p.writeByte((byte) cashItems.size());
        for (Item item : cashItems) {
            PacketHelper.addCashItemInformation(p, item, accountId);
        }
        p.writeInt(maplePoints);
        p.writeInt(items.size());
        for (Pair<Integer, Integer> itemPair : items) {
            int quantity = itemPair.getLeft();
            p.writeShort((short) quantity); //quantity (0 = 1 for cash items)
            p.writeShort(0x1F); //0 = ?, >=0x20 = ?, <0x20 = ? (does nothing?)
            p.writeInt(itemPair.getRight());
        }
        p.writeInt(mesos);
        return p;
    }

    public static Packet onCashItemGachaponOpenFailed() {
        OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_CASH_ITEM_GACHAPON_RESULT);
        p.writeByte(0xE4);
        return p;
    }

    public static Packet onCashGachaponOpenSuccess(int accountid, long boxCashId, int remainingBoxes, Item reward,
                                                   int rewardItemId, int rewardQuantity, boolean bJackpot) {
        OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_CASH_ITEM_GACHAPON_RESULT);
        p.writeByte(0xE5);   // subopcode thanks to Ubaware
        p.writeLong(boxCashId);
        p.writeInt(remainingBoxes);
        PacketHelper.addCashItemInformation(p, reward, accountid);
        p.writeInt(rewardItemId);
        p.writeByte(rewardQuantity); // nSelectedItemCount
        p.writeBool(bJackpot);// "CashGachaponJackpot"
        return p;
    }

    public static Packet sendWorldTransferRules(int error, Client c) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_CHECK_TRANSFER_WORLD_POSSIBLE_RESULT);
        p.writeInt(0); //ignored
        p.writeByte(error);
        p.writeInt(0);
        p.writeBool(error == 0); //0 = ?, otherwise list servers
        if (error == 0) {
            List<World> worlds = Server.getInstance().getWorlds();
            p.writeInt(worlds.size());
            for (World world : worlds) {
                p.writeString(GameConstants.WORLD_NAMES[world.getId()]);
            }
        }
        return p;
    }

    public static Packet showWorldTransferSuccess(Item item, int accountId) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);
        p.writeByte(0xA0);
        PacketHelper.addCashItemInformation(p, item, accountId);
        return p;
    }

    public static Packet showWorldTransferCancel(boolean success) {
        OutPacket p = OutPacket.create(SendOpcode.CANCEL_TRANSFER_WORLD_RESULT);
        p.writeBool(success);
        if (!success) {
            p.writeByte(0);
        }
        return p;
    }

    public static Packet sendNameTransferRules(int error) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_CHECK_NAME_CHANGE_POSSIBLE_RESULT);
        p.writeInt(0);
        p.writeByte(error);
        p.writeInt(0);

        return p;
    }

    public static Packet sendNameTransferCheck(String availableName, boolean canUseName) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_CHECK_NAME_CHANGE);
        //Send provided name back to client to add to temporary cache of checked & accepted names
        p.writeString(availableName);
        p.writeBool(!canUseName);
        return p;
    }

    public static Packet showNameChangeSuccess(Item item, int accountId) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);
        p.writeByte(0x9E);
        PacketHelper.addCashItemInformation(p, item, accountId);
        return p;
    }

    public static Packet showNameChangeCancel(boolean success) {
        OutPacket p = OutPacket.create(SendOpcode.CANCEL_NAME_CHANGE_RESULT);
        p.writeBool(success);
        if (!success) {
            p.writeByte(0);
        }
        return p;
    }

    public static Packet showMTSCash(Character chr) {
        final OutPacket p = OutPacket.create(SendOpcode.MTS_OPERATION2);
        p.writeInt(chr.getCashShop().getCash(CashShop.NX_PREPAID));
        p.writeInt(chr.getCashShop().getCash(CashShop.MAPLE_POINT));
        return p;
    }

    public static Packet sendMTS(List<MTSItemInfo> items, int tab, int type, int page, int pages) {
        final OutPacket p = OutPacket.create(SendOpcode.MTS_OPERATION);
        p.writeByte(0x15); //operation
        p.writeInt(pages * 16); //testing, change to 10 if fails
        p.writeInt(items.size()); //number of items
        p.writeInt(tab);
        p.writeInt(type);
        p.writeInt(page);
        p.writeByte(1);
        p.writeByte(1);
        for (MTSItemInfo item : items) {
            PacketHelper.addItemInfo(p, item.getItem(), true);
            p.writeInt(item.getID()); //id
            p.writeInt(item.getTaxes()); //this + below = price
            p.writeInt(item.getPrice()); //price
            p.writeInt(0);
            p.writeLong(PacketHelper.getTime(item.getEndingDate()));
            p.writeString(item.getSeller()); //account name (what was nexon thinking?)
            p.writeString(item.getSeller()); //char name
            for (int j = 0; j < 28; j++) {
                p.writeByte(0);
            }
        }
        p.writeByte(1);
        return p;
    }

    public static Packet MTSWantedListingOver(int nx, int items) {
        final OutPacket p = OutPacket.create(SendOpcode.MTS_OPERATION);
        p.writeByte(0x3D);
        p.writeInt(nx);
        p.writeInt(items);
        return p;
    }

    public static Packet MTSConfirmSell() {
        final OutPacket p = OutPacket.create(SendOpcode.MTS_OPERATION);
        p.writeByte(0x1D);
        return p;
    }

    public static Packet MTSConfirmBuy() {
        final OutPacket p = OutPacket.create(SendOpcode.MTS_OPERATION);
        p.writeByte(0x33);
        return p;
    }

    public static Packet MTSFailBuy() {
        final OutPacket p = OutPacket.create(SendOpcode.MTS_OPERATION);
        p.writeByte(0x34);
        p.writeByte(0x42);
        return p;
    }

    public static Packet MTSConfirmTransfer(int quantity, int pos) {
        final OutPacket p = OutPacket.create(SendOpcode.MTS_OPERATION);
        p.writeByte(0x27);
        p.writeInt(quantity);
        p.writeInt(pos);
        return p;
    }

    public static Packet notYetSoldInv(List<MTSItemInfo> items) {
        final OutPacket p = OutPacket.create(SendOpcode.MTS_OPERATION);
        p.writeByte(0x23);
        p.writeInt(items.size());
        if (!items.isEmpty()) {
            for (MTSItemInfo item : items) {
                PacketHelper.addItemInfo(p, item.getItem(), true);
                p.writeInt(item.getID()); //id
                p.writeInt(item.getTaxes()); //this + below = price
                p.writeInt(item.getPrice()); //price
                p.writeInt(0);
                p.writeLong(PacketHelper.getTime(item.getEndingDate()));
                p.writeString(item.getSeller()); //account name (what was nexon thinking?)
                p.writeString(item.getSeller()); //char name
                for (int i = 0; i < 28; i++) {
                    p.writeByte(0);
                }
            }
        } else {
            p.writeInt(0);
        }
        return p;
    }

    public static Packet transferInventory(List<MTSItemInfo> items) {
        final OutPacket p = OutPacket.create(SendOpcode.MTS_OPERATION);
        p.writeByte(0x21);
        p.writeInt(items.size());
        if (!items.isEmpty()) {
            for (MTSItemInfo item : items) {
                PacketHelper.addItemInfo(p, item.getItem(), true);
                p.writeInt(item.getID()); //id
                p.writeInt(item.getTaxes()); //taxes
                p.writeInt(item.getPrice()); //price
                p.writeInt(0);
                p.writeLong(PacketHelper.getTime(item.getEndingDate()));
                p.writeString(item.getSeller()); //account name (what was nexon thinking?)
                p.writeString(item.getSeller()); //char name
                for (int i = 0; i < 28; i++) {
                    p.writeByte(0);
                }
            }
        }
        p.writeByte(0xD0 + items.size());
        p.writeBytes(new byte[]{-1, -1, -1, 0});
        return p;
    }

    public static Packet UseTreasureBox(int type){
        OutPacket p = OutPacket.create(SendOpcode.SUCCESS_IN_USE_GACHAPON_BOX);
        p.writeInt(type);
        return p;
    }
}
