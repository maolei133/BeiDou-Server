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

    /**
     * 打开商城
     * @param c 客户端对象
     * @param mts 是否MTS
     * @return 数据包
     * @throws Exception 异常
     */
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
            Collection<ModifiedCashItemDO> items = CashItemFactory.getClientCache();
            p.writeShort(items.size());// 发送修改过的商城物品数量
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

    /**
     * 显示点券
     * @param mc 角色对象
     * @return 数据包
     */
    public static Packet showCash(Character mc) {
        final OutPacket p = OutPacket.create(SendOpcode.QUERY_CASH_RESULT);
        p.writeInt(mc.getCashShop().getCash(CashShop.NX_CREDIT));
        p.writeInt(mc.getCashShop().getCash(CashShop.MAPLE_POINT));
        p.writeInt(mc.getCashShop().getCash(CashShop.NX_PREPAID));
        return p;
    }

    /**
     * 启用商城使用
     * @param mc 角色对象
     * @return 数据包
     */
    public static Packet enableCSUse(Character mc) {
        return showCash(mc);
    }

    /**
     * 显示商城背包
     * @param c 客户端对象
     * @return 数据包
     */
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

    /**
     * 显示购买的商城物品
     * @param item 物品对象
     * @param accountId 账号ID
     * @return 数据包
     */
    public static Packet showBoughtCashItem(Item item, int accountId) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);

        p.writeByte(0x57);
        PacketHelper.addCashItemInformation(p, item, accountId);

        return p;
    }

    /**
     * 显示购买的商城礼包
     * @param cashPackage 礼包列表
     * @param accountId 账号ID
     * @return 数据包
     */
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

    /**
     * 显示购买的商城戒指
     * @param ring 戒指物品
     * @param recipient 接收者
     * @param accountId 账号ID
     * @return 数据包
     */
    public static Packet showBoughtCashRing(Item ring, String recipient, int accountId) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);
        p.writeByte(0x87);
        PacketHelper.addCashItemInformation(p, ring, accountId);
        p.writeString(recipient);
        p.writeInt(ring.getItemId());
        p.writeShort(1); //quantity
        return p;
    }

    /**
     * 显示购买的任务物品
     * @param itemId 物品ID
     * @return 数据包
     */
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

    /**
     * 显示购买的背包槽位
     * @param type 类型
     * @param slots 槽位数
     * @return 数据包
     */
    public static Packet showBoughtInventorySlots(int type, short slots) {
        OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);

        p.writeByte(0x60);
        p.writeByte(type);
        p.writeShort(slots);

        return p;
    }

    /**
     * 显示购买的仓库槽位
     * @param slots 槽位数
     * @return 数据包
     */
    public static Packet showBoughtStorageSlots(short slots) {
        OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);

        p.writeByte(0x62);
        p.writeShort(slots);

        return p;
    }

    /**
     * 显示购买的角色槽位
     * @param slots 槽位数
     * @return 数据包
     */
    public static Packet showBoughtCharacterSlot(short slots) {
        OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);

        p.writeByte(0x64);
        p.writeShort(slots);

        return p;
    }

    /**
     * 显示礼物成功
     * @param to 接收者
     * @param item 物品对象
     * @return 数据包
     */
    public static Packet showGiftSucceed(String to, ModifiedCashItemDO item) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);

        p.writeByte(0x5E); // 0x5D, 无法发送
        p.writeString(to);
        p.writeInt(item.getItemId());
        p.writeShort(item.getCount());
        p.writeInt(item.getPrice());

        return p;
    }

    /**
     * 显示礼物列表
     * @param gifts 礼物列表
     * @return 数据包
     */
    public static Packet showGifts(List<Pair<Item, String>> gifts) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);

        p.writeByte(0x4D);
        p.writeShort(gifts.size());

        for (Pair<Item, String> gift : gifts) {
            PacketHelper.addCashItemInformation(p, gift.getLeft(), 0, gift.getRight());
        }

        return p;
    }

    /**
     * 从商城背包取出
     * @param item 物品对象
     * @return 数据包
     */
    public static Packet takeFromCashInventory(Item item) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);

        p.writeByte(0x68);
        p.writeShort(item.getPosition());
        PacketHelper.addItemInfo(p, item, true);

        return p;
    }

    /**
     * 放入商城背包
     * @param item 物品对象
     * @param accountId 账号ID
     * @return 数据包
     */
    public static Packet putIntoCashInventory(Item item, int accountId) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);

        p.writeByte(0x6A);
        PacketHelper.addCashItemInformation(p, item, accountId);

        return p;
    }

    /**
     * 删除商城物品
     * @param item 物品对象
     * @return 数据包
     */
    public static Packet deleteCashItem(Item item) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);
        p.writeByte(0x6C);
        p.writeLong(item.getCashId());
        return p;
    }

    /**
     * 退款商城物品
     * @param item 物品对象
     * @param maplePoints 抵用券
     * @return 数据包
     */
    public static Packet refundCashItem(Item item, int maplePoints) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);
        p.writeByte(0x85);
        p.writeLong(item.getCashId());
        p.writeInt(maplePoints);
        return p;
    }

    /**
     * 显示商城消息
     * @param message 消息代码
     * @return 数据包
     */
    public static Packet showCashShopMessage(byte message) {
        OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);
        p.writeByte(0x5C);
        p.writeByte(message);
        return p;
    }

    /**
     * 显示愿望清单
     * @param mc 角色对象
     * @param update 是否更新
     * @return 数据包
     */
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

    /**
     * 显示兑换券兑换物品
     * @param accountId 账号ID
     * @param maplePoints 抵用券
     * @param mesos 金币
     * @param cashItems 现金物品列表
     * @param items 物品列表
     * @return 数据包
     */
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
            p.writeShort((short) quantity); // 数量 (现金物品 0 = 1)
            p.writeShort(0x1F); // 0 = ?, >=0x20 = ?, <0x20 = ? (无作用?)
            p.writeInt(itemPair.getRight());
        }
        p.writeInt(mesos);
        return p;
    }

    /**
     * 现金物品转蛋打开失败
     * @return 数据包
     */
    public static Packet onCashItemGachaponOpenFailed() {
        OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_CASH_ITEM_GACHAPON_RESULT);
        p.writeByte(0xE4);
        return p;
    }

    /**
     * 现金物品转蛋打开成功
     * @param accountid 账号ID
     * @param boxCashId 盒子现金ID
     * @param remainingBoxes 剩余盒子数
     * @param reward 奖励物品
     * @param rewardItemId 奖励物品ID
     * @param rewardQuantity 奖励数量
     * @param bJackpot 是否大奖
     * @return 数据包
     */
    public static Packet onCashGachaponOpenSuccess(int accountid, long boxCashId, int remainingBoxes, Item reward,
                                                   int rewardItemId, int rewardQuantity, boolean bJackpot) {
        OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_CASH_ITEM_GACHAPON_RESULT);
        p.writeByte(0xE5);   // 子操作码，感谢 Ubaware
        p.writeLong(boxCashId);
        p.writeInt(remainingBoxes);
        PacketHelper.addCashItemInformation(p, reward, accountid);
        p.writeInt(rewardItemId);
        p.writeByte(rewardQuantity); // 选中物品数量
        p.writeBool(bJackpot);// "现金转蛋大奖"
        return p;
    }

    /**
     * 发送世界转移规则
     * @param error 错误代码
     * @param c 客户端对象
     * @return 数据包
     */
    public static Packet sendWorldTransferRules(int error, Client c) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_CHECK_TRANSFER_WORLD_POSSIBLE_RESULT);
        p.writeInt(0); // 忽略
        p.writeByte(error);
        p.writeInt(0);
        p.writeBool(error == 0); // 0 = ?, 否则列出服务器
        if (error == 0) {
            List<World> worlds = Server.getInstance().getWorlds();
            p.writeInt(worlds.size());
            for (World world : worlds) {
                p.writeString(GameConstants.WORLD_NAMES[world.getId()]);
            }
        }
        return p;
    }

    /**
     * 显示世界转移成功
     * @param item 物品对象
     * @param accountId 账号ID
     * @return 数据包
     */
    public static Packet showWorldTransferSuccess(Item item, int accountId) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);
        p.writeByte(0xA0);
        PacketHelper.addCashItemInformation(p, item, accountId);
        return p;
    }

    /**
     * 显示世界转移取消
     * @param success 是否成功
     * @return 数据包
     */
    public static Packet showWorldTransferCancel(boolean success) {
        OutPacket p = OutPacket.create(SendOpcode.CANCEL_TRANSFER_WORLD_RESULT);
        p.writeBool(success);
        if (!success) {
            p.writeByte(0);
        }
        return p;
    }

    /**
     * 发送名称转移规则
     * @param error 错误代码
     * @return 数据包
     */
    public static Packet sendNameTransferRules(int error) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_CHECK_NAME_CHANGE_POSSIBLE_RESULT);
        p.writeInt(0);
        p.writeByte(error);
        p.writeInt(0);

        return p;
    }

    /**
     * 发送名称转移检查
     * @param availableName 可用名称
     * @param canUseName 是否可用
     * @return 数据包
     */
    public static Packet sendNameTransferCheck(String availableName, boolean canUseName) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_CHECK_NAME_CHANGE);
        // 将提供的名称发送回客户端，以添加到已检查和已接受名称的临时缓存中
        p.writeString(availableName);
        p.writeBool(!canUseName);
        return p;
    }

    /**
     * 显示名称更改成功
     * @param item 物品对象
     * @param accountId 账号ID
     * @return 数据包
     */
    public static Packet showNameChangeSuccess(Item item, int accountId) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_OPERATION);
        p.writeByte(0x9E);
        PacketHelper.addCashItemInformation(p, item, accountId);
        return p;
    }

    /**
     * 显示名称更改取消
     * @param success 是否成功
     * @return 数据包
     */
    public static Packet showNameChangeCancel(boolean success) {
        OutPacket p = OutPacket.create(SendOpcode.CANCEL_NAME_CHANGE_RESULT);
        p.writeBool(success);
        if (!success) {
            p.writeByte(0);
        }
        return p;
    }

    /**
     * 显示MTS点券
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet showMTSCash(Character chr) {
        final OutPacket p = OutPacket.create(SendOpcode.MTS_OPERATION2);
        p.writeInt(chr.getCashShop().getCash(CashShop.NX_PREPAID));
        p.writeInt(chr.getCashShop().getCash(CashShop.MAPLE_POINT));
        return p;
    }

    /**
     * 发送MTS
     * @param items 物品列表
     * @param tab 标签
     * @param type 类型
     * @param page 页码
     * @param pages 总页数
     * @return 数据包
     */
    public static Packet sendMTS(List<MTSItemInfo> items, int tab, int type, int page, int pages) {
        final OutPacket p = OutPacket.create(SendOpcode.MTS_OPERATION);
        p.writeByte(0x15); // 操作
        p.writeInt(pages * 16); // 测试中，如果失败请改为 10
        p.writeInt(items.size()); // 物品数量
        p.writeInt(tab);
        p.writeInt(type);
        p.writeInt(page);
        p.writeByte(1);
        p.writeByte(1);
        for (MTSItemInfo item : items) {
            PacketHelper.addItemInfo(p, item.getItem(), true);
            p.writeInt(item.getID()); // ID
            p.writeInt(item.getTaxes()); // 此项 + 下一项 = 价格
            p.writeInt(item.getPrice()); // 价格
            p.writeInt(0);
            p.writeLong(PacketHelper.getTime(item.getEndingDate()));
            p.writeString(item.getSeller()); // 账号名称 (Nexon 在想什么？)
            p.writeString(item.getSeller()); // 角色名称
            for (int j = 0; j < 28; j++) {
                p.writeByte(0);
            }
        }
        p.writeByte(1);
        return p;
    }

    /**
     * MTS求购列表结束
     * @param nx 点券
     * @param items 物品数
     * @return 数据包
     */
    public static Packet MTSWantedListingOver(int nx, int items) {
        final OutPacket p = OutPacket.create(SendOpcode.MTS_OPERATION);
        p.writeByte(0x3D);
        p.writeInt(nx);
        p.writeInt(items);
        return p;
    }

    /**
     * MTS确认出售
     * @return 数据包
     */
    public static Packet MTSConfirmSell() {
        final OutPacket p = OutPacket.create(SendOpcode.MTS_OPERATION);
        p.writeByte(0x1D);
        return p;
    }

    /**
     * MTS确认购买
     * @return 数据包
     */
    public static Packet MTSConfirmBuy() {
        final OutPacket p = OutPacket.create(SendOpcode.MTS_OPERATION);
        p.writeByte(0x33);
        return p;
    }

    /**
     * MTS购买失败
     * @return 数据包
     */
    public static Packet MTSFailBuy() {
        final OutPacket p = OutPacket.create(SendOpcode.MTS_OPERATION);
        p.writeByte(0x34);
        p.writeByte(0x42);
        return p;
    }

    /**
     * MTS确认转移
     * @param quantity 数量
     * @param pos 位置
     * @return 数据包
     */
    public static Packet MTSConfirmTransfer(int quantity, int pos) {
        final OutPacket p = OutPacket.create(SendOpcode.MTS_OPERATION);
        p.writeByte(0x27);
        p.writeInt(quantity);
        p.writeInt(pos);
        return p;
    }

    /**
     * 未售出物品
     * @param items 物品列表
     * @return 数据包
     */
    public static Packet notYetSoldInv(List<MTSItemInfo> items) {
        final OutPacket p = OutPacket.create(SendOpcode.MTS_OPERATION);
        p.writeByte(0x23);
        p.writeInt(items.size());
        if (!items.isEmpty()) {
            for (MTSItemInfo item : items) {
                PacketHelper.addItemInfo(p, item.getItem(), true);
                p.writeInt(item.getID()); // ID
                p.writeInt(item.getTaxes()); // 此项 + 下一项 = 价格
                p.writeInt(item.getPrice()); // 价格
                p.writeInt(0);
                p.writeLong(PacketHelper.getTime(item.getEndingDate()));
                p.writeString(item.getSeller()); // 账号名称 (Nexon 在想什么？)
                p.writeString(item.getSeller()); // 角色名称
                for (int i = 0; i < 28; i++) {
                    p.writeByte(0);
                }
            }
        } else {
            p.writeInt(0);
        }
        return p;
    }

    /**
     * 转移背包
     * @param items 物品列表
     * @return 数据包
     */
    public static Packet transferInventory(List<MTSItemInfo> items) {
        final OutPacket p = OutPacket.create(SendOpcode.MTS_OPERATION);
        p.writeByte(0x21);
        p.writeInt(items.size());
        if (!items.isEmpty()) {
            for (MTSItemInfo item : items) {
                PacketHelper.addItemInfo(p, item.getItem(), true);
                p.writeInt(item.getID()); // ID
                p.writeInt(item.getTaxes()); // 税费
                p.writeInt(item.getPrice()); // 价格
                p.writeInt(0);
                p.writeLong(PacketHelper.getTime(item.getEndingDate()));
                p.writeString(item.getSeller()); // 账号名称 (Nexon 在想什么？)
                p.writeString(item.getSeller()); // 角色名称
                for (int i = 0; i < 28; i++) {
                    p.writeByte(0);
                }
            }
        }
        p.writeByte(0xD0 + items.size());
        p.writeBytes(new byte[]{-1, -1, -1, 0});
        return p;
    }

    /**
     * 使用宝箱
     * @param type 类型
     * @return 数据包
     */
    public static Packet UseTreasureBox(int type){
        OutPacket p = OutPacket.create(SendOpcode.SUCCESS_IN_USE_GACHAPON_BOX);
        p.writeInt(type);
        return p;
    }
}
