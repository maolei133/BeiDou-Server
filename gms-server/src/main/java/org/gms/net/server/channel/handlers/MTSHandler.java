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

import com.mybatisflex.core.query.QueryWrapper;
import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.inventory.Equip;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.manipulator.InventoryManipulator;
import org.gms.constants.inventory.ItemConstants;
import org.gms.dao.entity.CharactersDO;
import org.gms.dao.entity.MtsCartDO;
import org.gms.dao.entity.MtsItemsDO;
import org.gms.dao.mapper.AccountsMapper;
import org.gms.dao.mapper.CharactersMapper;
import org.gms.dao.mapper.MtsCartMapper;
import org.gms.dao.mapper.MtsItemsMapper;
import org.gms.net.AbstractPacketHandler;
import org.gms.net.packet.InPacket;
import org.gms.net.packet.Packet;
import org.gms.net.server.Server;
import org.gms.net.server.channel.Channel;
import org.gms.server.CashShop;
import org.gms.server.ItemInformationProvider;
import org.gms.server.MTSItemInfo;
import org.gms.util.PacketCreator;
import org.gms.util.Pair;
import org.gms.util.SpringContextUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public final class MTSHandler extends AbstractPacketHandler {
    private static final Logger log = LoggerFactory.getLogger(MTSHandler.class);

    private static MtsItemsMapper mtsItemsMapper;
    private static MtsCartMapper mtsCartMapper;
    private static CharactersMapper charactersMapper;
    private static AccountsMapper accountsMapper;

    static {
        mtsItemsMapper = SpringContextUtil.getBean(MtsItemsMapper.class);
        mtsCartMapper = SpringContextUtil.getBean(MtsCartMapper.class);
        charactersMapper = SpringContextUtil.getBean(CharactersMapper.class);
        accountsMapper = SpringContextUtil.getBean(AccountsMapper.class);
    }

    @Override
    public void handlePacket(InPacket p, Client c) {
        // TODO add karma-to-untradeable flag on sold items here

        if (!c.getPlayer().getCashShop().isOpened()) {
            return;
        }
        if (p.available() > 0) {
            byte op = p.readByte();
            switch (op) {
            case 2: { //put item up for sale
                byte itemtype = p.readByte();
                int itemid = p.readInt();
                p.readShort();
                p.skip(7);
                short stars = 1;
                if (itemtype == 1) {
                    p.skip(32);
                } else {
                    stars = p.readShort();
                }
                p.readString(); // another useless thing (owner)
                if (itemtype == 1) {
                    p.skip(32);
                } else {
                    p.readShort();
                }
                short slot;
                short quantity;
                if (itemtype != 1) {
                    if (itemid / 10000 == 207 || itemid / 10000 == 233) {
                        p.skip(8);
                    }
                    slot = (short) p.readInt();
                } else {
                    slot = (short) p.readInt();
                }
                if (itemtype != 1) {
                    if (itemid / 10000 == 207 || itemid / 10000 == 233) {
                        quantity = stars;
                        p.skip(4);
                    } else {
                        quantity = (short) p.readInt();
                    }
                } else {
                    quantity = (byte) p.readInt();
                }
                int price = p.readInt();
                if (itemtype == 1) {
                    quantity = 1;
                }
                if (quantity < 0 || price < 110 || c.getPlayer().getItemQuantity(itemid, false) < quantity) {
                    return;
                }
                InventoryType invType = ItemConstants.getInventoryType(itemid);
                Item i = c.getPlayer().getInventory(invType).getItem(slot).copy();
                if (i != null && c.getPlayer().getMeso() >= 5000) {
                    long count = mtsItemsMapper.selectCountByQuery(QueryWrapper.create().where("seller = ?", c.getPlayer().getId()));
                    if (count > 10) { // They have more than 10 items up for sale already!
                        c.getPlayer().dropMessage(1, "您已经有 10 件物品在拍卖了！");
                        c.sendPacket(getMTS(1, 0, 0));
                        c.sendPacket(PacketCreator.transferInventory(getTransfer(c.getPlayer().getId())));
                        c.sendPacket(PacketCreator.notYetSoldInv(getNotYetSold(c.getPlayer().getId())));
                        return;
                    }

                    LocalDate now = LocalDate.now();
                    LocalDate sellEnd = now.plusDays(7);
                    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
                    String date = sellEnd.format(formatter);

                    MtsItemsDO mtsItem = new MtsItemsDO();
                    mtsItem.setTab(1);
                    mtsItem.setType((int) invType.getType());
                    mtsItem.setItemid((long) i.getItemId());
                    mtsItem.setQuantity((int) quantity);
                    mtsItem.setExpiration(i.getExpiration());
                    mtsItem.setGiftFrom(i.getGiftFrom());
                    mtsItem.setSeller(c.getPlayer().getId());
                    mtsItem.setPrice(price);
                    mtsItem.setOwner(i.getOwner());
                    mtsItem.setSellername(c.getPlayer().getName());
                    mtsItem.setSellEnds(date);
                    mtsItem.setTransfer(0); // Default value

                    if (i.getInventoryType().equals(InventoryType.EQUIP)) {
                        Equip equip = (Equip) i;
                        mtsItem.setUpgradeslots((int) equip.getUpgradeSlots());
                        mtsItem.setLevel((int) equip.getLevel());
                        mtsItem.setStr((int) equip.getStr());
                        mtsItem.setDex((int) equip.getDex());
                        mtsItem.setInte((int) equip.getInt());
                        mtsItem.setLuk((int) equip.getLuk());
                        mtsItem.setHp((int) equip.getHp());
                        mtsItem.setMp((int) equip.getMp());
                        mtsItem.setWatk((int) equip.getWatk());
                        mtsItem.setMatk((int) equip.getMatk());
                        mtsItem.setWdef((int) equip.getWdef());
                        mtsItem.setMdef((int) equip.getMdef());
                        mtsItem.setAcc((int) equip.getAcc());
                        mtsItem.setAvoid((int) equip.getAvoid());
                        mtsItem.setHands((int) equip.getHands());
                        mtsItem.setSpeed((int) equip.getSpeed());
                        mtsItem.setJump((int) equip.getJump());
                        mtsItem.setLocked(0);
                        mtsItem.setVicious((long) equip.getVicious());
                        mtsItem.setFlag((long) equip.getFlag());
                        mtsItem.setItemexp((long) equip.getItemExp());
                        mtsItem.setItemlevel((int) equip.getItemLevel());
                        mtsItem.setRingid(equip.getRingId());
                    }

                    mtsItemsMapper.insert(mtsItem);
                    InventoryManipulator.removeFromSlot(c, invType, slot, quantity, false);

                    c.getPlayer().gainMeso(-5000, false);
                    c.sendPacket(PacketCreator.MTSConfirmSell());
                    c.sendPacket(getMTS(1, 0, 0));
                    c.enableCSActions();
                    c.sendPacket(PacketCreator.transferInventory(getTransfer(c.getPlayer().getId())));
                    c.sendPacket(PacketCreator.notYetSoldInv(getNotYetSold(c.getPlayer().getId())));
                }
                break;
            }
            case 3: //send offer for wanted item
                break;
            case 4: //list wanted item
                p.readInt();
                p.readInt();
                p.readInt();
                p.readShort();
                p.readString();
                break;
            case 5: { //change page
                int tab = p.readInt();
                int type = p.readInt();
                int page = p.readInt();
                c.getPlayer().changePage(page);
                if (tab == 4 && type == 0) {
                    c.sendPacket(getCart(c.getPlayer().getId()));
                } else if (tab == c.getPlayer().getCurrentTab() && type == c.getPlayer().getCurrentType() && c.getPlayer().getSearch() != null) {
                    c.sendPacket(getMTSSearch(tab, type, c.getPlayer().getCi(), c.getPlayer().getSearch(), page));
                } else {
                    c.getPlayer().setSearch(null);
                    c.sendPacket(getMTS(tab, type, page));
                }
                c.getPlayer().changeTab(tab);
                c.getPlayer().changeType(type);
                c.enableCSActions();
                c.sendPacket(PacketCreator.transferInventory(getTransfer(c.getPlayer().getId())));
                c.sendPacket(PacketCreator.notYetSoldInv(getNotYetSold(c.getPlayer().getId())));
                break;
            }
            case 6: { //search
                int tab = p.readInt();
                int type = p.readInt();
                p.readInt();
                int ci = p.readInt();
                String search = p.readString();
                c.getPlayer().setSearch(search);
                c.getPlayer().changeTab(tab);
                c.getPlayer().changeType(type);
                c.getPlayer().changeCI(ci);
                c.enableCSActions();
                c.sendPacket(PacketCreator.enableActions());
                c.sendPacket(getMTSSearch(tab, type, ci, search, c.getPlayer().getCurrentPage()));
                c.sendPacket(PacketCreator.showMTSCash(c.getPlayer()));
                c.sendPacket(PacketCreator.transferInventory(getTransfer(c.getPlayer().getId())));
                c.sendPacket(PacketCreator.notYetSoldInv(getNotYetSold(c.getPlayer().getId())));
                break;
            }
            case 7: { //cancel sale
                int id = p.readInt(); // id of the item
                MtsItemsDO updateItem = new MtsItemsDO();
                updateItem.setTransfer(1);
                mtsItemsMapper.updateByQuery(updateItem,
                        QueryWrapper.create().where("id = ? AND seller = ?", id, c.getPlayer().getId()));

                mtsCartMapper.deleteByQuery(QueryWrapper.create().where("itemid = ?", id));

                c.enableCSActions();
                c.sendPacket(getMTS(c.getPlayer().getCurrentTab(), c.getPlayer().getCurrentType(),
                        c.getPlayer().getCurrentPage()));
                c.sendPacket(PacketCreator.notYetSoldInv(getNotYetSold(c.getPlayer().getId())));
                c.sendPacket(PacketCreator.transferInventory(getTransfer(c.getPlayer().getId())));
                break;
            }
            case 8: { // transfer item from transfer inv.
                int id = p.readInt(); // id of the item
                MtsItemsDO itemDO = mtsItemsMapper.selectOneByQuery(
                        QueryWrapper.create()
                                .where("seller = ? AND transfer = 1 AND id = ?", c.getPlayer().getId(), id)
                                .orderBy("id", false)
                );

                if (itemDO != null) {
                    Item i;
                    if (itemDO.getType() != 1) {
                        Item ii = new Item(itemDO.getItemid().intValue(), (short) 0, (short) itemDO.getQuantity().intValue());
                        ii.setOwner(itemDO.getOwner());
                        ii.setPosition(
                                c.getPlayer().getInventory(ItemConstants.getInventoryType(itemDO.getItemid().intValue()))
                                        .getNextFreeSlot());
                        i = ii.copy();
                    } else {
                        Equip equip = new Equip(itemDO.getItemid().intValue(), (byte) itemDO.getPosition().intValue(), -1);
                        equip.setOwner(itemDO.getOwner());
                        equip.setQuantity((short) 1);
                        equip.setAcc(itemDO.getAcc() != null ? itemDO.getAcc().shortValue() : 0);
                        equip.setAvoid(itemDO.getAvoid() != null ? itemDO.getAvoid().shortValue() : 0);
                        equip.setDex(itemDO.getDex() != null ? itemDO.getDex().shortValue() : 0);
                        equip.setHands(itemDO.getHands() != null ? itemDO.getHands().shortValue() : 0);
                        equip.setHp(itemDO.getHp() != null ? itemDO.getHp().shortValue() : 0);
                        equip.setInt(itemDO.getInte() != null ? itemDO.getInte().shortValue() : 0);
                        equip.setJump(itemDO.getJump() != null ? itemDO.getJump().shortValue() : 0);
                        equip.setLuk(itemDO.getLuk() != null ? itemDO.getLuk().shortValue() : 0);
                        equip.setMatk(itemDO.getMatk() != null ? itemDO.getMatk().shortValue() : 0);
                        equip.setMdef(itemDO.getMdef() != null ? itemDO.getMdef().shortValue() : 0);
                        equip.setMp(itemDO.getMp() != null ? itemDO.getMp().shortValue() : 0);
                        equip.setSpeed(itemDO.getSpeed() != null ? itemDO.getSpeed().shortValue() : 0);
                        equip.setStr(itemDO.getStr() != null ? itemDO.getStr().shortValue() : 0);
                        equip.setWatk(itemDO.getWatk() != null ? itemDO.getWatk().shortValue() : 0);
                        equip.setWdef(itemDO.getWdef() != null ? itemDO.getWdef().shortValue() : 0);
                        equip.setUpgradeSlots(itemDO.getUpgradeslots() != null ? itemDO.getUpgradeslots().byteValue() : 0);
                        equip.setLevel(itemDO.getLevel() != null ? itemDO.getLevel().byteValue() : 0);
                        equip.setItemLevel(itemDO.getItemlevel() != null ? itemDO.getItemlevel().byteValue() : 0);
                        equip.setItemExp(itemDO.getItemexp() != null ? itemDO.getItemexp().intValue() : 0);
                        equip.setRingId(itemDO.getRingid() != null ? itemDO.getRingid() : -1);
                        equip.setVicious(itemDO.getVicious() != null ? itemDO.getVicious().byteValue() : 0);
                        equip.setFlag(itemDO.getFlag() != null ? itemDO.getFlag().shortValue() : 0);
                        equip.setExpiration(itemDO.getExpiration() != null ? itemDO.getExpiration() : -1);
                        equip.setGiftFrom(itemDO.getGiftFrom());
                        equip.setPosition(
                                c.getPlayer().getInventory(ItemConstants.getInventoryType(itemDO.getItemid().intValue()))
                                        .getNextFreeSlot());
                        i = equip.copy();
                    }

                    mtsItemsMapper.deleteByQuery(
                            QueryWrapper.create()
                                    .where("id = ? AND seller = ? AND transfer = 1", id, c.getPlayer().getId())
                    );

                    InventoryManipulator.addFromDrop(c, i, false);
                    c.enableCSActions();
                    c.sendPacket(getCart(c.getPlayer().getId()));
                    c.sendPacket(getMTS(c.getPlayer().getCurrentTab(), c.getPlayer().getCurrentType(),
                            c.getPlayer().getCurrentPage()));
                    c.sendPacket(PacketCreator.MTSConfirmTransfer(i.getQuantity(), i.getPosition()));
                    c.sendPacket(PacketCreator.transferInventory(getTransfer(c.getPlayer().getId())));
                }
                break;
            }
            case 9: { //add to cart
                int id = p.readInt(); // id of the item
                MtsItemsDO item = mtsItemsMapper.selectOneByQuery(
                        QueryWrapper.create().where("id = ? AND seller <> ?", id, c.getPlayer().getId())
                );

                if (item != null) {
                    MtsCartDO existingCart = mtsCartMapper.selectOneByQuery(
                            QueryWrapper.create().where("cid = ? AND itemid = ?", c.getPlayer().getId(), id)
                    );

                    if (existingCart == null) {
                        MtsCartDO newCart = new MtsCartDO();
                        newCart.setCid(c.getPlayer().getId());
                        newCart.setItemid(id);
                        mtsCartMapper.insert(newCart);
                    }
                }

                c.sendPacket(getMTS(c.getPlayer().getCurrentTab(), c.getPlayer().getCurrentType(), c.getPlayer().getCurrentPage()));
                c.enableCSActions();
                c.sendPacket(PacketCreator.enableActions());
                c.sendPacket(PacketCreator.transferInventory(getTransfer(c.getPlayer().getId())));
                c.sendPacket(PacketCreator.notYetSoldInv(getNotYetSold(c.getPlayer().getId())));
                break;
            }
            case 10: { //delete from cart
                int id = p.readInt(); // id of the item
                mtsCartMapper.deleteByQuery(
                        QueryWrapper.create().where("itemid = ? AND cid = ?", id, c.getPlayer().getId())
                );

                c.sendPacket(getCart(c.getPlayer().getId()));
                c.enableCSActions();
                c.sendPacket(PacketCreator.transferInventory(getTransfer(c.getPlayer().getId())));
                c.sendPacket(PacketCreator.notYetSoldInv(getNotYetSold(c.getPlayer().getId())));
                break;
            }
            case 12: //put item up for auction
                break;
            case 13: //cancel wanted cart thing
                break;
            case 14: //buy auction item now
                break;
            case 16: { //buy
                int id = p.readInt(); // id of the item
                MtsItemsDO itemDO = mtsItemsMapper.selectOneByQuery(
                        QueryWrapper.create().where("id = ?", id).orderBy("id", false)
                );

                if (itemDO != null) {
                    int price = itemDO.getPrice() + 100 + (int) (itemDO.getPrice() * 0.1); // taxes
                    if (c.getPlayer().getCashShop().getCash(CashShop.NX_PREPAID) >= price) { // FIX
                        boolean alwaysnull = true;
                        for (Channel cserv : Server.getInstance().getAllChannels()) {
                            Character victim = cserv.getPlayerStorage().getCharacterById(itemDO.getSeller());
                            if (victim != null) {
                                victim.getCashShop().gainCash(4, itemDO.getPrice());
                                alwaysnull = false;
                            }
                        }
                        if (alwaysnull) {
                            CharactersDO sellerChar = charactersMapper.selectOneById(itemDO.getSeller());
                            if (sellerChar != null) {
                                accountsMapper.addNxPrepaid(sellerChar.getAccountid(), itemDO.getPrice());
                            }
                        }

                        MtsItemsDO updateItem = new MtsItemsDO();
                        updateItem.setSeller(c.getPlayer().getId());
                        updateItem.setTransfer(1);
                        mtsItemsMapper.updateByQuery(updateItem, QueryWrapper.create().where("id = ?", id));

                        mtsCartMapper.deleteByQuery(QueryWrapper.create().where("itemid = ?", id));

                        c.getPlayer().getCashShop().gainCash(4, -price);
                        c.enableCSActions();
                        c.sendPacket(getMTS(c.getPlayer().getCurrentTab(), c.getPlayer().getCurrentType(),c.getPlayer().getCurrentPage()));
                        c.sendPacket(PacketCreator.MTSConfirmBuy());
                        c.sendPacket(PacketCreator.showMTSCash(c.getPlayer()));
                        c.sendPacket(PacketCreator.transferInventory(getTransfer(c.getPlayer().getId())));
                        c.sendPacket(PacketCreator.notYetSoldInv(getNotYetSold(c.getPlayer().getId())));
                        c.sendPacket(PacketCreator.enableActions());
                    } else {
                        c.sendPacket(PacketCreator.MTSFailBuy());
                    }
                } else {
                    c.sendPacket(PacketCreator.MTSFailBuy());
                }
                break;
            }
            case 17: { //buy from cart
                int id = p.readInt(); // id of the item
                MtsItemsDO itemDO = mtsItemsMapper.selectOneByQuery(
                        QueryWrapper.create().where("id = ?", id).orderBy("id", false)
                );

                if (itemDO != null) {
                    int price = itemDO.getPrice() + 100 + (int) (itemDO.getPrice() * 0.1);
                    if (c.getPlayer().getCashShop().getCash(CashShop.NX_PREPAID) >= price) {
                        for (Channel cserv : Server.getInstance().getAllChannels()) {
                            Character victim = cserv.getPlayerStorage().getCharacterById(itemDO.getSeller());
                            if (victim != null) {
                                victim.getCashShop().gainCash(CashShop.NX_PREPAID, itemDO.getPrice());
                            } else {
                                CharactersDO sellerChar = charactersMapper.selectOneById(itemDO.getSeller());
                                if (sellerChar != null) {
                                    accountsMapper.addNxPrepaid(sellerChar.getAccountid(), itemDO.getPrice());
                                }
                            }
                        }

                        MtsItemsDO updateItem = new MtsItemsDO();
                        updateItem.setSeller(c.getPlayer().getId());
                        updateItem.setTransfer(1);
                        mtsItemsMapper.updateByQuery(updateItem, QueryWrapper.create().where("id = ?", id));

                        mtsCartMapper.deleteByQuery(QueryWrapper.create().where("itemid = ?", id));

                        c.getPlayer().getCashShop().gainCash(4, -price);
                        c.sendPacket(getCart(c.getPlayer().getId()));
                        c.enableCSActions();
                        c.sendPacket(PacketCreator.MTSConfirmBuy());
                        c.sendPacket(PacketCreator.showMTSCash(c.getPlayer()));
                        c.sendPacket(PacketCreator.transferInventory(getTransfer(c.getPlayer().getId())));
                        c.sendPacket(PacketCreator.notYetSoldInv(getNotYetSold(c.getPlayer().getId())));
                    } else {
                        c.sendPacket(PacketCreator.MTSFailBuy());
                    }
                } else {
                    c.sendPacket(PacketCreator.MTSFailBuy());
                }
                break;
            }
            default:
                log.warn("未处理的操作码 (MTS): {}, 数据包: {}", op, p);
                break;
            }
        } else {
            c.sendPacket(PacketCreator.showMTSCash(c.getPlayer()));
        }
    }

    public List<MTSItemInfo> getNotYetSold(int cid) {
        List<MTSItemInfo> items = new ArrayList<>();
        List<MtsItemsDO> result = mtsItemsMapper.selectListByQuery(
                QueryWrapper.create()
                        .where("seller = ? AND transfer = 0", cid)
                        .orderBy("id", false)
        );

        for (MtsItemsDO rs : result) {
            if (rs.getType() != 1) {
                Item i = new Item(rs.getItemid().intValue(), (byte) 0, (short) rs.getQuantity().intValue());
                i.setOwner(rs.getOwner());
                items.add(new MTSItemInfo(i, rs.getPrice(), rs.getId().intValue(), rs.getSeller(), rs.getSellername(), rs.getSellEnds()));
            } else {
                Equip equip = new Equip(rs.getItemid().intValue(), (byte) rs.getPosition().intValue(), -1);
                equip.setOwner(rs.getOwner());
                equip.setQuantity((short) 1);
                equip.setAcc(rs.getAcc() != null ? rs.getAcc().shortValue() : 0);
                equip.setAvoid(rs.getAvoid() != null ? rs.getAvoid().shortValue() : 0);
                equip.setDex(rs.getDex() != null ? rs.getDex().shortValue() : 0);
                equip.setHands(rs.getHands() != null ? rs.getHands().shortValue() : 0);
                equip.setHp(rs.getHp() != null ? rs.getHp().shortValue() : 0);
                equip.setInt(rs.getInte() != null ? rs.getInte().shortValue() : 0);
                equip.setJump(rs.getJump() != null ? rs.getJump().shortValue() : 0);
                equip.setVicious(rs.getVicious() != null ? rs.getVicious().byteValue() : 0);
                equip.setLuk(rs.getLuk() != null ? rs.getLuk().shortValue() : 0);
                equip.setMatk(rs.getMatk() != null ? rs.getMatk().shortValue() : 0);
                equip.setMdef(rs.getMdef() != null ? rs.getMdef().shortValue() : 0);
                equip.setMp(rs.getMp() != null ? rs.getMp().shortValue() : 0);
                equip.setSpeed(rs.getSpeed() != null ? rs.getSpeed().shortValue() : 0);
                equip.setStr(rs.getStr() != null ? rs.getStr().shortValue() : 0);
                equip.setWatk(rs.getWatk() != null ? rs.getWatk().shortValue() : 0);
                equip.setWdef(rs.getWdef() != null ? rs.getWdef().shortValue() : 0);
                equip.setUpgradeSlots(rs.getUpgradeslots() != null ? rs.getUpgradeslots().byteValue() : 0);
                equip.setLevel(rs.getLevel() != null ? rs.getLevel().byteValue() : 0);
                equip.setFlag(rs.getFlag() != null ? rs.getFlag().shortValue() : 0);
                equip.setItemLevel(rs.getItemlevel() != null ? rs.getItemlevel().byteValue() : 0);
                equip.setItemExp(rs.getItemexp() != null ? rs.getItemexp().intValue() : 0);
                equip.setRingId(rs.getRingid() != null ? rs.getRingid() : -1);
                equip.setExpiration(rs.getExpiration() != null ? rs.getExpiration() : -1);
                equip.setGiftFrom(rs.getGiftFrom());
                items.add(new MTSItemInfo(equip, rs.getPrice(), rs.getId().intValue(), rs.getSeller(), rs.getSellername(), rs.getSellEnds()));
            }
        }
        return items;
    }

    public Packet getCart(int cid) {
        List<MTSItemInfo> items = new ArrayList<>();
        int pages = 0;

        List<MtsCartDO> cartList = mtsCartMapper.selectListByQuery(
                QueryWrapper.create().where("cid = ?", cid).orderBy("id", false)
        );

        for (MtsCartDO cart : cartList) {
            MtsItemsDO rse = mtsItemsMapper.selectOneById(cart.getItemid());
            if (rse != null) {
                if (rse.getType() != 1) {
                    Item i = new Item(rse.getItemid().intValue(), (short) 0, (short) rse.getQuantity().intValue());
                    i.setOwner(rse.getOwner());
                    items.add(new MTSItemInfo(i, rse.getPrice(), rse.getId().intValue(),
                            rse.getSeller(), rse.getSellername(), rse.getSellEnds()));
                } else {
                    Equip equip = new Equip(rse.getItemid().intValue(), (byte) rse.getPosition().intValue(), -1);
                    equip.setOwner(rse.getOwner());
                    equip.setQuantity((short) 1);
                    equip.setAcc(rse.getAcc() != null ? rse.getAcc().shortValue() : 0);
                    equip.setAvoid(rse.getAvoid() != null ? rse.getAvoid().shortValue() : 0);
                    equip.setDex(rse.getDex() != null ? rse.getDex().shortValue() : 0);
                    equip.setHands(rse.getHands() != null ? rse.getHands().shortValue() : 0);
                    equip.setHp(rse.getHp() != null ? rse.getHp().shortValue() : 0);
                    equip.setInt(rse.getInte() != null ? rse.getInte().shortValue() : 0);
                    equip.setJump(rse.getJump() != null ? rse.getJump().shortValue() : 0);
                    equip.setVicious(rse.getVicious() != null ? rse.getVicious().byteValue() : 0);
                    equip.setLuk(rse.getLuk() != null ? rse.getLuk().shortValue() : 0);
                    equip.setMatk(rse.getMatk() != null ? rse.getMatk().shortValue() : 0);
                    equip.setMdef(rse.getMdef() != null ? rse.getMdef().shortValue() : 0);
                    equip.setMp(rse.getMp() != null ? rse.getMp().shortValue() : 0);
                    equip.setSpeed(rse.getSpeed() != null ? rse.getSpeed().shortValue() : 0);
                    equip.setStr(rse.getStr() != null ? rse.getStr().shortValue() : 0);
                    equip.setWatk(rse.getWatk() != null ? rse.getWatk().shortValue() : 0);
                    equip.setWdef(rse.getWdef() != null ? rse.getWdef().shortValue() : 0);
                    equip.setUpgradeSlots(rse.getUpgradeslots() != null ? rse.getUpgradeslots().byteValue() : 0);
                    equip.setLevel(rse.getLevel() != null ? rse.getLevel().byteValue() : 0);
                    equip.setItemLevel(rse.getItemlevel() != null ? rse.getItemlevel().byteValue() : 0);
                    equip.setItemExp(rse.getItemexp() != null ? rse.getItemexp().intValue() : 0);
                    equip.setRingId(rse.getRingid() != null ? rse.getRingid() : -1);
                    equip.setFlag(rse.getFlag() != null ? rse.getFlag().shortValue() : 0);
                    equip.setExpiration(rse.getExpiration() != null ? rse.getExpiration() : -1);
                    equip.setGiftFrom(rse.getGiftFrom());
                    items.add(new MTSItemInfo(equip, rse.getPrice(), rse.getId().intValue(),
                            rse.getSeller(), rse.getSellername(), rse.getSellEnds()));
                }
            }
        }

        long count = mtsCartMapper.selectCountByQuery(QueryWrapper.create().where("cid = ?", cid));
        if (count > 0) {
            pages = (int) (count / 16);
            if (count % 16 > 0) {
                pages += 1;
            }
        }

        return PacketCreator.sendMTS(items, 4, 0, 0, pages);
    }

    public List<MTSItemInfo> getTransfer(int cid) {
        List<MTSItemInfo> items = new ArrayList<>();
        List<MtsItemsDO> result = mtsItemsMapper.selectListByQuery(
                QueryWrapper.create()
                        .where("transfer = 1 AND seller = ?", cid)
                        .orderBy("id", false)
        );

        for (MtsItemsDO rs : result) {
            if (rs.getType() != 1) {
                Item i = new Item(rs.getItemid().intValue(), (short) 0, (short) rs.getQuantity().intValue());
                i.setOwner(rs.getOwner());
                items.add(new MTSItemInfo(i, rs.getPrice(), rs.getId().intValue(), rs.getSeller(), rs.getSellername(), rs.getSellEnds()));
            } else {
                Equip equip = new Equip(rs.getItemid().intValue(), (byte) rs.getPosition().intValue(), -1);
                equip.setOwner(rs.getOwner());
                equip.setQuantity((short) 1);
                equip.setAcc(rs.getAcc() != null ? rs.getAcc().shortValue() : 0);
                equip.setAvoid(rs.getAvoid() != null ? rs.getAvoid().shortValue() : 0);
                equip.setDex(rs.getDex() != null ? rs.getDex().shortValue() : 0);
                equip.setHands(rs.getHands() != null ? rs.getHands().shortValue() : 0);
                equip.setHp(rs.getHp() != null ? rs.getHp().shortValue() : 0);
                equip.setInt(rs.getInte() != null ? rs.getInte().shortValue() : 0);
                equip.setJump(rs.getJump() != null ? rs.getJump().shortValue() : 0);
                equip.setVicious(rs.getVicious() != null ? rs.getVicious().byteValue() : 0);
                equip.setLuk(rs.getLuk() != null ? rs.getLuk().shortValue() : 0);
                equip.setMatk(rs.getMatk() != null ? rs.getMatk().shortValue() : 0);
                equip.setMdef(rs.getMdef() != null ? rs.getMdef().shortValue() : 0);
                equip.setMp(rs.getMp() != null ? rs.getMp().shortValue() : 0);
                equip.setSpeed(rs.getSpeed() != null ? rs.getSpeed().shortValue() : 0);
                equip.setStr(rs.getStr() != null ? rs.getStr().shortValue() : 0);
                equip.setWatk(rs.getWatk() != null ? rs.getWatk().shortValue() : 0);
                equip.setWdef(rs.getWdef() != null ? rs.getWdef().shortValue() : 0);
                equip.setUpgradeSlots(rs.getUpgradeslots() != null ? rs.getUpgradeslots().byteValue() : 0);
                equip.setLevel(rs.getLevel() != null ? rs.getLevel().byteValue() : 0);
                equip.setItemLevel(rs.getItemlevel() != null ? rs.getItemlevel().byteValue() : 0);
                equip.setItemExp(rs.getItemexp() != null ? rs.getItemexp().intValue() : 0);
                equip.setRingId(rs.getRingid() != null ? rs.getRingid() : -1);
                equip.setFlag(rs.getFlag() != null ? rs.getFlag().shortValue() : 0);
                equip.setExpiration(rs.getExpiration() != null ? rs.getExpiration() : -1);
                equip.setGiftFrom(rs.getGiftFrom());
                items.add(new MTSItemInfo(equip, rs.getPrice(), rs.getId().intValue(), rs.getSeller(), rs.getSellername(), rs.getSellEnds()));
            }
        }
        return items;
    }

    private static Packet getMTS(int tab, int type, int page) {
        List<MTSItemInfo> items = new ArrayList<>();
        int pages = 0;

        QueryWrapper query = QueryWrapper.create()
                .where("tab = ? AND transfer = 0", tab);

        if (type != 0) {
            query.and("type = ?", type);
        }

        long count = mtsItemsMapper.selectCountByQuery(query);
        if (count > 0) {
            pages = (int) (count / 16);
            if (count % 16 > 0) {
                pages++;
            }
        }

        query.orderBy("id", false).limit(page * 16, 16);
        List<MtsItemsDO> result = mtsItemsMapper.selectListByQuery(query);

        for (MtsItemsDO rs : result) {
            if (rs.getType() != 1) {
                Item i = new Item(rs.getItemid().intValue(), (short) 0, (short) rs.getQuantity().intValue());
                i.setOwner(rs.getOwner());
                items.add(new MTSItemInfo(i, rs.getPrice(), rs.getId().intValue(), rs.getSeller(),
                        rs.getSellername(), rs.getSellEnds()));
            } else {
                Equip equip = new Equip(rs.getItemid().intValue(), (byte) rs.getPosition().intValue(), -1);
                equip.setOwner(rs.getOwner());
                equip.setQuantity((short) 1);
                equip.setAcc(rs.getAcc() != null ? rs.getAcc().shortValue() : 0);
                equip.setAvoid(rs.getAvoid() != null ? rs.getAvoid().shortValue() : 0);
                equip.setDex(rs.getDex() != null ? rs.getDex().shortValue() : 0);
                equip.setHands(rs.getHands() != null ? rs.getHands().shortValue() : 0);
                equip.setHp(rs.getHp() != null ? rs.getHp().shortValue() : 0);
                equip.setInt(rs.getInte() != null ? rs.getInte().shortValue() : 0);
                equip.setJump(rs.getJump() != null ? rs.getJump().shortValue() : 0);
                equip.setVicious(rs.getVicious() != null ? rs.getVicious().byteValue() : 0);
                equip.setLuk(rs.getLuk() != null ? rs.getLuk().shortValue() : 0);
                equip.setMatk(rs.getMatk() != null ? rs.getMatk().shortValue() : 0);
                equip.setMdef(rs.getMdef() != null ? rs.getMdef().shortValue() : 0);
                equip.setMp(rs.getMp() != null ? rs.getMp().shortValue() : 0);
                equip.setSpeed(rs.getSpeed() != null ? rs.getSpeed().shortValue() : 0);
                equip.setStr(rs.getStr() != null ? rs.getStr().shortValue() : 0);
                equip.setWatk(rs.getWatk() != null ? rs.getWatk().shortValue() : 0);
                equip.setWdef(rs.getWdef() != null ? rs.getWdef().shortValue() : 0);
                equip.setUpgradeSlots(rs.getUpgradeslots() != null ? rs.getUpgradeslots().byteValue() : 0);
                equip.setLevel(rs.getLevel() != null ? rs.getLevel().byteValue() : 0);
                equip.setItemLevel(rs.getItemlevel() != null ? rs.getItemlevel().byteValue() : 0);
                equip.setItemExp(rs.getItemexp() != null ? rs.getItemexp().intValue() : 0);
                equip.setRingId(rs.getRingid() != null ? rs.getRingid() : -1);
                equip.setFlag(rs.getFlag() != null ? rs.getFlag().shortValue() : 0);
                equip.setExpiration(rs.getExpiration() != null ? rs.getExpiration() : -1);
                equip.setGiftFrom(rs.getGiftFrom());
                items.add(new MTSItemInfo(equip, rs.getPrice(), rs.getId().intValue(), rs.getSeller(), rs.getSellername(), rs.getSellEnds()));
            }
        }
        return PacketCreator.sendMTS(items, tab, type, page, pages); // resniff
    }

    public Packet getMTSSearch(int tab, int type, int cOi, String search, int page) {
        List<MTSItemInfo> items = new ArrayList<>();
        ItemInformationProvider ii = ItemInformationProvider.getInstance();
        
        QueryWrapper query = QueryWrapper.create()
                .where("tab = ? AND transfer = 0", tab);

        if (type != 0) {
            query.and("type = ?", type);
        }

        if (cOi != 0) {
            List<Integer> itemIds = new ArrayList<>();
            for (Pair<Integer, String> itemPair : ii.getAllItems()) {
                if (itemPair.getRight().toLowerCase().contains(search.toLowerCase())) {
                    itemIds.add(itemPair.getLeft());
                }
            }
            if (!itemIds.isEmpty()) {
                query.and("itemid IN (?)", itemIds);
            } else {
                // 如果没有匹配的物品ID，则添加一个不可能的条件，确保查询结果为空
                query.and("itemid = 0");
            }
        } else {
            query.and("sellername LIKE ?", "%" + search + "%");
        }

        int pages = 0;
        if (type == 0) {
            long count = mtsItemsMapper.selectCountByQuery(query);
            if (count > 0) {
                pages = (int) (count / 16);
                if (count % 16 > 0) {
                    pages++;
                }
            }
        }

        query.orderBy("id", false).limit(page * 16, 16);
        List<MtsItemsDO> result = mtsItemsMapper.selectListByQuery(query);

        for (MtsItemsDO rs : result) {
            if (rs.getType() != 1) {
                Item i = new Item(rs.getItemid().intValue(), (short) 0, (short) rs.getQuantity().intValue());
                i.setOwner(rs.getOwner());
                items.add(new MTSItemInfo(i, rs.getPrice(), rs.getId().intValue(), rs.getSeller(), rs.getSellername(), rs.getSellEnds()));
            } else {
                Equip equip = new Equip(rs.getItemid().intValue(), (byte) rs.getPosition().intValue(), -1);
                equip.setOwner(rs.getOwner());
                equip.setQuantity((short) 1);
                equip.setAcc(rs.getAcc() != null ? rs.getAcc().shortValue() : 0);
                equip.setAvoid(rs.getAvoid() != null ? rs.getAvoid().shortValue() : 0);
                equip.setDex(rs.getDex() != null ? rs.getDex().shortValue() : 0);
                equip.setHands(rs.getHands() != null ? rs.getHands().shortValue() : 0);
                equip.setHp(rs.getHp() != null ? rs.getHp().shortValue() : 0);
                equip.setInt(rs.getInte() != null ? rs.getInte().shortValue() : 0);
                equip.setJump(rs.getJump() != null ? rs.getJump().shortValue() : 0);
                equip.setVicious(rs.getVicious() != null ? rs.getVicious().byteValue() : 0);
                equip.setLuk(rs.getLuk() != null ? rs.getLuk().shortValue() : 0);
                equip.setMatk(rs.getMatk() != null ? rs.getMatk().shortValue() : 0);
                equip.setMdef(rs.getMdef() != null ? rs.getMdef().shortValue() : 0);
                equip.setMp(rs.getMp() != null ? rs.getMp().shortValue() : 0);
                equip.setSpeed(rs.getSpeed() != null ? rs.getSpeed().shortValue() : 0);
                equip.setStr(rs.getStr() != null ? rs.getStr().shortValue() : 0);
                equip.setWatk(rs.getWatk() != null ? rs.getWatk().shortValue() : 0);
                equip.setWdef(rs.getWdef() != null ? rs.getWdef().shortValue() : 0);
                equip.setUpgradeSlots(rs.getUpgradeslots() != null ? rs.getUpgradeslots().byteValue() : 0);
                equip.setLevel(rs.getLevel() != null ? rs.getLevel().byteValue() : 0);
                equip.setItemLevel(rs.getItemlevel() != null ? rs.getItemlevel().byteValue() : 0);
                equip.setItemExp(rs.getItemexp() != null ? rs.getItemexp().intValue() : 0);
                equip.setRingId(rs.getRingid() != null ? rs.getRingid() : -1);
                equip.setFlag(rs.getFlag() != null ? rs.getFlag().shortValue() : 0);
                equip.setExpiration(rs.getExpiration() != null ? rs.getExpiration() : -1);
                equip.setGiftFrom(rs.getGiftFrom());
                items.add(new MTSItemInfo(equip, rs.getPrice(), rs.getId().intValue(), rs.getSeller(), rs.getSellername(), rs.getSellEnds()));
            }
        }
        return PacketCreator.sendMTS(items, tab, type, page, pages);
    }
}
