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
import org.gms.client.inventory.Item;
import org.gms.config.GameConfig;
import org.gms.constants.id.NpcId;
import org.gms.dao.entity.MtsItemsDO;
import org.gms.dao.mapper.MtsItemsMapper;
import org.gms.net.AbstractPacketHandler;
import org.gms.net.packet.InPacket;
import org.gms.net.server.Server;
import org.gms.scripting.npc.NPCScriptManager;
import org.gms.server.MTSItemInfo;
import org.gms.server.maps.FieldLimit;
import org.gms.server.maps.MiniDungeonInfo;
import org.gms.util.PacketCreator;
import org.gms.util.SpringContextUtil;

import java.util.ArrayList;
import java.util.List;

public final class EnterMTSHandler extends AbstractPacketHandler {

    private static MtsItemsMapper mtsItemsMapper;

    static {
        mtsItemsMapper = SpringContextUtil.getBean(MtsItemsMapper.class);
    }

    @Override
    public void handlePacket(InPacket p, Client c) {
        Character chr = c.getPlayer();

        if (!GameConfig.getServerBoolean("use_mts")) {
            openCenterScript(c);
            return;
        }

        if (chr.getEventInstance() != null) {
            c.sendPacket(PacketCreator.serverNotice(5, "注册活动时禁止进入商城或拍卖行。"));
            c.sendPacket(PacketCreator.enableActions());
            return;
        }

        if (MiniDungeonInfo.isDungeonMap(chr.getMapId())) {
            c.sendPacket(PacketCreator.serverNotice(5, "在迷你副本中禁止切换频道或进入商城/拍卖行。"));
            c.sendPacket(PacketCreator.enableActions());
            return;
        }

        if (FieldLimit.CANNOTMIGRATE.check(chr.getMap().getFieldLimit())) {
            chr.dropMessage(1, "你不能在这个地图这样做。");
            c.sendPacket(PacketCreator.enableActions());
            return;
        }

        if (!chr.isAlive()) {
            c.sendPacket(PacketCreator.enableActions());
            return;
        }
        if (chr.getLevel() < 10) {
            c.sendPacket(PacketCreator.blockedMessage2(5));
            c.sendPacket(PacketCreator.enableActions());
            return;
        }

        chr.closePlayerInteractions();
        chr.closePartySearchInteractions();

        chr.unregisterChairBuff();
        Server.getInstance().getPlayerBuffStorage().addBuffsToStorage(chr.getId(), chr.getAllBuffs());
        Server.getInstance().getPlayerBuffStorage().addDiseasesToStorage(chr.getId(), chr.getAllDiseases());
        chr.setAwayFromChannelWorld();
        chr.notifyMapTransferToPartner(-1);
        chr.removeIncomingInvites();
        chr.cancelAllBuffs(true);
        chr.cancelAllDebuffs();
        chr.cancelBuffExpireTask();
        chr.cancelDiseaseExpireTask();
        chr.cancelSkillCooldownTask();
        chr.cancelExpirationTask();

        chr.forfeitExpirableQuests();
        chr.cancelQuestExpirationTask();

        chr.saveCharToDB();

        c.getChannelServer().removePlayer(chr);
        chr.getMap().removePlayer(c.getPlayer());
        try {
            c.sendPacket(PacketCreator.openCashShop(c, true));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        chr.getCashShop().open(true);// xD
        c.enableCSActions();
        c.sendPacket(PacketCreator.MTSWantedListingOver(0, 0));
        c.sendPacket(PacketCreator.showMTSCash(c.getPlayer()));
        List<MTSItemInfo> items = new ArrayList<>();
        int pages = 0;

        List<MtsItemsDO> result = mtsItemsMapper.selectListByQuery(
                QueryWrapper.create()
                        .where("tab = 1 AND transfer = 0")
                        .orderBy("id", false)
                        .limit(16, 16)
        );

        for (MtsItemsDO rs : result) {
            if (rs.getType() != 1) {
                Item i = new Item(rs.getItemid().intValue(), (short) 0, (short) rs.getQuantity().intValue());
                i.setOwner(rs.getOwner());
                items.add(new MTSItemInfo(i, rs.getPrice() + 100 + (int) (rs.getPrice() * 0.1), rs.getId().intValue(), rs.getSeller(), rs.getSellername(), rs.getSellEnds()));
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
                equip.setFlag(rs.getFlag() != null ? rs.getFlag().shortValue() : 0);
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
                equip.setExpiration(rs.getExpiration() != null ? rs.getExpiration() : -1);
                equip.setGiftFrom(rs.getGiftFrom());

                items.add(new MTSItemInfo(equip, rs.getPrice() + 100 + (int) (rs.getPrice() * 0.1), rs.getId().intValue(), rs.getSeller(), rs.getSellername(), rs.getSellEnds()));
            }
        }

        long count = mtsItemsMapper.selectCountByQuery(QueryWrapper.create());
        if (count > 0) {
            pages = (int) Math.ceil((double) count / 16);
        }

        c.sendPacket(PacketCreator.sendMTS(items, 1, 0, 0, pages));
        c.sendPacket(PacketCreator.transferInventory(getTransfer(chr.getId())));
        c.sendPacket(PacketCreator.notYetSoldInv(getNotYetSold(chr.getId())));
    }

    private List<MTSItemInfo> getNotYetSold(int cid) {
        List<MTSItemInfo> items = new ArrayList<>();
        List<MtsItemsDO> result = mtsItemsMapper.selectListByQuery(
                QueryWrapper.create()
                        .where("seller = ? AND transfer = 0", cid)
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

    private List<MTSItemInfo> getTransfer(int cid) {
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

    /**
     * 打开拍卖行脚本菜单中心
     *
     * @param c 客户端
     */
    private void openCenterScript(Client c) {
        NPCScriptManager.getInstance().start(c, NpcId.BEI_DOU_NPC_BASE, null);
    }
}
