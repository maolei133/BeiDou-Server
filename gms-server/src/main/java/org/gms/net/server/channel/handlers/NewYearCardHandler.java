/*
    This file is part of the HeavenMS MapleStory Server
    Copyleft (L) 2016 - 2019 RonanLana

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
import org.gms.client.inventory.Item;
import org.gms.dao.entity.CharactersDO;
import org.gms.dao.mapper.CharactersMapper;
import org.gms.model.pojo.NewYearCardRecord;
import org.gms.constants.id.ItemId;
import org.gms.constants.inventory.ItemConstants;
import org.gms.net.AbstractPacketHandler;
import org.gms.net.packet.InPacket;
import org.gms.net.server.Server;
import org.gms.util.PacketCreator;
import org.gms.util.SpringContextUtil;

/**
 * 新年贺卡处理器
 * @author Ronan
 * Header layout thanks to Eric
 */
public final class NewYearCardHandler extends AbstractPacketHandler {

    @Override
    public final void handlePacket(InPacket p, Client c) {
        final Character player = c.getPlayer();
        byte reqMode = p.readByte();

        if (reqMode == 0) {  // 发送贺卡
            if (player.haveItem(ItemId.NEW_YEARS_CARD)) {
                short slot = p.readShort();
                int itemid = p.readInt();

                int status = getValidNewYearCardStatus(itemid, player, slot);
                if (status == 0) {
                    if (player.canHold(ItemId.NEW_YEARS_CARD_SEND, 1)) {
                        String receiver = p.readString();

                        int receiverid = getReceiverId(receiver, c.getWorld());
                        if (receiverid != -1) {
                            if (receiverid != c.getPlayer().getId()) {
                                String message = p.readString();

                                NewYearCardRecord newyear = new NewYearCardRecord(player.getId(), player.getName(), receiverid, receiver, message);
                                NewYearCardRecord.saveNewYearCard(newyear);
                                player.addNewYearRecord(newyear);

                                player.getAbstractPlayerInteraction().gainItem(ItemId.NEW_YEARS_CARD, (short) -1);
                                player.getAbstractPlayerInteraction().gainItem(ItemId.NEW_YEARS_CARD_SEND, (short) 1);

                                Server.getInstance().setNewYearCard(newyear);
                                newyear.startNewYearCardTask();
                                player.sendPacket(PacketCreator.onNewYearCardRes(player, newyear, 4, 0));    // 发送成功
                            } else {
                                player.sendPacket(PacketCreator.onNewYearCardRes(player, -1, 5, 0xF));   // 不能发送给自己
                            }
                        } else {
                            player.sendPacket(PacketCreator.onNewYearCardRes(player, -1, 5, 0x13));  // 找不到该角色
                        }
                    } else {
                        player.sendPacket(PacketCreator.onNewYearCardRes(player, -1, 5, 0x10));  // 背包已满
                    }
                } else {
                    player.sendPacket(PacketCreator.onNewYearCardRes(player, -1, 5, status));  // 物品和背包错误
                }
            } else {
                player.sendPacket(PacketCreator.onNewYearCardRes(player, -1, 5, 0x11));  // 没有贺卡可发送
            }
        } else {    // 接收者接受贺卡
            int cardid = p.readInt();

            NewYearCardRecord newyear = NewYearCardRecord.loadNewYearCard(cardid);

            if (newyear != null && newyear.getReceiverId() == player.getId() && !newyear.isReceiverReceivedCard()) {
                if (!newyear.isSenderDiscardCard()) {
                    if (player.canHold(ItemId.NEW_YEARS_CARD_RECEIVED, 1)) {
                        newyear.stopNewYearCardTask();
                        NewYearCardRecord.updateNewYearCard(newyear);

                        player.getAbstractPlayerInteraction().gainItem(ItemId.NEW_YEARS_CARD_RECEIVED, (short) 1);
                        if (!newyear.getMessage().isEmpty()) {
                            player.dropMessage(6, "[新年] " + newyear.getSenderName() + ": " + newyear.getMessage());
                        }

                        player.addNewYearRecord(newyear);
                        player.sendPacket(PacketCreator.onNewYearCardRes(player, newyear, 6, 0));    // 接收成功

                        player.getMap().broadcastMessage(PacketCreator.onNewYearCardRes(player, newyear, 0xD, 0));

                        Character sender = c.getWorldServer().getPlayerStorage().getCharacterById(newyear.getSenderId());
                        if (sender != null && sender.isLoggedInWorld()) {
                            sender.getMap().broadcastMessage(PacketCreator.onNewYearCardRes(sender, newyear, 0xD, 0));
                            sender.dropMessage(6, "[新年] 您的收件人已成功收到新年贺卡。");
                        }
                    } else {
                        player.sendPacket(PacketCreator.onNewYearCardRes(player, -1, 5, 0x10));  // 背包已满
                    }
                } else {
                    player.dropMessage(6, "[新年] 新年贺卡的发送者已经丢弃了它。无法接收。");
                }
            } else {
                if (newyear == null) {
                    player.dropMessage(6, "[新年] 新年贺卡的发送者已经丢弃了它。无法接收。");
                }
            }
        }
    }

    private static int getReceiverId(String receiver, int world) {
        CharactersMapper mapper = SpringContextUtil.getBean(CharactersMapper.class);
        QueryWrapper query = QueryWrapper.create()
                .select(CharactersDO::getId, CharactersDO::getWorld)
                .where(CharactersDO::getName).like(receiver);

        CharactersDO result = mapper.selectOneByQuery(query);
        if (result != null && result.getWorld() == world) {
            return result.getId();
        }
        return -1;
    }

    private static int getValidNewYearCardStatus(int itemid, Character player, short slot) {
        if (!ItemConstants.isNewYearCardUse(itemid)) {
            return 0x14;
        }

        Item it = player.getInventory(ItemConstants.getInventoryType(itemid)).getItem(slot);
        return (it != null && it.getItemId() == itemid) ? 0 : 0x12;
    }
}
