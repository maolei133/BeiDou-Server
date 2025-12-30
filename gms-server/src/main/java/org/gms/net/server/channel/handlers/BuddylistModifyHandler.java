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
import org.gms.client.BuddyList;
import org.gms.client.BuddyList.BuddyAddResult;
import org.gms.client.BuddyList.BuddyOperation;
import org.gms.client.BuddylistEntry;
import org.gms.client.Character;
import org.gms.client.CharacterNameAndId;
import org.gms.client.Client;
import org.gms.dao.entity.BuddiesDO;
import org.gms.dao.entity.CharactersDO;
import org.gms.dao.mapper.BuddiesMapper;
import org.gms.dao.mapper.CharactersMapper;
import org.gms.net.AbstractPacketHandler;
import org.gms.net.packet.InPacket;
import org.gms.net.server.world.World;
import org.gms.util.PacketCreator;
import org.gms.util.SpringContextUtil;

public class BuddylistModifyHandler extends AbstractPacketHandler {
    private static class CharacterIdNameBuddyCapacity extends CharacterNameAndId {
        private final int buddyCapacity;

        public CharacterIdNameBuddyCapacity(int id, String name, int buddyCapacity) {
            super(id, name);
            this.buddyCapacity = buddyCapacity;
        }

        public int getBuddyCapacity() {
            return buddyCapacity;
        }
    }

    private void nextPendingRequest(Client c) {
        CharacterNameAndId pendingBuddyRequest = c.getPlayer().getBuddylist().pollPendingRequest();
        if (pendingBuddyRequest != null) {
            c.sendPacket(PacketCreator.requestBuddylistAdd(pendingBuddyRequest.getId(), c.getPlayer().getId(), pendingBuddyRequest.getName()));
        }
    }

    private CharacterIdNameBuddyCapacity getCharacterIdAndNameFromDatabase(String name) {
        CharactersMapper mapper = SpringContextUtil.getBean(CharactersMapper.class);
        if (mapper != null) {
            CharactersDO character = mapper.selectOneByQuery(
                    new QueryWrapper()
                            .select(CharactersDO::getId, CharactersDO::getName, CharactersDO::getBuddyCapacity)
                            .where(CharactersDO::getName).like(name)
            );
            
            if (character != null) {
                return new CharacterIdNameBuddyCapacity(character.getId(), character.getName(), character.getBuddyCapacity());
            }
        }
        return null;
    }

    @Override
    public void handlePacket(InPacket p, Client c) {
        int mode = p.readByte();
        Character player = c.getPlayer();
        BuddyList buddylist = player.getBuddylist();
        if (mode == 1) { // 添加
            String addName = p.readString();
            String group = p.readString();
            if (group.length() > 16 || addName.length() < 2 || addName.length() > 13) {
                return; // 非法操作
            }
            BuddylistEntry ble = buddylist.get(addName);
            if (ble != null && !ble.isVisible() && group.equals(ble.getGroup())) {
                c.sendPacket(PacketCreator.serverNotice(1, "你的好友列表中已经有 \"" + ble.getName() + "\" 了"));
            } else if (buddylist.isFull() && ble == null) {
                c.sendPacket(PacketCreator.serverNotice(1, "你的好友列表已满"));
            } else if (ble == null) {
                try {
                    World world = c.getWorldServer();
                    CharacterIdNameBuddyCapacity charWithId;
                    int channel;
                    Character otherChar = c.getChannelServer().getPlayerStorage().getCharacterByName(addName);
                    if (otherChar != null) {
                        channel = c.getChannel();
                        charWithId = new CharacterIdNameBuddyCapacity(otherChar.getId(), otherChar.getName(), otherChar.getBuddylist().getCapacity());
                    } else {
                        channel = world.find(addName);
                        charWithId = getCharacterIdAndNameFromDatabase(addName);
                    }
                    if (charWithId != null) {
                        BuddyAddResult buddyAddResult = null;
                        if (channel != -1) {
                            buddyAddResult = world.requestBuddyAdd(addName, c.getChannel(), player.getId(), player.getName());
                        } else {
                            BuddiesMapper buddiesMapper = SpringContextUtil.getBean(BuddiesMapper.class);
                            if (buddiesMapper != null) {
                                long buddyCount = buddiesMapper.selectCountByQuery(
                                        new QueryWrapper()
                                                .eq(BuddiesDO::getCharacterid, charWithId.getId())
                                                .eq(BuddiesDO::getPending, 0)
                                );
                                
                                if (buddyCount >= charWithId.getBuddyCapacity()) {
                                    buddyAddResult = BuddyAddResult.BUDDYLIST_FULL;
                                }

                                BuddiesDO existing = buddiesMapper.selectOneByQuery(
                                        new QueryWrapper()
                                                .eq(BuddiesDO::getCharacterid, charWithId.getId())
                                                .eq(BuddiesDO::getBuddyid, player.getId())
                                );
                                
                                if (existing != null) {
                                    buddyAddResult = BuddyAddResult.ALREADY_ON_LIST;
                                }
                            }
                        }
                        if (buddyAddResult == BuddyAddResult.BUDDYLIST_FULL) {
                            c.sendPacket(PacketCreator.serverNotice(1, "\"" + addName + "\" 的好友列表已满"));
                        } else {
                            int displayChannel;
                            displayChannel = -1;
                            int otherCid = charWithId.getId();
                            if (buddyAddResult == BuddyAddResult.ALREADY_ON_LIST && channel != -1) {
                                displayChannel = channel;
                                notifyRemoteChannel(c, channel, otherCid, BuddyOperation.ADDED);
                            } else if (buddyAddResult != BuddyAddResult.ALREADY_ON_LIST && channel == -1) {
                                BuddiesMapper buddiesMapper = SpringContextUtil.getBean(BuddiesMapper.class);
                                if (buddiesMapper != null) {
                                    BuddiesDO newBuddy = new BuddiesDO();
                                    newBuddy.setCharacterid(charWithId.getId());
                                    newBuddy.setBuddyid(player.getId());
                                    newBuddy.setPending(1);
                                    buddiesMapper.insert(newBuddy);
                                }
                            }
                            buddylist.put(new BuddylistEntry(charWithId.getName(), group, otherCid, displayChannel, true));
                            c.sendPacket(PacketCreator.updateBuddylist(buddylist.getBuddies()));
                        }
                    } else {
                        c.sendPacket(PacketCreator.serverNotice(1, "名为 \"" + addName + "\" 的角色不存在"));
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } else {
                ble.changeGroup(group);
                c.sendPacket(PacketCreator.updateBuddylist(buddylist.getBuddies()));
            }
        } else if (mode == 2) { // 接受好友
            int otherCid = p.readInt();
            if (!buddylist.isFull()) {
                try {
                    int channel = c.getWorldServer().find(otherCid);
                    String otherName = null;
                    Character otherChar = c.getChannelServer().getPlayerStorage().getCharacterById(otherCid);
                    if (otherChar == null) {
                        CharactersMapper mapper = SpringContextUtil.getBean(CharactersMapper.class);
                        if (mapper != null) {
                            CharactersDO character = mapper.selectOneById(otherCid);
                            if (character != null) {
                                otherName = character.getName();
                            }
                        }
                    } else {
                        otherName = otherChar.getName();
                    }
                    if (otherName != null) {
                        buddylist.put(new BuddylistEntry(otherName, "默认分组", otherCid, channel, true));
                        c.sendPacket(PacketCreator.updateBuddylist(buddylist.getBuddies()));
                        notifyRemoteChannel(c, channel, otherCid, BuddyOperation.ADDED);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            nextPendingRequest(c);
        } else if (mode == 3) { // 删除
            int otherCid = p.readInt();
            player.deleteBuddy(otherCid);
        }
    }

    private void notifyRemoteChannel(Client c, int remoteChannel, int otherCid, BuddyOperation operation) {
        Character player = c.getPlayer();
        if (remoteChannel != -1) {
            c.getWorldServer().buddyChanged(otherCid, player.getId(), player.getName(), c.getChannel(), operation);
        }
    }
}
