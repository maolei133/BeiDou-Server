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
import org.gms.client.Family;
import org.gms.client.FamilyEntry;
import org.gms.config.GameConfig;
import org.gms.dao.entity.FamilyCharacterDO;
import org.gms.dao.mapper.CharactersMapper;
import org.gms.dao.mapper.FamilyCharacterMapper;
import org.gms.net.AbstractPacketHandler;
import org.gms.net.packet.InPacket;
import org.gms.net.server.coordinator.world.InviteCoordinator;
import org.gms.net.server.coordinator.world.InviteCoordinator.InviteResult;
import org.gms.net.server.coordinator.world.InviteCoordinator.InviteResultType;
import org.gms.net.server.coordinator.world.InviteCoordinator.InviteType;
import org.gms.util.PacketCreator;
import org.gms.util.SpringContextUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Jay Estrella
 * @author Ubaware
 */
public final class AcceptFamilyHandler extends AbstractPacketHandler {
    private static final Logger log = LoggerFactory.getLogger(AcceptFamilyHandler.class);

    private static FamilyCharacterMapper familyCharacterMapper;
    private static CharactersMapper charactersMapper;

    static {
        familyCharacterMapper = SpringContextUtil.getBean(FamilyCharacterMapper.class);
        charactersMapper = SpringContextUtil.getBean(CharactersMapper.class);
    }

    @Override
    public void handlePacket(InPacket p, Client c) {
        if (!GameConfig.getServerBoolean("use_family_system")) {
            return;
        }
        Character chr = c.getPlayer();
        int inviterId = p.readInt();
        p.readString();
        boolean accept = p.readByte() != 0;
        // String inviterName = slea.readMapleAsciiString();
        Character inviter = c.getWorldServer().getPlayerStorage().getCharacterById(inviterId);
        if (inviter != null) {
            InviteResult inviteResult = InviteCoordinator.answerInvite(InviteType.FAMILY, c.getPlayer().getId(), c.getPlayer(), accept);
            if (inviteResult.result == InviteResultType.NOT_FOUND) {
                return; //was never invited. (or expired on server only somehow?)
            }
            if (accept) {
                if (inviter.getFamily() != null) {
                    if (chr.getFamily() == null) {
                        FamilyEntry newEntry = new FamilyEntry(inviter.getFamily(), chr.getId(), chr.getName(), chr.getLevel(), chr.getJob());
                        newEntry.setCharacter(chr);
                        if (!newEntry.setSenior(inviter.getFamilyEntry(), true)) {
                            inviter.sendPacket(PacketCreator.sendFamilyMessage(1, 0));
                            return;
                        } else {
                            // save
                            inviter.getFamily().addEntry(newEntry);
                            insertNewFamilyRecord(chr.getId(), inviter.getFamily().getID(), inviter.getId(), false);
                        }
                    } else { //absorb target family
                        FamilyEntry targetEntry = chr.getFamilyEntry();
                        Family targetFamily = targetEntry.getFamily();
                        if (targetFamily.getLeader() != targetEntry) {
                            return;
                        }
                        if (inviter.getFamily().getTotalGenerations() + targetFamily.getTotalGenerations() <= GameConfig.getServerInt("family_max_generations")) {
                            targetEntry.join(inviter.getFamilyEntry());
                        } else {
                            inviter.sendPacket(PacketCreator.sendFamilyMessage(76, 0));
                            chr.sendPacket(PacketCreator.sendFamilyMessage(76, 0));
                            return;
                        }
                    }
                } else { // create new family
                    if (chr.getFamily() != null && inviter.getFamily() != null && chr.getFamily().getTotalGenerations() + inviter.getFamily().getTotalGenerations() >= GameConfig.getServerInt("family_max_generations")) {
                        inviter.sendPacket(PacketCreator.sendFamilyMessage(76, 0));
                        chr.sendPacket(PacketCreator.sendFamilyMessage(76, 0));
                        return;
                    }
                    Family newFamily = new Family(-1, c.getWorld());
                    c.getWorldServer().addFamily(newFamily.getID(), newFamily);
                    FamilyEntry inviterEntry = new FamilyEntry(newFamily, inviter.getId(), inviter.getName(), inviter.getLevel(), inviter.getJob());
                    inviterEntry.setCharacter(inviter);
                    newFamily.setLeader(inviter.getFamilyEntry());
                    newFamily.addEntry(inviterEntry);
                    if (chr.getFamily() == null) { //completely new family
                        FamilyEntry newEntry = new FamilyEntry(newFamily, chr.getId(), chr.getName(), chr.getLevel(), chr.getJob());
                        newEntry.setCharacter(chr);
                        newEntry.setSenior(inviterEntry, true);
                        // save new family
                        insertNewFamilyRecord(inviter.getId(), newFamily.getID(), 0, true);
                        insertNewFamilyRecord(chr.getId(), newFamily.getID(), inviter.getId(), false); // char was already saved from setSenior() above
                        newFamily.setMessage("", true);
                    } else { //new family for inviter, absorb invitee family
                        insertNewFamilyRecord(inviter.getId(), newFamily.getID(), 0, true);
                        newFamily.setMessage("", true);
                        chr.getFamilyEntry().join(inviterEntry);
                    }
                }
                c.getPlayer().getFamily().broadcast(PacketCreator.sendFamilyJoinResponse(true, c.getPlayer().getName()), c.getPlayer().getId());
                c.sendPacket(PacketCreator.getSeniorMessage(inviter.getName()));
                c.sendPacket(PacketCreator.getFamilyInfo(chr.getFamilyEntry()));
                chr.getFamilyEntry().updateSeniorFamilyInfo(true);
            } else {
                inviter.sendPacket(PacketCreator.sendFamilyJoinResponse(false, c.getPlayer().getName()));
            }
        }
        c.sendPacket(PacketCreator.sendFamilyMessage(0, 0));
    }

    private static void insertNewFamilyRecord(int characterID, int familyID, int seniorID, boolean updateChar) {
        try {
            FamilyCharacterDO familyCharacterDO = new FamilyCharacterDO();
            familyCharacterDO.setCid(characterID);
            familyCharacterDO.setFamilyid(familyID);
            familyCharacterDO.setSeniorid(seniorID);
            familyCharacterDO.setReputation(0);
            familyCharacterDO.setTodaysrep(0);
            familyCharacterDO.setTotalreputation(0);
            familyCharacterDO.setReptosenior(0);
            familyCharacterDO.setPrecepts("");
            familyCharacterDO.setLastresettime(System.currentTimeMillis());
            familyCharacterMapper.insert(familyCharacterDO);
        } catch (Exception e) {
            log.error("无法保存角色ID {} 的新家族记录", characterID, e);
        }
        if (updateChar) {
            try {
                charactersMapper.updateFamilyId(characterID, familyID);
            } catch (Exception e) {
                log.error("无法更新角色ID {} 的家族ID记录", characterID, e);
            }
        }
    }
}
