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
package org.gms.net.server.handlers.login;

import org.gms.client.Client;
import org.gms.client.Family;
import org.gms.dao.entity.CharactersDO;
import org.gms.manager.ServerManager;
import org.gms.net.AbstractPacketHandler;
import org.gms.net.packet.InPacket;
import org.gms.net.server.Server;
import org.gms.service.CharacterService;
import org.gms.service.WorldTransferService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.gms.util.PacketCreator;

public final class DeleteCharHandler extends AbstractPacketHandler {
    private static final Logger log = LoggerFactory.getLogger(DeleteCharHandler.class);
    private static final CharacterService characterService = ServerManager.getApplicationContext().getBean(CharacterService.class);
    private static final WorldTransferService worldTransferService = ServerManager.getApplicationContext().getBean(WorldTransferService.class);

    @Override
    public void handlePacket(InPacket p, Client c) {
        String pic = p.readString();
        int cid = p.readInt();
        if (c.checkPic(pic)) {
            CharactersDO charactersDO = characterService.findById(cid);
            if (charactersDO == null) {
                c.sendPacket(PacketCreator.deleteCharResponse(cid, 0x09));
                return;
            }

            int world = charactersDO.getWorld();
            int guildId = charactersDO.getGuildid();
            int guildRank = charactersDO.getGuildrank();
            int familyId = charactersDO.getFamilyId();

            if (guildId != 0 && guildRank <= 1) {
                c.sendPacket(PacketCreator.deleteCharResponse(cid, 0x16));
                return;
            } else if (familyId != -1) {
                Family family = Server.getInstance().getWorld(world).getFamily(familyId);
                if (family != null && family.getTotalMembers() > 1) {
                    c.sendPacket(PacketCreator.deleteCharResponse(cid, 0x1D));
                    return;
                }
            }

            if (worldTransferService.isCharacterInTransfer(cid)) {
                c.sendPacket(PacketCreator.deleteCharResponse(cid, 0x1A));
                return;
            }

            if (c.deleteCharacter(cid, c.getAccID())) {
                log.info("账号 {} 删除了角色 ID {}", c.getAccountName(), cid);
                c.sendPacket(PacketCreator.deleteCharResponse(cid, 0));
            } else {
                c.sendPacket(PacketCreator.deleteCharResponse(cid, 0x09));
            }
        } else {
            c.sendPacket(PacketCreator.deleteCharResponse(cid, 0x14));
        }
    }
}
