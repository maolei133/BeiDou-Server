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
package org.gms.scripting.portal;

import org.gms.client.Client;
import org.gms.dao.entity.CharactersDO;
import org.gms.manager.ServerManager;
import org.gms.scripting.AbstractPlayerInteraction;
import org.gms.scripting.map.MapScriptManager;
import org.gms.server.maps.Portal;
import org.gms.service.CharacterService;
import org.gms.util.PacketCreator;

import java.util.List;

public class PortalPlayerInteraction extends AbstractPlayerInteraction {
    private final Portal portal;
    private static final CharacterService characterService = ServerManager.getApplicationContext().getBean(CharacterService.class);

    public PortalPlayerInteraction(Client c, Portal portal) {
        super(c);
        this.portal = portal;
    }

    public Portal getPortal() {
        return portal;
    }

    public void runMapScript() {
        MapScriptManager msm = MapScriptManager.getInstance();
        msm.runMapScript(c, "onUserEnter/" + portal.getScriptName(), false);
    }

    public boolean hasLevel30Character() {
        List<CharactersDO> characters = characterService.getCharactersByAccountId(getPlayer().getAccountId());
        for (CharactersDO character : characters) {
            if (character.getLevel() >= 30) {
                return true;
            }
        }
        return getPlayer().getLevel() >= 30;
    }

    public void blockPortal() {
        c.getPlayer().blockPortal(getPortal().getScriptName());
    }

    public void unblockPortal() {
        c.getPlayer().unblockPortal(getPortal().getScriptName());
    }

    public void playPortalSound() {
        c.sendPacket(PacketCreator.playPortalSound());
    }
}
