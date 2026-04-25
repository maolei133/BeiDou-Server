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

import org.apache.logging.log4j.message.MapMessage;
import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.autoban.AutobanManager;
import org.gms.net.AbstractPacketHandler;
import org.gms.net.packet.InPacket;
import org.gms.server.logging.AuditLogger;
import org.gms.server.logging.LogAction;
import org.gms.server.logging.LogModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.gms.server.maps.MapObject;

import java.awt.*;

/**
 * @author Matze
 * @author Ronan
 */
public final class ItemPickupHandler extends AbstractPacketHandler {
    private static final Logger log = LoggerFactory.getLogger(ItemPickupHandler.class);

    @Override
    public void handlePacket(final InPacket p, final Client c) {
        int timestamp = p.readInt(); //Timestamp
        p.readByte();
        p.readPos(); //cpos
        int oid = p.readInt();
        Character chr = c.getPlayer();
        MapObject ob = chr.getMap().getMapObject(oid);
        if (ob == null) {
            return;
        }

        AutobanManager abm = chr.getAutoBanManager();
        abm.checkActionFrequency(AutobanManager.ActionType.ITEM_PICKUP, timestamp, 5);

        Point charPos = chr.getPosition();
        Point obPos = ob.getPosition();
        if (Math.abs(charPos.getX() - obPos.getX()) > 800 || Math.abs(charPos.getY() - obPos.getY()) > 600) {
            log.warn("角色 {} 尝试拾取距离过远的物品。地图ID: {}, 玩家位置: {}, 物品位置: {}",
                    c.getPlayer().getName(), chr.getMapId(), charPos, obPos);
            AuditLogger.info(LogModule.AUTOBAN, LogAction.AUTOBAN_CHEAT_WARNING, new MapMessage().with("msg", "拾取物品距离过远").with("map", chr.getMapId()).with("pos", charPos).with("objPos", obPos));
            return;
        }

        chr.pickupItem(ob);
    }
}
