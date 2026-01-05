/*
    This file is part of the HeavenMS MapleStory Server, commands OdinMS-based
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

/*
   @Author: Ronan
*/
package org.gms.client.command.commands.gm4;

import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.command.Command;
import org.gms.manager.ServerManager;
import org.gms.net.server.channel.Channel;
import org.gms.server.maps.MapleMap;
import org.gms.service.PlifeService;
import org.gms.util.I18nUtil;
import org.gms.util.Pair;

import java.awt.*;
import java.util.List;

public class PmobRemoveCommand extends Command {
    private static final PlifeService plifeService = ServerManager.getApplicationContext().getBean(PlifeService.class);

    {
        setDescription(I18nUtil.getMessage("PmobRemoveCommand.message1"));
    }

    @Override
    public void execute(Client c, String[] params) {
        Character player = c.getPlayer();

        int mapId = player.getMapId();
        int mobId = params.length > 0 ? Integer.parseInt(params[0]) : -1;

        Point pos = player.getPosition();

        List<Pair<Integer, Pair<Integer, Integer>>> toRemove = plifeService.removePmob(player.getWorld(), mapId, mobId, pos);

        if (!toRemove.isEmpty()) {
            for (Channel ch : player.getWorldServer().getChannels()) {
                MapleMap map = ch.getMapFactory().getMap(mapId);

                for (Pair<Integer, Pair<Integer, Integer>> r : toRemove) {
                    map.removeMonsterSpawn(r.getLeft(), r.getRight().getLeft(), r.getRight().getRight());
                    map.removeAllMonsterSpawn(r.getLeft(), r.getRight().getLeft(), r.getRight().getRight());
                }
            }
        }

        player.yellowMessage(I18nUtil.getMessage("PmobRemoveCommand.message3", toRemove.size()));
    }
}
