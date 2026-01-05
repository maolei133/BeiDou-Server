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
import org.gms.server.life.LifeFactory;
import org.gms.server.life.Monster;
import org.gms.server.maps.MapleMap;
import org.gms.service.PlifeService;
import org.gms.util.I18nUtil;

import java.awt.*;

public class PmobCommand extends Command {
    private static final PlifeService plifeService = ServerManager.getApplicationContext().getBean(PlifeService.class);

    {
        setDescription(I18nUtil.getMessage("PmobCommand.message1"));
    }

    @Override
    public void execute(Client c, String[] params) {
        Character player = c.getPlayer();
        if (params.length < 1) {
            player.yellowMessage(I18nUtil.getMessage("PmobCommand.message2"));
            return;
        }

        // command suggestion thanks to HighKey21, none, bibiko94 (TAYAMO), asafgb
        int mapId = player.getMapId();
        int mobId = Integer.parseInt(params[0]);
        int mobTime = (params.length > 1) ? Integer.parseInt(params[1]) : -1;

        Point checkpos = player.getMap().getGroundBelow(player.getPosition());
        int xpos = checkpos.x;
        int ypos = checkpos.y;
        int fh = player.getMap().getFootholds().findBelow(checkpos).getId();

        Monster mob = LifeFactory.getMonster(mobId);
        if (mob != null && !mob.getName().equals("MISSINGNO")) {
            mob.setPosition(checkpos);
            mob.setCy(ypos);
            mob.setRx0(xpos + 50);
            mob.setRx1(xpos - 50);
            mob.setFh(fh);
            try {
                plifeService.addPmob(player.getWorld(), mapId, mobId, mobTime, checkpos, fh);

                for (Channel ch : player.getWorldServer().getChannels()) {
                    MapleMap map = ch.getMapFactory().getMap(mapId);
                    map.addMonsterSpawn(mob, mobTime, -1);
                    map.addAllMonsterSpawn(mob, mobTime, -1);
                }

                player.yellowMessage(I18nUtil.getMessage("PmobCommand.message3"));
            } catch (Exception e) {
                e.printStackTrace();
                player.dropMessage(5, I18nUtil.getMessage("PmobCommand.message4"));
            }
        } else {
            player.dropMessage(5, I18nUtil.getMessage("PmobCommand.message5"));
        }
    }
}
