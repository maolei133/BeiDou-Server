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
   @Author: Arthur L - Refactored command content into modules
*/
package org.gms.client.command.commands.gm4;

import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.command.Command;
import org.gms.cheat.core.CheatManager;
import org.gms.cheat.plugin.MobVacPlugin;
import org.gms.util.I18nUtil;

public class MobVacCommand extends Command {
    {
        setDescription("吸怪功能 - （BOSS除外）");
    }

    @Override
    public void execute(Client c, String[] params) {
        Character player = c.getPlayer();
        
        // 获取作弊管理器
        CheatManager cheatManager = player.getCheatManager();
        if (cheatManager == null) {
            player.dropMessage(5, "无法获取内置辅助管理器。");
            return;
        }
        
        // 获取吸怪插件
        MobVacPlugin mobVacPlugin = cheatManager.getPlugin("MobVac");
        if (mobVacPlugin == null) {
            player.dropMessage(5, "吸怪插件未注册。");
            return;
        }
        
        // 切换吸怪功能状态
        if (mobVacPlugin.isRunning()) {
            mobVacPlugin.stop();
            player.dropMessage(5, "吸怪功能已关闭。");
        } else {
            // 启动插件并调用吸怪功能
            mobVacPlugin.start();
            boolean started = mobVacPlugin.startMobVac();
            if (!started) {
                // 如果启动失败，则停止插件
                mobVacPlugin.stop();
                player.dropMessage(5, "吸怪功能启动失败。");
            } else {
                player.dropMessage(5, "吸怪功能已开启。");
            }
        }
    }
}