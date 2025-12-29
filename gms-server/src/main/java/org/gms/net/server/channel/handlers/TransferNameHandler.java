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
import org.gms.config.GameConfig;
import org.gms.dao.entity.NamechangesDO;
import org.gms.dao.mapper.NamechangesMapper;
import org.gms.net.AbstractPacketHandler;
import org.gms.net.packet.InPacket;
import org.gms.util.PacketCreator;
import org.gms.util.SpringContextUtil;

import java.sql.Timestamp;
import java.util.Calendar;
import java.util.List;

import static java.util.concurrent.TimeUnit.DAYS;

/**
 * @author Ronan
 * @author Ubaware
 */
public final class TransferNameHandler extends AbstractPacketHandler {

    @Override
    public final void handlePacket(InPacket p, Client c) {
        p.readInt(); //cid
        int birthday = p.readInt();
        if (!CashOperationHandler.checkBirthday(c, birthday)) {
            c.sendPacket(PacketCreator.showCashShopMessage((byte) 0xC4));
            c.sendPacket(PacketCreator.enableActions());
            return;
        }
        if (!GameConfig.getServerBoolean("allow_cash_shop_name_change")) {
            c.sendPacket(PacketCreator.sendNameTransferRules(4));
            return;
        }
        Character chr = c.getPlayer();
        if (chr.getLevel() < 10) {
            c.sendPacket(PacketCreator.sendNameTransferRules(4));
            return;
        } else if (c.getTempBanCalendar() != null && c.getTempBanCalendar().getTimeInMillis() + DAYS.toMillis(30) < Calendar.getInstance().getTimeInMillis()) {
            c.sendPacket(PacketCreator.sendNameTransferRules(2));
            return;
        }
        
        // DAO 改造
        NamechangesMapper mapper = SpringContextUtil.getBean(NamechangesMapper.class);
        if (mapper != null) {
            List<NamechangesDO> list = mapper.selectListByQuery(
                    new QueryWrapper().select("completionTime").eq("characterid", chr.getId())
            );
            
            for (NamechangesDO record : list) {
                Timestamp completedTimestamp = record.getCompletionTime();
                if (completedTimestamp == null) { //has pending name request
                    c.sendPacket(PacketCreator.sendNameTransferRules(1));
                    return;
                } else if (completedTimestamp.getTime() + GameConfig.getServerLong("name_change_cooldown") > System.currentTimeMillis()) {
                    c.sendPacket(PacketCreator.sendNameTransferRules(3));
                    return;
                }
            }
        }

        c.sendPacket(PacketCreator.sendNameTransferRules(0));
    }
}
