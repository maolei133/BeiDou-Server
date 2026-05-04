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
import org.gms.config.GameConfig;
import org.gms.net.AbstractPacketHandler;
import org.gms.net.packet.InPacket;
import org.gms.net.server.coordinator.world.InviteCoordinator;
import org.gms.net.server.coordinator.world.InviteCoordinator.InviteType;
import org.gms.util.PacketCreator;

/**
 * @author Jay Estrella
 * @author Ubaware
 */
public final class FamilyAddHandler extends AbstractPacketHandler {
    @Override
    public final void handlePacket(InPacket p, Client c) {
        if (!GameConfig.getServerBoolean("use_family_system")) {
            return;
        }
        String toAdd = p.readString();
        Character addChr = c.getChannelServer().getPlayerStorage().getCharacterByName(toAdd);
        Character chr = c.getPlayer();
        if (addChr == null) {
            c.sendPacket(PacketCreator.sendFamilyMessage(65, 0));
        } else if (addChr == chr) { // 只能通过数据包编辑/客户端编辑实现？
            c.sendPacket(PacketCreator.enableActions());
        } else if (addChr.getMap() != chr.getMap() || (addChr.isHidden()) && chr.gmLevel() < addChr.gmLevel()) {
            c.sendPacket(PacketCreator.sendFamilyMessage(69, 0));
        } else if (addChr.getLevel() <= 10) {
            c.sendPacket(PacketCreator.sendFamilyMessage(77, 0));
        } else if (Math.abs(addChr.getLevel() - chr.getLevel()) > 20) {
            c.sendPacket(PacketCreator.sendFamilyMessage(72, 0));
        } else if (addChr.getFamily() != null && addChr.getFamily() == chr.getFamily()) { // 同一家族
            c.sendPacket(PacketCreator.enableActions());
        } else if (InviteCoordinator.hasInvite(InviteType.FAMILY, addChr.getId())) {
            c.sendPacket(PacketCreator.sendFamilyMessage(73, 0));
        } else if (chr.getFamily() != null && addChr.getFamily() != null && addChr.getFamily().getTotalGenerations() + chr.getFamily().getTotalGenerations() > GameConfig.getServerInt("family_max_generations")) {
            c.sendPacket(PacketCreator.sendFamilyMessage(76, 0));
        } else {
            // 在发送邀请之前检查潜在的循环
            if (chr.getFamilyEntry() != null && addChr.getFamilyEntry() != null) {
                 // 如果我邀请某人，他们不能是我的长辈（祖先）
                 // 如果我们假设树结构得到维护，这个检查有点多余，但为了安全起见是好的。
                 // 更重要的是，如果我们合并家族，我们需要确保不会产生循环。
                 // 但是，在这个阶段（邀请），我们可能不会进行完整的循环检查，因为昂贵的操作应该延迟。
                 // 但我们可以做一个快速检查，看看他们是否已经以某种会导致问题的方式相关联。
                 // 实际上，主要的循环检查应该在 AcceptFamilyHandler 或 FamilyEntry.setSenior 中。
                 // 这里我们只确保基本的资格。
            }

            InviteCoordinator.createInvite(InviteType.FAMILY, chr, addChr, addChr.getId());
            addChr.getClient().sendPacket(PacketCreator.sendFamilyInvite(chr.getId(), chr.getName()));
            chr.dropMessage("已向 " + addChr.getName() + " 发送邀请登录为同学。");
            c.sendPacket(PacketCreator.enableActions());
        }
    }
}
