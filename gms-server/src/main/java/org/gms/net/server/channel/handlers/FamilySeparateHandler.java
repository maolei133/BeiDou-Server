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

import org.gms.client.Client;
import org.gms.client.Family;
import org.gms.client.FamilyEntry;
import org.gms.config.GameConfig;
import org.gms.net.AbstractPacketHandler;
import org.gms.net.packet.InPacket;
import org.gms.util.PacketCreator;

/**
 * 家族分离处理器
 * 处理玩家请求脱离家族关系的数据包
 * 玩家需要支付一定的金币和声望值才能脱离家族
 */
public class FamilySeparateHandler extends AbstractPacketHandler {

    /**
     * 处理家族分离请求数据包
     * @param p 数据包内容
     * @param c 客户端连接
     */
    @Override
    public void handlePacket(InPacket p, Client c) {
        // 检查服务器是否启用了家族系统
        if (!GameConfig.getServerBoolean("use_family_system")) {
            return;
        }
        
        // 获取玩家当前的家族信息
        Family oldFamily = c.getPlayer().getFamily();
        if (oldFamily == null) {
            return;
        }
        
        // 确定要分离的家庭成员条目
        FamilyEntry forkOn = null;
        boolean isSenior; // 标记是否是上级成员
        
        // 根据数据包内容判断分离方向
        if (p.available() > 0) { //packet 0x95 doesn't send id, since there is only one senior
            // 从数据包中读取要分离的成员ID
            forkOn = c.getPlayer().getFamily().getEntryByID(p.readInt());
            // 验证该成员是否为当前玩家的下级
            if (!c.getPlayer().getFamilyEntry().isJunior(forkOn)) {
                return; //packet editing?
            }
            isSenior = true; // 表示分离上级成员
        } else {
            // 分离自己的家族关系
            forkOn = c.getPlayer().getFamilyEntry();
            isSenior = false; // 表示分离自己
        }
        
        if (forkOn == null) {
            return;
        }

        // 获取上级成员信息
        FamilyEntry senior = forkOn.getSenior();
        if (senior == null) {
            return;
        }
        
        // 计算分离所需费用（基于等级差）
        int levelDiff = Math.abs(c.getPlayer().getLevel() - senior.getLevel());
        int cost = 2500 * levelDiff;
        cost += levelDiff * levelDiff;
        
        // 检查玩家是否有足够的金币
        if (c.getPlayer().getMeso() < cost) {
            c.sendPacket(PacketCreator.sendFamilyMessage(isSenior ? 81 : 80, cost));
            return;
        }
        
        // 扣除玩家金币
        c.getPlayer().gainMeso(-cost);
        
        // 计算并扣除声望值
        int repCost = separateRepCost(forkOn);
        senior.gainReputation(-repCost, false); // 扣除上级成员声望
        
        // 如果上级成员还有上级，则也扣除部分声望
        if (senior.getSenior() != null) {
            senior.getSenior().gainReputation(-(repCost / 2), false);
        }
        
        // 通知上级成员该玩家已离开家族
        forkOn.announceToSenior(PacketCreator.serverNotice(5, forkOn.getName() + " 已经离开了这个学院。"), true);
        
        // 执行家族关系分离
        forkOn.fork();
        
        // 向客户端发送更新后的家族信息
        c.sendPacket(PacketCreator.getFamilyInfo(forkOn)); //pedigree info will be requested from the client if the window is open
        forkOn.updateSeniorFamilyInfo(true);
        c.sendPacket(PacketCreator.sendFamilyMessage(1, 0)); // 发送成功消息
    }


    /**
     * 计算家族分离所需的声望值消耗
     * 声望消耗公式: ((level / 20) + 10) * level * 2
     * @param junior 家族中的下级成员
     * @return 需要消耗的声望值
     */
    private static int separateRepCost(FamilyEntry junior) {
        int level = junior.getLevel();
        int ret = level / 20;
        ret += 10;
        ret *= level;
        ret *= 2;
        return ret;
    }
}