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

import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.net.AbstractPacketHandler;
import org.gms.net.packet.InPacket;
import org.gms.net.server.Server;
import org.gms.net.server.coordinator.session.Hwid;
import org.gms.net.server.coordinator.session.SessionCoordinator;
import org.gms.net.server.coordinator.session.SessionCoordinator.AntiMulticlientResult;
import org.gms.net.server.world.World;
import org.gms.server.logging.AuditContext;
import org.gms.server.logging.AuditLogger;
import org.gms.server.logging.LogAction;
import org.gms.server.logging.LogModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.gms.util.PacketCreator;

import java.net.InetAddress;
import java.net.UnknownHostException;

public final class CharSelectedHandler extends AbstractPacketHandler {
    private static final Logger log = LoggerFactory.getLogger(CharSelectedHandler.class);

    private static int parseAntiMulticlientError(AntiMulticlientResult res) {
        return switch (res) {
            case REMOTE_PROCESSING -> 10;
            case REMOTE_LOGGEDIN -> 7;
            case REMOTE_NO_MATCH -> 17;
            case COORDINATOR_ERROR -> 8;
            default -> 9;
        };
    }

    @Override
    public final void handlePacket(InPacket p, Client c) {
        int charId = p.readInt();

        String macs = p.readString();
        String hostString = p.readString();

        final Hwid hwid;
        try {
            hwid = Hwid.fromHostString(hostString);
        } catch (IllegalArgumentException e) {
            log.warn("无效的主机字符串: {}", hostString, e);
            c.sendPacket(PacketCreator.getAfterLoginError(17));
            return;
        }

        c.updateMacs(macs);
        c.updateHwid(hwid);

        AntiMulticlientResult res = SessionCoordinator.getInstance().attemptGameSession(c, c.getAccID(), hwid);
        if (res != AntiMulticlientResult.SUCCESS) {
            c.sendPacket(PacketCreator.getAfterLoginError(parseAntiMulticlientError(res)));
            return;
        }

        if (c.hasBannedMac() || c.hasBannedHWID()) {
            log.warn("客户端 {} 选择角色ID [{}] 尝试进入频道 {} ，但是IP / 设备码被封禁，无法登录{}{}。",
                    c.getRemoteAddress(),
                    charId,
                    c.getChannelServer().getId(),
                    (c.hasBannedMac() ? "，Mac：[" + macs + "] 被封禁" : ""),
                    (c.hasBannedHWID() ? "，HWID：[" + hwid + "]，被封禁" : "×")
            );
            c.sendPacket(PacketCreator.serverNotice(1,"您的设备已被禁止进入游戏。\r\n如有疑问，请联系GM处理。"));
            c.sendPacket(PacketCreator.getLoginFailed(1));//启用客户端操作
            //SessionCoordinator.getInstance().closeSession(c, true);   //这里直接断开连接，会导致客户端弹窗与服务器失去连接，不清楚情况的话要排查很久
            return;
        }

        Server server = Server.getInstance();
        if (!server.haveCharacterEntry(c.getAccID(), charId)) {
            SessionCoordinator.getInstance().closeSession(c, true);
            return;
        }

        c.setWorld(server.getCharacterWorld(charId));
        World wserv = c.getWorldServer();
        if (wserv == null || wserv.isWorldCapacityFull()) {
            c.sendPacket(PacketCreator.getAfterLoginError(10));
            return;
        }

        String[] socket = server.getInetSocket(c, c.getWorld(), c.getChannel());
        if (socket == null) {
            c.sendPacket(PacketCreator.getAfterLoginError(10));
            return;
        }

        // [链路调试] log.info("[链路] 选角 → 发频道地址: charId={} addr={}:{} remoteAddress={}",
        //         charId, socket[0], socket[1], c.getRemoteAddress());

        server.unregisterLoginState(c);
        c.setCharacterOnSessionTransitionState(charId);

        try {
            c.sendPacket(PacketCreator.getServerIP(InetAddress.getByName(socket[0]), Integer.parseInt(socket[1]), charId));
            
            // 刷新上下文 (更新 MAC/HWID 等信息)
            AuditContext.set(c);
            
            // 从 Client 缓存中获取角色信息，避免重复查询数据库
            Character chr = c.getLoadedChar(charId);
            if (chr != null) {
                AuditContext.put("cid", String.valueOf(chr.getId()));
                AuditContext.put("chr", chr.getName());
                AuditContext.put("lvl", String.valueOf(chr.getLevel()));
                AuditContext.put("job", String.valueOf(chr.getJob().getId()));
                AuditContext.put("map", String.valueOf(chr.getMapId()));
                AuditContext.put("jobName", chr.getJob().getName());
            } else {
                log.warn("在 Client 缓存中未找到角色 ID: {}，无法记录详细审计日志", charId);
            }

            AuditLogger.info(LogModule.ACCOUNT, LogAction.CHARACTER_SELECT, "选择角色: " + charId);

        } catch (UnknownHostException | NumberFormatException e) {
            e.printStackTrace();
        }
    }
}