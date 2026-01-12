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

import com.mybatisflex.core.query.QueryWrapper;
import org.gms.client.Client;
import org.gms.config.GameConfig;
import org.gms.dao.entity.AccountsDO;
import org.gms.dao.mapper.AccountsMapper;
import org.gms.net.PacketHandler;
import org.gms.net.packet.InPacket;
import org.gms.net.server.Server;
import org.gms.net.server.coordinator.session.Hwid;
import org.gms.util.BCrypt;
import org.gms.util.HexTool;
import org.gms.util.PacketCreator;
import org.gms.util.SpringContextUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.SimpleDateFormat;
import java.util.Calendar;

public final class LoginPasswordHandler implements PacketHandler {
    private static final Logger log = LoggerFactory.getLogger(LoginPasswordHandler.class);
    private static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy年MM月dd日 HH时mm分ss秒");

    @Override
    public boolean validateState(Client c) {
        return !c.isLoggedIn();
    }

    @Override
    public final void handlePacket(InPacket p, Client c) {
        String remoteHost = c.getRemoteAddress();
        if (remoteHost.contentEquals("null")) {
            c.sendPacket(PacketCreator.getLoginFailed(14));          // 感谢 Alchemist 指出 remoteHost 可能为 null
            return;
        } else if (c.getAccID() == -5) {
            c.sendPacket(PacketCreator.serverNotice(1,"服务器已限制非法方式进入游戏\r\n请使用服务器指定的方式进入游戏。"));
            return;
        }

        if (Server.getInstance().isShutdown()) {
            c.sendPacket(PacketCreator.serverNotice(1, "服务器即将关闭，暂时无法登录。"));
            c.sendPacket(PacketCreator.getLoginFailed(1));
            return;
        }

        Server.getInstance().sendShutdownNotice(c);

        String login = p.readString();
        String pwd = p.readString();
        c.setAccountName(login);

        p.skip(6);   // localhost 用零掩盖了初始部分...
        byte[] hwidNibbles = p.readBytes(4);
        Hwid hwid = new Hwid(HexTool.toCompactHexString(hwidNibbles));
        int loginok = c.login(login, pwd, hwid);

        if (GameConfig.getServerBoolean("automatic_register") && loginok == 5) {
            c.setAccountName(login);
            c.setTempPassword(pwd);
            c.setHwid(hwid);
            c.sendPacket(PacketCreator.getLoginFailed(23)); // 触发协议确认窗口
            return;
        }

        if (GameConfig.getServerBoolean("bcrypt_migration") && (loginok <= -10)) { // -10 表示迁移到 bcrypt, -23 表示 TOS 未接受
            AccountsMapper mapper = SpringContextUtil.getBean(AccountsMapper.class);
            if (mapper != null) {
                AccountsDO account = mapper.selectOneByQuery(new QueryWrapper().eq(AccountsDO::getName, login));
                if (account != null) {
                    // BCrypt.hashpw 不会抛出 NoSuchAlgorithmException，因此不需要 try-catch
                    account.setPassword(BCrypt.hashpw(pwd, BCrypt.gensalt(12)));
                    mapper.update(account);
                }
            }
            loginok = (loginok == -10) ? 0 : 23;    //发送协议确认
        }

        if (c.hasBannedIP() || c.hasBannedMac() || c.hasBannedHWID()) {
            log.warn("客户端 {} 尝试登录账号 {}，但是IP / 设备码已被封禁，无法登录{}{}{}。",
                    c.getRemoteAddress(),
                    login,
                    (c.hasBannedIP() ? "，IP：[" + c.getRemoteAddress() + "] 被封禁" : ""),
                    (c.hasBannedMac() ? "，Mac：[" + c.getMacs() + "] 被封禁" : ""),
                    (c.hasBannedHWID() ? "，HWID：[" + hwid + "]，被封禁" : "")
            );
            c.sendPacket(PacketCreator.serverNotice(1,"您的设备已被禁止进入游戏。\r\n如有疑问，请联系GM处理。"));
            c.sendPacket(PacketCreator.getLoginFailed(1));//启用客户端操作
            return;
        }

        Calendar tempban = c.getTempBanCalendar();
        String banreason = c.getBanReason();
        if (tempban != null) {
            if (tempban.getTimeInMillis() > Calendar.getInstance().getTimeInMillis()) {
                String tmpbanstr = sdf.format(tempban.getTime());
                c.sendPacket(PacketCreator.serverNotice(1, "您的账号已被临时封停至 " + tmpbanstr + (!banreason.isEmpty() ? "\r\n\r\n【原因】\r\n" : "") + banreason));   //发送临时封禁时间和原因
                c.sendPacket(PacketCreator.getLoginFailed(1));          //通知客户端恢复操作
                log.warn("客户端 {} 尝试登录账号 {} ，但是被临时封停至 {} ，原因：{}",c.getRemoteAddress(),login,tmpbanstr,banreason);
                return;
            }
        }

        // 优化：仅在登录成功（密码正确）时检查在线数量限制，避免无效登录触发耗时查询
        if (loginok == 0) {
            int loginCountMax = GameConfig.getServerInt("login_client_limit");
            if (loginCountMax > 0) {
                int loginCount = Math.max(c.getActiveRecordCount(c.getRemoteAddress()), c.getActiveRecordCount(hwid.hwid()));
                if (loginCount >= loginCountMax) {
                    c.sendPacket(PacketCreator.serverNotice(1, "您的设备当前已登录账号数已超过服务端允许，无法继续登录账号。"));
                    c.sendPacket(PacketCreator.getLoginFailed(1));          //通知客户端恢复操作
                    log.warn("客户端 {} 尝试登录账号 {} ，已登录数量 {} ，最大允许登录数量 {} ，已限制登录。", c.getRemoteAddress(), login, loginCount, loginCountMax);
                    return;
                }
            }

            loginCountMax = GameConfig.getServerInt("login_client_limit_today");
            if (loginCountMax > 0) {
                int loginCount = Math.max(c.getTodayLoginCount(c.getRemoteAddress()), c.getTodayLoginCount(hwid.hwid()));
                if (loginCount >= loginCountMax) {
                    c.sendPacket(PacketCreator.serverNotice(1, "您的设备今天累计登录账号数已超过服务端允许，无法继续登录账号。"));
                    c.sendPacket(PacketCreator.getLoginFailed(1));          //通知客户端恢复操作
                    log.warn("客户端 {} 尝试登录账号 {} ，已累计登录数量 {} ，最大允许登录数量 {} ，已限制登录。", c.getRemoteAddress(), login, loginCount, loginCountMax);
                    return;
                }
            }
        }

        if (loginok == 3) {
            c.sendPacket(PacketCreator.getPermBan(c.getGReason()));//crashes but idc :D
            log.warn("客户端 {} 尝试登录账号 {} ，但是账号已被封禁",c.getRemoteAddress(),login);
            return;
        } else if (loginok != 0) {
            c.sendPacket(PacketCreator.getLoginFailed(loginok));    //通知客户端密码错误
            log.warn("客户端 {} 尝试登录账号 {} ，但是登录失败：{}",c.getRemoteAddress(),login,loginok);
            return;
        }
        if (c.finishLogin() == 0) {
            c.checkChar(c.getAccID());
            login(c);
            log.info("客户端 {} 成功登录账号 {} 。",c.getRemoteAddress(),login);
        } else {
            c.sendPacket(PacketCreator.getLoginFailed(7));
        }
    }

    private static void login(Client c) {
        c.sendPacket(PacketCreator.getAuthSuccess(c));//why the fk did I do c.getAccountName()?
        Server.getInstance().registerLoginState(c);
    }
}
