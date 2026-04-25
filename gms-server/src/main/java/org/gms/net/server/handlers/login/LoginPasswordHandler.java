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
import org.gms.server.logging.AuditContext;
import org.gms.server.logging.AuditLogger;
import org.gms.server.logging.LogAction;
import org.gms.server.logging.LogModule;
import org.gms.util.BCrypt;
import org.gms.util.HexTool;
import org.gms.util.PacketCreator;
import org.gms.util.SpringContextUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.SimpleDateFormat;
import java.util.Calendar;

/**
 * 处理客户端登录密码验证请求
 *
 * @author 现有作者
 */
public final class LoginPasswordHandler implements PacketHandler {
    private static final Logger log = LoggerFactory.getLogger(LoginPasswordHandler.class);
    private static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy年MM月dd日 HH时mm分ss秒");

    @Override
    public boolean validateState(Client c) {
        return !c.isLoggedIn();
    }

    @Override
    public final void handlePacket(InPacket p, Client c) {
        // 前置检查：无效远程地址或非法登录方式
        String remoteHost = c.getRemoteAddress();
        if (remoteHost.contentEquals("null")) {
            // 感谢 Alchemist 指出 remoteHost 可能为 null
            c.sendPacket(PacketCreator.getLoginFailed(14));
            return;
        } else if (c.getAccID() == -5) {
            sendNoticeAndUnlockUI(c, "服务器已限制非法方式进入游戏\r\n请使用服务器指定的方式进入游戏。");
            return;
        }

        // 服务器维护检查
        if (Server.getInstance().isShutdown()) {
            sendNoticeAndUnlockUI(c, "服务器即将维护，暂时无法登录。");
            return;
        }
        Server.getInstance().sendShutdownNotice(c);

        // 读取登录信息
        String login = p.readString();
        String pwd = p.readString();
        c.setAccountName(login);

        p.skip(6); // localhost 用零掩盖了初始部分...
        byte[] hwidNibbles = p.readBytes(4);
        Hwid hwid = new Hwid(HexTool.toCompactHexString(hwidNibbles));

        // 核心登录逻辑
        int loginok = c.login(login, pwd, hwid);

        // 自动注册流程
        if (GameConfig.getServerBoolean("automatic_register") && loginok == 5) {
            c.setAccountName(login);
            c.setTempPassword(pwd);
            c.setHwid(hwid);
            c.sendPacket(PacketCreator.getLoginFailed(23)); // 触发协议确认窗口
            return;
        }

        // BCrypt 密码迁移
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
            loginok = (loginok == -10) ? 0 : 23; // 发送协议确认
        }

        // 封禁与限制检查
        if (handleBansAndRestrictions(c, loginok, login, hwid)) {
            return; // 如果被封禁或限制，则中断登录流程
        }

        // 永久封禁状态检查
        if (loginok == 3) {
            c.sendPacket(PacketCreator.getPermBan(c.getGReason()));
            log.warn("客户端 {} 尝试登录账号 {} ，但是账号已被永久封禁", c.getRemoteAddress(), login);
            return;
        }

        // 其他登录失败情况 (如密码错误)
        if (loginok != 0) {
            c.sendPacket(PacketCreator.getLoginFailed(loginok));
            log.warn("客户端 {} 尝试登录账号 {} ，但是登录失败，状态码：{}", c.getRemoteAddress(), login, loginok);
            AuditLogger.info(LogModule.ACCOUNT, LogAction.ACCOUNT_LOGIN_FAIL, "登录失败: " + loginok);
            return;
        }

        // 登录成功
        if (c.finishLogin() == 0) {
            c.checkChar(c.getAccID());
            loginSuccess(c);
            log.info("客户端 {} 成功登录账号 {} 。", c.getRemoteAddress(), login);

            // 刷新上下文并记录登录成功日志
            AuditContext.set(c);
            AuditLogger.info(LogModule.ACCOUNT, LogAction.ACCOUNT_LOGIN_SUCCESS, "登录成功");
        } else {
            // 已在其他地方登录
            c.sendPacket(PacketCreator.getLoginFailed(7));
        }
    }

    /**
     * 封装了发送服务器通知并重新启用客户端UI的操作
     *
     * @param c       客户端实例
     * @param message 要发送的通知消息
     */
    private void sendNoticeAndUnlockUI(Client c, String message) {
        c.sendPacket(PacketCreator.serverNotice(1, message));
        c.sendPacket(PacketCreator.getLoginFailed(1)); // 启用客户端操作
    }

    /**
     * 统一处理各种封禁和登录限制检查
     *
     * @param c     客户端实例
     * @param login 登录名
     * @param hwid  硬件ID
     * @return 如果触发了任何封禁或限制，返回 true，否则返回 false
     */
    private boolean handleBansAndRestrictions(Client c,int loginok, String login, Hwid hwid) {
        // 硬件/IP封禁检查
        if (c.hasBannedIP() || c.hasBannedMac() || c.hasBannedHWID()) {
            log.warn("客户端 {} 尝试登录账号 {}，但是IP / 设备码已被封禁，无法登录{}{}{}。",
                    c.getRemoteAddress(),
                    login,
                    (c.hasBannedIP() ? "，IP：[" + c.getRemoteAddress() + "] 被封禁" : ""),
                    (c.hasBannedMac() ? "，Mac：[" + c.getMacs() + "] 被封禁" : ""),
                    (c.hasBannedHWID() ? "，HWID：[" + hwid + "]，被封禁" : "")
            );
            sendNoticeAndUnlockUI(c, "您的设备已被禁止进入游戏。\r\n如有疑问，请联系GM处理。");
            return true;
        }

        // 临时封禁检查
        Calendar tempban = c.getTempBanCalendar();
        if (tempban != null && tempban.getTimeInMillis() > System.currentTimeMillis()) {
            String banReason = c.getBanReason();
            String tmpbanstr = sdf.format(tempban.getTime());
            String notice = "您的账号已被临时封停至 " + tmpbanstr + (!banReason.isEmpty() ? "\r\n\r\n【原因】\r\n" + banReason : "");
            sendNoticeAndUnlockUI(c, notice);
            log.warn("客户端 {} 尝试登录账号 {} ，但是被临时封停至 {} ，原因：{}", c.getRemoteAddress(), login, tmpbanstr, banReason);
            return true;
        }

        // 优化：仅在密码正确后才进行设备数量检查
        if (loginok == 0) {
            // 单台设备同时在线账号数量限制
            int loginCountMax = GameConfig.getServerInt("login_client_limit");
            if (loginCountMax > 0) {
                int loginCount = Math.max(c.getActiveRecordCount(c.getRemoteAddress()), c.getActiveRecordCount(hwid.hwid()));
                if (loginCount >= loginCountMax) {
                    log.warn("客户端 {} 尝试登录账号 {} ，已登录数量 {} ，最大允许登录数量 {} ，已限制登录。", c.getRemoteAddress(), login, loginCount, loginCountMax);
                    sendNoticeAndUnlockUI(c, "您的设备当前已登录账号数已超过服务端允许，无法继续登录账号。");
                    return true;
                }
            }

            // 单台设备每日累计登录账号数量限制
            int loginCountMaxToday = GameConfig.getServerInt("login_client_limit_today");
            if (loginCountMaxToday > 0) {
                int loginCount = Math.max(c.getTodayLoginCount(c.getRemoteAddress()), c.getTodayLoginCount(hwid.hwid()));
                if (loginCount >= loginCountMaxToday) {
                    log.warn("客户端 {} 尝试登录账号 {} ，已累计登录数量 {} ，最大允许登录数量 {} ，已限制登录。", c.getRemoteAddress(), login, loginCount, loginCountMaxToday);
                    sendNoticeAndUnlockUI(c, "您的设备今天累计登录账号数已超过服务端允许，无法继续登录账号。");
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 处理登录成功后的逻辑
     *
     * @param c 客户端实例
     */
    private static void loginSuccess(Client c) {
        c.sendPacket(PacketCreator.getAuthSuccess(c));
        Server.getInstance().registerLoginState(c);
    }
}
