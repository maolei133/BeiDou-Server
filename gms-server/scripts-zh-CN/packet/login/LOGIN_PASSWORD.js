/**
 * [脚本化] 处理登录密码 (LOGIN_PASSWORD) 数据包的脚本。
 * 该脚本是内置辅助插件的最佳实践范本。
 *
 * @global log     - 由 Java 注入的 SLF4J Logger 实例。
 * @global client  - 由 Java 注入的 Client 实例，代表当前客户端连接。
 * @global packet  - 由 Java 注入的 InPacket 实例，包含了接收到的数据包内容。
 * @global PacketCreator - 由 Java 注入的、被代理的 PacketCreator 对象。
 */

// --- 1. 导入所有需要的 Java 类 ---
// PacketCreator 已由引擎自动注入，无需手动导入。
var System = Java.type('java.lang.System');
var QueryWrapper = Java.type('com.mybatisflex.core.query.QueryWrapper');
var GameConfig = Java.type('org.gms.config.GameConfig');
var AccountsDO = Java.type('org.gms.dao.entity.AccountsDO');
var AccountsMapper = Java.type('org.gms.dao.mapper.AccountsMapper');
var Server = Java.type('org.gms.net.server.Server');
var Hwid = Java.type('org.gms.net.server.coordinator.session.Hwid');
var AuditContext = Java.type('org.gms.server.logging.AuditContext');
var AuditLogger = Java.type('org.gms.server.logging.AuditLogger');
var LogAction = Java.type('org.gms.server.logging.LogAction');
var LogModule = Java.type('org.gms.server.logging.LogModule');
var BCrypt = Java.type('org.gms.util.BCrypt');
var HexTool = Java.type('org.gms.util.HexTool');
var SpringContextUtil = Java.type('org.gms.util.SpringContextUtil');
var SimpleDateFormat = Java.type('java.text.SimpleDateFormat');
var Calendar = Java.type('java.util.Calendar');


// log.info("脚本 LOGIN_PASSWORD.js 开始执行...");

// --- 2. 定义辅助函数 ---
var sdf = new SimpleDateFormat("yyyy年MM月dd日 HH时mm分ss秒");

function sendNoticeAndUnlockUI(c, message) {
    c.sendPacket(PacketCreator.serverNotice(1, message));
    c.sendPacket(PacketCreator.getLoginFailed(1));
}

function handleBansAndRestrictions(c, loginok, login, hwid) {
    // 硬件/IP封禁检查
    if (c.hasBannedIP() || c.hasBannedMac() || c.hasBannedHWID()) {
        log.warn("客户端 {} 尝试登录账号 {}，但是IP / 设备码已被封禁。", c.getRemoteAddress(), login);
        sendNoticeAndUnlockUI(c, "您的设备已被禁止进入游戏。\r\n如有疑问，请联系GM处理。");
        return true;
    }

    // 临时封禁检查
    var tempban = c.getTempBanCalendar();
    if (tempban != null && tempban.getTimeInMillis() > System.currentTimeMillis()) {
        var banReason = c.getBanReason();
        var tmpbanstr = sdf.format(tempban.getTime());
        var notice = "您的账号已被临时封停至 " + tmpbanstr + (!banReason.isEmpty() ? "\r\n\r\n【原因】\r\n" + banReason : "");
        sendNoticeAndUnlockUI(c, notice);
        log.warn("客户端 {} 尝试登录账号 {} ，但是被临时封停至 {} ，原因：{}", c.getRemoteAddress(), login, tmpbanstr, banReason);
        return true;
    }

    // 优化：仅在密码正确后才进行设备数量检查
    if (loginok === 0) {
        // 单台设备同时在线账号数量限制
        var loginCountMax = GameConfig.getServerInt("login_client_limit");
        if (loginCountMax > 0) {
            var loginCount = Math.max(c.getActiveRecordCount(c.getRemoteAddress()), c.getActiveRecordCount(hwid.hwid()));
            if (loginCount >= loginCountMax) {
                log.warn("客户端 {} 尝试登录账号 {} ，已登录数量 {} ，超过最大允许数量 {}。", c.getRemoteAddress(), login, loginCount, loginCountMax);
                sendNoticeAndUnlockUI(c, "您的设备当前已登录账号数已超过服务端允许，无法继续登录账号。");
                return true;
            }
        }

        // 单台设备每日累计登录账号数量限制
        var loginCountMaxToday = GameConfig.getServerInt("login_client_limit_today");
        if (loginCountMaxToday > 0) {
            var loginCountToday = Math.max(c.getTodayLoginCount(c.getRemoteAddress()), c.getTodayLoginCount(hwid.hwid()));
            if (loginCountToday >= loginCountMaxToday) {
                log.warn("客户端 {} 尝试登录账号 {} ，已累计登录数量 {} ，超过最大允许登录数量 {}。", c.getRemoteAddress(), login, loginCountToday, loginCountMaxToday);
                sendNoticeAndUnlockUI(c, "您的设备今天累计登录账号数已超过服务端允许，无法继续登录账号。");
                return true;
            }
        }
    }
    return false;
}

function loginSuccess(c) {
    c.sendPacket(PacketCreator.getAuthSuccess(c));
    Server.getInstance().registerLoginState(c);
}

// --- 3. 主处理逻辑 ---
if (client.isLoggedIn()) {
    log.warn("客户端 {} 在已登录状态下再次发送登录请求，已忽略。", client.getRemoteAddress());
} else {
    var remoteHost = client.getRemoteAddress();
    if (remoteHost === "null") {
        client.sendPacket(PacketCreator.getLoginFailed(14));
    } else if (client.getAccID() === -5) {
        sendNoticeAndUnlockUI(client, "服务器已限制非法方式进入游戏\r\n请使用服务器指定的方式进入游戏。");
    } else if (Server.getInstance().isShutdown()) {
        sendNoticeAndUnlockUI(client, "服务器即将维护，暂时无法登录。");
    } else {
        Server.getInstance().sendShutdownNotice(client);

        var login = packet.readString();
        var pwd = packet.readString();
        client.setAccountName(login);
        packet.skip(6);
        var hwidNibbles = packet.readBytes(4);
        var hwid = new Hwid(HexTool.toCompactHexString(hwidNibbles));
        var loginok = client.login(login, pwd, hwid);

        if (GameConfig.getServerBoolean("automatic_register") && loginok === 5) {
            client.setAccountName(login);
            client.setTempPassword(pwd);
            client.setHwid(hwid);
            client.sendPacket(PacketCreator.getLoginFailed(23));
        } else {
            if (GameConfig.getServerBoolean("bcrypt_migration") && (loginok <= -10)) {
                var mapper = SpringContextUtil.getBean(AccountsMapper.class);
                if (mapper != null) {
                    var account = mapper.selectOneByQuery(new QueryWrapper().eq("name", login));
                    if (account != null) {
                        account.setPassword(BCrypt.hashpw(pwd, BCrypt.gensalt(12)));
                        mapper.update(account);
                    }
                }
                loginok = (loginok === -10) ? 0 : 23;
            }

            if (!handleBansAndRestrictions(client, loginok, login, hwid)) {
                if (loginok === 3) {
                    client.sendPacket(PacketCreator.getPermBan(client.getGReason()));
                } else if (loginok !== 0) {
                    // 终极方案：直接调用，就像它是Java的静态方法一样
                    var packetToSend = PacketCreator.getLoginFailednew(loginok);    //调用JS注册的函数方法
                    if (packetToSend) {
                        client.sendPacket(packetToSend);
                    } else {
                        // 如果JS调用失败或函数不存在，可以有一个备用方案
                        client.sendPacket(PacketCreator.getLoginFailed(loginok));
                    }
                } else {
                    if (client.finishLogin() === 0) {
                        client.checkChar(client.getAccID());
                        loginSuccess(client);
                        AuditContext.set(client);
                        AuditLogger.info(LogModule.ACCOUNT, LogAction.ACCOUNT_LOGIN_SUCCESS, "登录成功");
                    } else {
                        client.sendPacket(PacketCreator.getLoginFailed(7));
                    }
                }
            }
        }
    }
}

// log.info("脚本 LOGIN_PASSWORD.js 执行完毕。");
