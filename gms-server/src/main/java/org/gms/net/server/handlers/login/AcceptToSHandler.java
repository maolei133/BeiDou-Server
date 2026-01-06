package org.gms.net.server.handlers.login;

import org.gms.client.Client;
import org.gms.client.DefaultDates;
import org.gms.config.GameConfig;
import org.gms.dao.entity.AccountsDO;
import org.gms.dao.mapper.AccountsMapper;
import org.gms.net.AbstractPacketHandler;
import org.gms.net.packet.InPacket;
import org.gms.util.BCrypt;
import org.gms.util.PacketCreator;
import org.gms.util.SpringContextUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Date;
import java.sql.Timestamp;

/**
 * @author kevintjuh93
 */
public final class AcceptToSHandler extends AbstractPacketHandler {
    private static final Logger log = LoggerFactory.getLogger(AcceptToSHandler.class);

    @Override
    public boolean validateState(Client c) {
        return !c.isLoggedIn();
    }

    @Override
    public final void handlePacket(InPacket p, Client c) {
        if (p.available() == 0 || p.readByte() != 1) {
            c.disconnect(false, false);//Client dc's but just because I am cool I do this (:
            return;
        }

        // 检查是否有暂存密码，如果有则说明是新账号注册流程
        if (c.getTempPassword() != null) {
            String login = c.getAccountName();
            String pwd = c.getTempPassword();
            
            AccountsMapper mapper = SpringContextUtil.getBean(AccountsMapper.class);
            if (mapper != null) {
                try {
                    AccountsDO newAccount = new AccountsDO();
                    newAccount.setName(login);
                    newAccount.setPassword(GameConfig.getServerBoolean("bcrypt_migration") ? BCrypt.hashpw(pwd, BCrypt.gensalt(12)) : BCrypt.hashpwSHA512(pwd));
                    newAccount.setBirthday(Date.valueOf(DefaultDates.getBirthday()));
                    newAccount.setTempban(Timestamp.valueOf(DefaultDates.getTempban()));
                    newAccount.setPin(""); // 或者一个默认的PIN，如 "1234"
                    newAccount.setPic(""); // 或者一个默认的PIC，如 "123456"
                    newAccount.setLoggedin(0); // 0 代表未登录
                    newAccount.setLastlogin(null); // 首次创建，没有上次登录时间
                    newAccount.setCreatedat(new Timestamp(System.currentTimeMillis()));
                    newAccount.setBanned(false); // 代表未封禁
                    newAccount.setCharacterslots(3); // 默认角色槽数量
                    newAccount.setMacs(""); // 默认空字符串
                    newAccount.setSitelogged(""); // 默认空字符串
                    newAccount.setNick(""); // 默认空字符串
                    newAccount.setEmail(""); // 默认空字符串
                    newAccount.setIp(""); // 默认空字符串
                    newAccount.setGender(10); // 默认值
                    newAccount.setGreason(0); // 默认值
                    newAccount.setTos(true); // 用户已同意协议
                    newAccount.setRewardpoints(0); // 默认值
                    newAccount.setVotepoints(0); // 默认值
                    newAccount.setHwid(""); // 默认值
                    newAccount.setLanguage(3); // 默认值

                    mapper.insert(newAccount);
                    c.setAccID(newAccount.getId());
                    
                    // 注册成功后尝试登录
                    int loginok = c.login(login, pwd, c.getHwid());
                    if (loginok == 0) {
                        if (c.finishLogin() == 0) {
                            c.checkChar(c.getAccID());
                            c.sendPacket(PacketCreator.getAuthSuccess(c));
                            org.gms.net.server.Server.getInstance().registerLoginState(c);
                            log.info("自动注册并登录账号 {} 成功。", login);
                        } else {
                            c.sendPacket(PacketCreator.getLoginFailed(7));
                        }
                    } else {
                        c.sendPacket(PacketCreator.getLoginFailed(loginok));
                    }
                } catch (Exception e) {
                    c.setAccID(-1);
                    log.error("自动注册账号 {} 失败: {}", login, e);
                    c.sendPacket(PacketCreator.serverNotice(1, "自动注册失败，请稍后再试或联系管理员。"));
                    c.sendPacket(PacketCreator.getLoginFailed(1));
                } finally {
                    c.setTempPassword(null); // 清除暂存密码
                }
            }
            return;
        }

        // 原有的老账号补签协议流程
        if (c.acceptToS()) {
            c.disconnect(false, false);
            return;
        }
        if (c.finishLogin() == 0) {
            c.sendPacket(PacketCreator.getAuthSuccess(c));
        } else {
            c.sendPacket(PacketCreator.getLoginFailed(9));//shouldn't happen XD
        }
    }
}
