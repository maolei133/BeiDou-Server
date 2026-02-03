package org.gms.util.packets;

import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.config.GameConfig;
import org.gms.constants.game.GameConstants;
import org.gms.net.encryption.InitializationVector;
import org.gms.net.opcodes.SendOpcode;
import org.gms.net.packet.ByteBufOutPacket;
import org.gms.net.packet.OutPacket;
import org.gms.net.packet.Packet;
import org.gms.net.server.Server;
import org.gms.net.server.channel.Channel;
import org.gms.net.server.world.World;
import org.gms.util.Pair;
import org.gms.util.Randomizer;

import java.net.InetAddress;
import java.util.List;

/**
 * LoginPackets
 * 处理登录、服务器列表、选角等相关的数据包构建
 */
public class LoginPackets {

    /**
     * 发送握手包 (Hello Packet)
     *
     * @param mapleVersion 冒险岛客户端版本
     * @param sendIv       服务器发送用的 IV
     * @param recvIv       服务器接收用的 IV
     * @return 握手包
     */
    public static Packet getHello(short mapleVersion, InitializationVector sendIv, InitializationVector recvIv) {
        OutPacket p = new ByteBufOutPacket();
        p.writeShort(0x0E);
        p.writeShort(mapleVersion);
        p.writeShort(1);
        p.writeByte(49);
        p.writeBytes(recvIv.getBytes());
        p.writeBytes(sendIv.getBytes());
        p.writeByte(8);
        return p;
    }

    /**
     * 发送 Ping 包
     *
     * @return Ping 包
     */
    public static Packet getPing() {
        return OutPacket.create(SendOpcode.PING);
    }

    /**
     * 获取登录失败包
     * <p>
     * reason 可能的值:<br>
     * 3: ID 已删除或被封锁<br>
     * 4: 密码错误<br>
     * 5: 不是注册的 ID<br>
     * 6: 系统错误<br>
     * 7: 已经登录<br>
     * 8: 系统错误<br>
     * 9: 系统错误<br>
     * 10: 无法处理这么多连接<br>
     * 11: 只有 20 岁以上的用户可以使用此频道<br>
     * 13: 无法在此 IP 以管理员身份登录<br>
     * 14: 错误的网关或个人信息以及奇怪的韩语按钮<br>
     * 15: 正在处理该韩语按钮的请求！<br>
     * 16: 请通过电子邮件验证您的帐户...<br>
     * 17: 错误的网关或个人信息<br>
     * 21: 请通过电子邮件验证您的帐户...<br>
     * 23: 许可协议<br>
     * 25: Maple Europe 通知 =[ FUCK YOU NEXON<br>
     * 27: 一些奇怪的完整客户端通知，可能用于试用版<br>
     *
     * @param reason 登录失败的原因
     * @return 登录失败包
     */
    public static Packet getLoginFailed(int reason) {
        OutPacket p = OutPacket.create(SendOpcode.LOGIN_STATUS);
        p.writeByte(reason);
        p.writeByte(0);
        p.writeInt(0);
        return p;
    }

    /**
     * 获取登录后错误包
     * <p>
     * reason 可能的值:<br>
     * 2: ID 已删除或被封锁<br>
     * 3: ID 已删除或被封锁<br>
     * 4: 密码错误<br>
     * 5: 不是注册的 ID<br>
     * 6: 登录游戏遇到问题？<br>
     * 7: 已经登录<br>
     * 8: 登录游戏遇到问题？<br>
     * 9: 登录游戏遇到问题？<br>
     * 10: 无法处理这么多连接<br>
     * 11: 只有 20 岁以上的用户可以使用此频道<br>
     * 12: 登录游戏遇到问题？<br>
     * 13: 无法在此 IP 以管理员身份登录<br>
     * 14: 错误的网关或个人信息以及奇怪的韩语按钮<br>
     * 15: 正在处理该韩语按钮的请求！<br>
     * 16: 请通过电子邮件验证您的帐户...<br>
     * 17: 错误的网关或个人信息<br>
     * 21: 请通过电子邮件验证您的帐户...<br>
     * 23: 崩溃<br>
     * 25: Maple Europe 通知 =[ FUCK YOU NEXON<br>
     * 27: 一些奇怪的完整客户端通知，可能用于试用版<br>
     *
     * @param reason 登录失败的原因
     * @return 登录失败包
     */
    public static Packet getAfterLoginError(int reason) {
        OutPacket p = OutPacket.create(SendOpcode.SELECT_CHARACTER_BY_VAC);
        p.writeShort(reason);
        return p;
    }

    /**
     * 获取认证成功包
     *
     * @param c 客户端对象
     * @return 认证成功包
     */
    public static Packet getAuthSuccess(Client c) {
        Server.getInstance().loadAccountCharacters(c);    // 锁定登录会话，直到从缓存或数据库恢复数据。
        Server.getInstance().loadAccountStorages(c);

        final OutPacket p = OutPacket.create(SendOpcode.LOGIN_STATUS);
        p.writeInt(0);
        p.writeShort(0);
        p.writeInt(c.getAccID());
        p.writeByte(c.getGender());

        boolean canFly = Server.getInstance().canFly(c.getAccID());
        p.writeBool((GameConfig.getServerBoolean("use_enforce_admin_account") || canFly) && c.getGMLevel() > 1);
        p.writeByte(((GameConfig.getServerBoolean("use_enforce_admin_account") || canFly) && c.getGMLevel() > 1) ? 0x80 : 0);
        p.writeByte(0); // 国家代码

        p.writeString(c.getAccountName());
        p.writeByte(0);

        p.writeByte(0); // IsQuietBan
        p.writeLong(0);//IsQuietBanTimeStamp
        p.writeLong(0); //CreationTimeStamp

        p.writeInt(1); // 1: 移除 "选择你想玩的世界"

        p.writeByte(GameConfig.getServerBoolean("enable_pin") && !c.canBypassPin() ? 0 : 1); // 0 = 启用 Pin 系统, 1 = 禁用
        p.writeByte(GameConfig.getServerBoolean("enable_pic") && !c.canBypassPic() ? (c.getPic() == null || c.getPic().equals("") ? 0 : 1) : 2); // 0 = 注册 PIC, 1 = 询问 PIC, 2 = 禁用

        return p;
    }

    /**
     * 获取 PIN 操作包
     * <p>
     * mode 可能的值:<br>
     * 0 - PIN 被接受<br>
     * 1 - 注册新 PIN<br>
     * 2 - 无效 PIN / 重新输入<br>
     * 3 - 由于系统错误导致连接失败<br>
     * 4 - 输入 PIN
     *
     * @param mode 模式
     * @return PIN 操作包
     */
    private static Packet pinOperation(byte mode) {
        OutPacket p = OutPacket.create(SendOpcode.CHECK_PINCODE);
        p.writeByte(mode);
        return p;
    }

    /**
     * PIN 码已注册
     * @return 数据包
     */
    public static Packet pinRegistered() {
        OutPacket p = OutPacket.create(SendOpcode.UPDATE_PINCODE);
        p.writeByte(0);
        return p;
    }

    /**
     * 请求 PIN 码
     * @return 数据包
     */
    public static Packet requestPin() {
        return pinOperation((byte) 4);
    }

    /**
     * 失败后请求 PIN 码
     * @return 数据包
     */
    public static Packet requestPinAfterFailure() {
        return pinOperation((byte) 2);
    }

    /**
     * 注册 PIN 码
     * @return 数据包
     */
    public static Packet registerPin() {
        return pinOperation((byte) 1);
    }

    /**
     * PIN 码已接受
     * @return 数据包
     */
    public static Packet pinAccepted() {
        return pinOperation((byte) 0);
    }

    /**
     * 错误的 PIC 码
     * @return 数据包
     */
    public static Packet wrongPic() {
        OutPacket p = OutPacket.create(SendOpcode.CHECK_SPW_RESULT);
        p.writeByte(0);
        return p;
    }

    /**
     * 获取服务器列表包
     *
     * @param serverId    服务器 ID
     * @param serverName  服务器名称
     * @param flag        标志
     * @param eventmsg    事件消息
     * @param channelLoad 频道负载
     * @return 服务器列表包
     */
    public static Packet getServerList(int serverId, String serverName, int flag, String eventmsg, List<Channel> channelLoad) {
        final OutPacket p = OutPacket.create(SendOpcode.SERVERLIST);
        p.writeByte(serverId);
        p.writeString(serverName);
        p.writeByte(flag);
        p.writeString(eventmsg);
        p.writeByte(100); // 倍率修改器
        p.writeByte(0); // 活动经验 * 2.6
        p.writeByte(100); // 倍率修改器
        p.writeByte(0); // 掉落率 * 2.6
        p.writeByte(0);
        p.writeByte(channelLoad.size());
        for (Channel ch : channelLoad) {
            p.writeString(serverName + "-" + ch.getId());
            p.writeInt(ch.getChannelCapacity());

            p.writeByte(1);// nWorldID
            p.writeByte(ch.getId() - 1);// nChannelID
            p.writeBool(false);// bAdultChannel
        }
        p.writeShort(0);
        return p;
    }

    /**
     * 获取服务器列表结束包
     *
     * @return 服务器列表结束包
     */
    public static Packet getEndOfServerList() {
        OutPacket p = OutPacket.create(SendOpcode.SERVERLIST);
        p.writeByte(0xFF);
        return p;
    }

    /**
     * 获取服务器状态包
     * <p>
     * status 可能的值:<br>
     * 0 - 正常<br>
     * 1 - 人口众多<br>
     * 2 - 满员
     *
     * @param status 服务器状态
     * @return 服务器状态包
     */
    public static Packet getServerStatus(int status) {
        OutPacket p = OutPacket.create(SendOpcode.SERVERSTATUS);
        p.writeShort(status);
        return p;
    }

    /**
     * 获取服务器 IP 包
     *
     * @param inetAddr 服务器 IP 地址
     * @param port     端口
     * @param clientId 客户端 ID
     * @return 服务器 IP 包
     */
    public static Packet getServerIP(InetAddress inetAddr, int port, int clientId) {
        final OutPacket p = OutPacket.create(SendOpcode.SERVER_IP);
        p.writeShort(0);
        byte[] addr = inetAddr.getAddress();
        p.writeBytes(addr);
        p.writeShort(port);
        p.writeInt(clientId);
        p.writeBytes(new byte[]{0, 0, 0, 0, 0});
        return p;
    }

    /**
     * 获取频道切换包
     *
     * @param inetAddr 新频道的 IP 地址
     * @param port     端口
     * @return 频道切换包
     */
    public static Packet getChannelChange(InetAddress inetAddr, int port) {
        final OutPacket p = OutPacket.create(SendOpcode.CHANGE_CHANNEL);
        p.writeByte(1);
        byte[] addr = inetAddr.getAddress();
        p.writeBytes(addr);
        p.writeShort(port);
        return p;
    }

    /**
     * 获取角色列表包
     *
     * @param c        客户端对象
     * @param serverId 服务器 ID
     * @param status   角色列表请求结果状态
     * @return 角色列表包
     */
    public static Packet getCharList(Client c, int serverId, int status) {
        final OutPacket p = OutPacket.create(SendOpcode.CHARLIST);
        p.writeByte(status);
        List<Character> chars = c.loadCharacters(serverId);
        p.writeByte((byte) chars.size());
        for (Character chr : chars) {
            PacketHelper.addCharEntry(p, chr, false);
        }

        p.writeByte(GameConfig.getServerBoolean("enable_pic") && !c.canBypassPic() ? (c.getPic() == null || c.getPic().equals("") ? 0 : 1) : 2);
        p.writeInt(GameConfig.getServerBoolean("collective_chr_slot") ? chars.size() + c.getAvailableCharacterSlots() : c.getCharacterSlots());
        return p;
    }

    /**
     * 获取重新登录响应包
     *
     * @return 重新登录响应包
     */
    public static Packet getRelogResponse() {
        OutPacket p = OutPacket.create(SendOpcode.RELOG_RESPONSE);
        p.writeByte(1);
        return p;
    }

    /**
     * 发送访客服务条款
     * @return 数据包
     */
    public static Packet sendGuestTOS() {
        final OutPacket p = OutPacket.create(SendOpcode.GUEST_ID_LOGIN);
        p.writeShort(0x100);
        p.writeInt(Randomizer.nextInt(999999));
        p.writeLong(0);
        p.writeLong(PacketHelper.getTime(-2));
        p.writeLong(PacketHelper.getTime(System.currentTimeMillis()));
        p.writeInt(0);
        p.writeString("http://maplesolaxia.com");
        return p;
    }

    /**
     * 发送推荐服务器
     * @param worlds 推荐服务器列表
     * @return 数据包
     */
    public static Packet sendRecommended(List<Pair<Integer, String>> worlds) {
        final OutPacket p = OutPacket.create(SendOpcode.RECOMMENDED_WORLD_MESSAGE);
        p.writeByte(worlds.size());//size
        for (Pair<Integer, String> world : worlds) {
            p.writeInt(world.getLeft());
            p.writeString(world.getRight());
        }
        return p;
    }

    /**
     * 选择世界
     * @param world 世界ID
     * @return 数据包
     */
    public static Packet selectWorld(int world) {
        final OutPacket p = OutPacket.create(SendOpcode.LAST_CONNECTED_WORLD);
        p.writeInt(world);
        return p;
    }

    /**
     * 显示所有角色
     * @param totalWorlds 总世界数
     * @param totalChrs 总角色数
     * @return 数据包
     */
    public static Packet showAllCharacter(int totalWorlds, int totalChrs) {
        OutPacket p = OutPacket.create(SendOpcode.VIEW_ALL_CHAR);
        p.writeByte(totalChrs > 0 ? 1 : 5); // 2: already connected to server, 3 : unk error (view-all-characters), 5 : cannot find any
        p.writeInt(totalWorlds);
        p.writeInt(totalChrs);
        return p;
    }

    /**
     * 显示所有角色信息
     * @param worldid 世界ID
     * @param chars 角色列表
     * @param usePic 是否使用PIC
     * @return 数据包
     */
    public static Packet showAllCharacterInfo(int worldid, List<Character> chars, boolean usePic) {
        final OutPacket p = OutPacket.create(SendOpcode.VIEW_ALL_CHAR);
        p.writeByte(0);
        p.writeByte(worldid);
        p.writeByte(chars.size());
        for (Character chr : chars) {
            PacketHelper.addCharEntry(p, chr, true);
        }
        p.writeByte(usePic ? 1 : 2);
        return p;
    }

    /**
     * 添加新角色条目
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet addNewCharEntry(Character chr) {
        final OutPacket p = OutPacket.create(SendOpcode.ADD_NEW_CHAR_ENTRY);
        p.writeByte(0);
        PacketHelper.addCharEntry(p, chr, false);
        return p;
    }

    /**
     * 角色删除响应
     * State :
     * 0x00 = 成功
     * 0x06 = 登录游戏遇到问题？
     * 0x09 = 未知错误
     * 0x0A = 由于服务器连接请求过多，无法处理。
     * 0x12 = 无效生日
     * 0x14 = 错误 pic
     * 0x16 = 无法删除公会会长。
     * 0x18 = 无法删除有待处理婚礼的角色。
     * 0x1A = 无法删除有待处理世界转移的角色。
     * 0x1D = 无法删除拥有家族的角色。
     *
     * @param cid   角色ID
     * @param state 状态码
     * @return 删除角色响应包
     */
    public static Packet deleteCharResponse(int cid, int state) {
        final OutPacket p = OutPacket.create(SendOpcode.DELETE_CHAR_RESPONSE);
        p.writeInt(cid);
        p.writeByte(state);
        return p;
    }

    /**
     * 角色名称响应
     * @param charname 角色名称
     * @param nameUsed 名称是否已使用
     * @return 数据包
     */
    public static Packet charNameResponse(String charname, boolean nameUsed) {
        final OutPacket p = OutPacket.create(SendOpcode.CHAR_NAME_RESPONSE);
        p.writeString(charname);
        p.writeByte(nameUsed ? 1 : 0);
        return p;
    }

    /**
     * 发送 MapleLife 角色信息
     * @return 数据包
     */
    public static Packet sendMapleLifeCharacterInfo() {
        final OutPacket p = OutPacket.create(SendOpcode.MAPLELIFE_RESULT);
        p.writeInt(0);
        return p;
    }

    /**
     * 发送 MapleLife 名称错误
     * @return 数据包
     */
    public static Packet sendMapleLifeNameError() {
        OutPacket p = OutPacket.create(SendOpcode.MAPLELIFE_RESULT);
        p.writeInt(2);
        p.writeInt(3);
        p.writeByte(0);
        return p;
    }

    /**
     * 发送 MapleLife 错误
     * @param code 错误代码
     * @return 数据包
     */
    public static Packet sendMapleLifeError(int code) {
        OutPacket p = OutPacket.create(SendOpcode.MAPLELIFE_ERROR);
        p.writeByte(0);
        p.writeInt(code);
        return p;
    }

    /**
     * 启用举报
     * @return 数据包
     */
    public static Packet enableReport() {
        OutPacket p = OutPacket.create(SendOpcode.CLAIM_STATUS_CHANGED);
        p.writeByte(1);
        return p;
    }

    /**
     * 发送举报响应
     * <p>
     * mode 可能的值:<br>
     * 0: 您已成功举报该用户。<br>
     * 1: 无法找到该用户。<br>
     * 2: 您每天只能举报用户 10 次。<br>
     * 3: 您已被用户举报给 GM。<br>
     * 4: 由于未知原因，您的请求未通过。请稍后再试。<br>
     *
     * @param mode 模式
     * @return 举报响应包
     */
    public static Packet reportResponse(byte mode) {
        final OutPacket p = OutPacket.create(SendOpcode.SUE_CHARACTER_RESULT);
        p.writeByte(mode);
        return p;
    }

    /**
     * 更新性别
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet updateGender(Character chr) {
        OutPacket p = OutPacket.create(SendOpcode.SET_GENDER);
        p.writeByte(chr.getGender());
        return p;
    }

    /**
     * 发送金币限制
     * @return 数据包
     */
    public static Packet sendMesoLimit() {
        final OutPacket p = OutPacket.create(SendOpcode.TRADE_MONEY_LIMIT); // 15级以下玩家每天只能交易100万金币
        return p;
    }

    /**
     * 更新 HP/MP 警告
     * @param hp HP 百分比
     * @param mp MP 百分比
     * @return 数据包
     */
    public static Packet updateHpMpAlert(byte hp, byte mp) {
        OutPacket p = OutPacket.create(SendOpcode.UPDATE_HPMPAALERT);
        p.writeByte(hp);
        p.writeByte(mp);
        return p;
    }

    /**
     * 发送世界转移规则
     * @param error 错误代码
     * @param c 客户端对象
     * @return 数据包
     */
    public static Packet sendWorldTransferRules(int error, Client c) {
        final OutPacket p = OutPacket.create(SendOpcode.CASHSHOP_CHECK_TRANSFER_WORLD_POSSIBLE_RESULT);
        p.writeInt(0); //ignored
        p.writeByte(error);
        p.writeInt(0);
        p.writeBool(error == 0); //0 = ?, otherwise list servers
        if (error == 0) {
            List<World> worlds = Server.getInstance().getWorlds();
            p.writeInt(worlds.size());
            for (World world : worlds) {
                p.writeString(GameConstants.WORLD_NAMES[world.getId()]);
            }
        }
        return p;
    }
}
