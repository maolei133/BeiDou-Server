package org.gms.util.packets;

import org.gms.net.opcodes.SendOpcode;
import org.gms.net.packet.OutPacket;
import org.gms.net.packet.Packet;

/**
 * AdminPackets
 * 处理 GM 警告、封禁、测试包等相关的数据包构建
 */
public class AdminPackets {

    /**
     * 获取 GM 效果包 (如隐藏、封禁等)
     * <p>
     * type 可能的值:<br>
     * 0x04: 您已成功阻止访问。<br>
     * 0x05: 解除封锁成功。<br>
     * 0x06 (Mode 0): 您已成功从排名中删除该名称。<br>
     * 0x06 (Mode 1): 您输入了无效的角色名称。<br>
     * 0x10: GM 隐藏，mode 决定是否开启。<br>
     * 0x1E (Mode 0): 发送警告失败<br>
     * 0x1E (Mode 1): 发送警告成功<br>
     * 0x13 (Mode 0): + mapid<br>
     * 0x13 (Mode 1): + ch (FF = 无法找到商人)
     *
     * @param type 类型
     * @param mode 模式
     * @return GM 效果包
     */
    public static Packet getGMEffect(int type, byte mode) {
        OutPacket p = OutPacket.create(SendOpcode.ADMIN_RESULT);
        p.writeByte(type);
        p.writeByte(mode);
        return p;
    }

    public static Packet getPermBan(byte reason) {
        final OutPacket p = OutPacket.create(SendOpcode.LOGIN_STATUS);
        p.writeByte(2); // Account is banned
        p.writeByte(0);
        p.writeInt(0);
        p.writeByte(0);
        p.writeLong(PacketHelper.getTime(-1));
        return p;
    }

    public static Packet getTempBan(long timestampTill, byte reason) {
        OutPacket p = OutPacket.create(SendOpcode.LOGIN_STATUS);
        p.writeByte(2);
        p.writeByte(0);
        p.writeInt(0);
        p.writeByte(reason);
        p.writeLong(PacketHelper.getTime(timestampTill));
        return p;
    }

    public static Packet sendPolice() {
        final OutPacket p = OutPacket.create(SendOpcode.FAKE_GM_NOTICE);
        p.writeByte(0);
        return p;
    }

    public static Packet sendPolice(String text) {
        final OutPacket p = OutPacket.create(SendOpcode.DATA_CRC_CHECK_FAILED);
        p.writeString(text);
        return p;
    }

    public static Packet findMerchantResponse(boolean map, int extra) {
        final OutPacket p = OutPacket.create(SendOpcode.ADMIN_RESULT);
        p.writeByte(0x13);
        p.writeByte(map ? 0 : 1); //00 = mapid, 01 = ch
        if (map) {
            p.writeInt(extra);
        } else {
            p.writeByte(extra); //-1 = unable to find
        }
        p.writeByte(0);
        return p;
    }

    public static Packet disableMinimap() {
        final OutPacket p = OutPacket.create(SendOpcode.ADMIN_RESULT);
        p.writeShort(0x1C);
        return p;
    }
}
