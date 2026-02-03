package org.gms.util.packets;

import org.gms.client.Character;
import org.gms.client.Stat;
import org.gms.client.inventory.Pet;
import org.gms.net.opcodes.SendOpcode;
import org.gms.net.packet.OutPacket;
import org.gms.net.packet.Packet;
import org.gms.server.movement.LifeMovementFragment;

import java.util.List;

/**
 * PetPackets
 * 处理宠物生成、移动、对话、升级等相关的数据包构建
 */
public class PetPackets {

    /**
     * 显示宠物
     * @param chr 角色对象
     * @param pet 宠物对象
     * @param remove 是否移除
     * @param hunger 是否饥饿
     * @return 数据包
     */
    public static Packet showPet(Character chr, Pet pet, boolean remove, boolean hunger) {
        OutPacket p = OutPacket.create(SendOpcode.SPAWN_PET);
        p.writeInt(chr.getId());
        p.writeByte(chr.getPetIndex(pet));
        if (remove) {
            p.writeByte(0);
            p.writeBool(hunger);
        } else {
            PacketHelper.addPetInfo(p, pet, true);
        }
        return p;
    }

    /**
     * 移动宠物
     * @param cid 角色ID
     * @param pid 宠物ID
     * @param slot 槽位
     * @param moves 移动列表
     * @return 数据包
     */
    public static Packet movePet(int cid, int pid, byte slot, List<LifeMovementFragment> moves) {
        final OutPacket p = OutPacket.create(SendOpcode.MOVE_PET);
        p.writeInt(cid);
        p.writeByte(slot);
        p.writeInt(pid);
        PacketHelper.serializeMovementList(p, moves);
        return p;
    }

    /**
     * 宠物聊天
     * @param cid 角色ID
     * @param index 索引
     * @param act 动作
     * @param text 文本
     * @return 数据包
     */
    public static Packet petChat(int cid, byte index, int act, String text) {
        final OutPacket p = OutPacket.create(SendOpcode.PET_CHAT);
        p.writeInt(cid);
        p.writeByte(index);
        p.writeByte(0);
        p.writeByte(act);
        p.writeString(text);
        p.writeByte(0);
        return p;
    }

    /**
     * 宠物食物响应
     * @param cid 角色ID
     * @param index 索引
     * @param success 是否成功
     * @param balloonType 气泡类型
     * @return 数据包
     */
    public static Packet petFoodResponse(int cid, byte index, boolean success, boolean balloonType) {
        final OutPacket p = OutPacket.create(SendOpcode.PET_COMMAND);
        p.writeInt(cid);
        p.writeByte(index);
        p.writeByte(1);
        p.writeBool(success);
        p.writeBool(balloonType);
        return p;
    }

    /**
     * 命令响应
     * @param cid 角色ID
     * @param index 索引
     * @param talk 是否说话
     * @param animation 动画
     * @param balloonType 气泡类型
     * @return 数据包
     */
    public static Packet commandResponse(int cid, byte index, boolean talk, int animation, boolean balloonType) {
        final OutPacket p = OutPacket.create(SendOpcode.PET_COMMAND);
        p.writeInt(cid);
        p.writeByte(index);
        p.writeByte(0);
        p.writeByte(animation);
        p.writeBool(!talk);
        p.writeBool(balloonType);
        return p;
    }

    /**
     * 显示自身宠物升级
     * @param index 索引
     * @return 数据包
     */
    public static Packet showOwnPetLevelUp(byte index) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_ITEM_GAIN_INCHAT);
        p.writeByte(4);
        p.writeByte(0);
        p.writeByte(index); // 宠物索引
        return p;
    }

    /**
     * 显示宠物升级
     * @param chr 角色对象
     * @param index 索引
     * @return 数据包
     */
    public static Packet showPetLevelUp(Character chr, byte index) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_FOREIGN_EFFECT);
        p.writeInt(chr.getId());
        p.writeByte(4);
        p.writeByte(0);
        p.writeByte(index);
        return p;
    }

    /**
     * 更改宠物名称
     * @param chr 角色对象
     * @param newname 新名称
     * @param slot 槽位
     * @return 数据包
     */
    public static Packet changePetName(Character chr, String newname, int slot) {
        OutPacket p = OutPacket.create(SendOpcode.PET_NAMECHANGE);
        p.writeInt(chr.getId());
        p.writeByte(0);
        p.writeString(newname);
        p.writeByte(0);
        return p;
    }

    /**
     * 加载例外列表
     * @param cid 角色ID
     * @param petId 宠物ID
     * @param petIdx 宠物索引
     * @param data 数据列表
     * @return 数据包
     */
    public static Packet loadExceptionList(final int cid, final int petId, final byte petIdx, final List<Integer> data) {
        final OutPacket p = OutPacket.create(SendOpcode.PET_EXCEPTION_LIST);
        p.writeInt(cid);
        p.writeByte(petIdx);
        p.writeLong(petId);
        p.writeByte(data.size());
        for (final Integer ids : data) {
            p.writeInt(ids);
        }
        return p;
    }

    /**
     * 宠物状态更新
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet petStatUpdate(Character chr) {
        final OutPacket p = OutPacket.create(SendOpcode.STAT_CHANGED);
        int mask = 0;
        mask |= Stat.PET.getValue();
        p.writeByte(0);
        p.writeInt(mask);
        Pet[] pets = chr.getPets();
        for (int i = 0; i < 3; i++) {
            if (pets[i] != null) {
                p.writeLong(pets[i].getUniqueId());
            } else {
                p.writeLong(0);
            }
        }
        p.writeByte(0);
        return p;
    }
}
