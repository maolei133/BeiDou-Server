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

    public static Packet movePet(int cid, int pid, byte slot, List<LifeMovementFragment> moves) {
        final OutPacket p = OutPacket.create(SendOpcode.MOVE_PET);
        p.writeInt(cid);
        p.writeByte(slot);
        p.writeInt(pid);
        PacketHelper.serializeMovementList(p, moves);
        return p;
    }

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

    public static Packet petFoodResponse(int cid, byte index, boolean success, boolean balloonType) {
        final OutPacket p = OutPacket.create(SendOpcode.PET_COMMAND);
        p.writeInt(cid);
        p.writeByte(index);
        p.writeByte(1);
        p.writeBool(success);
        p.writeBool(balloonType);
        return p;
    }

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

    public static Packet showOwnPetLevelUp(byte index) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_ITEM_GAIN_INCHAT);
        p.writeByte(4);
        p.writeByte(0);
        p.writeByte(index); // Pet Index
        return p;
    }

    public static Packet showPetLevelUp(Character chr, byte index) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_FOREIGN_EFFECT);
        p.writeInt(chr.getId());
        p.writeByte(4);
        p.writeByte(0);
        p.writeByte(index);
        return p;
    }

    public static Packet changePetName(Character chr, String newname, int slot) {
        OutPacket p = OutPacket.create(SendOpcode.PET_NAMECHANGE);
        p.writeInt(chr.getId());
        p.writeByte(0);
        p.writeString(newname);
        p.writeByte(0);
        return p;
    }

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
