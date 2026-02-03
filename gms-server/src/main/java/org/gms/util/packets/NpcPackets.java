package org.gms.util.packets;

import org.gms.client.Client;
import org.gms.constants.id.NpcId;
import org.gms.constants.inventory.ItemConstants;
import org.gms.client.inventory.InventoryType;
import org.gms.net.opcodes.SendOpcode;
import org.gms.net.packet.OutPacket;
import org.gms.net.packet.Packet;
import org.gms.server.ItemInformationProvider;
import org.gms.server.ShopItem;
import org.gms.server.life.NPC;
import org.gms.server.life.PlayerNPC;
import org.gms.util.HexTool;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * NpcPackets
 * 处理 NPC 生成、对话、商店等相关的数据包构建
 */
public class NpcPackets {

    /**
     * 获取生成 NPC 包
     *
     * @param life NPC 对象
     * @return 生成 NPC 包
     */
    public static Packet spawnNPC(NPC life) {
        OutPacket p = OutPacket.create(SendOpcode.SPAWN_NPC);
        p.writeInt(life.getObjectId());
        p.writeInt(life.getId());
        p.writeShort(life.getPosition().x);
        p.writeShort(life.getCy());
        p.writeBool(life.getF() != 1);
        p.writeShort(life.getFh());
        p.writeShort(life.getRx0());
        p.writeShort(life.getRx1());
        p.writeByte(1);
        return p;
    }

    /**
     * 获取生成 NPC 请求控制包
     *
     * @param life    NPC 对象
     * @param miniMap 是否在小地图显示
     * @return 生成 NPC 请求控制包
     */
    public static Packet spawnNPCRequestController(NPC life, boolean miniMap) {
        OutPacket p = OutPacket.create(SendOpcode.SPAWN_NPC_REQUEST_CONTROLLER);
        p.writeByte(1);
        p.writeInt(life.getObjectId());
        p.writeInt(life.getId());
        p.writeShort(life.getPosition().x);
        p.writeShort(life.getCy());
        p.writeBool(life.getF() != 1);
        p.writeShort(life.getFh());
        p.writeShort(life.getRx0());
        p.writeShort(life.getRx1());
        p.writeBool(miniMap);
        return p;
    }

    /**
     * 获取移除 NPC 包
     *
     * @param objId NPC 对象 ID
     * @return 移除 NPC 包
     */
    public static Packet removeNPC(int objId) {
        OutPacket p = OutPacket.create(SendOpcode.REMOVE_NPC);
        p.writeInt(objId);
        return p;
    }

    /**
     * 获取移除 NPC 控制包
     *
     * @param objId NPC 对象 ID
     * @return 移除 NPC 控制包
     */
    public static Packet removeNPCController(int objId) {
        OutPacket p = OutPacket.create(SendOpcode.SPAWN_NPC_REQUEST_CONTROLLER);
        p.writeByte(0);
        p.writeInt(objId);
        return p;
    }

    /**
     * 获取 NPC 对话包
     * <p>
     * speaker 可能的值:<br>
     * 0: NPC 说话 (左)<br>
     * 1: NPC 说话 (右)<br>
     * 2: 玩家说话 (左)<br>
     * 3: 玩家说话 (左)<br>
     *
     * @param npc      NPC ID
     * @param msgType  消息类型
     * @param talk     对话内容
     * @param endBytes 结束字节
     * @param speaker  说话者
     * @return NPC 对话包
     */
    public static Packet getNPCTalk(int npc, byte msgType, String talk, String endBytes, byte speaker) {
        final OutPacket p = OutPacket.create(SendOpcode.NPC_TALK);
        p.writeByte(4);
        p.writeInt(npc);
        p.writeByte(msgType);
        p.writeByte(speaker);
        p.writeString(talk);
        p.writeBytes(HexTool.toBytes(endBytes));
        return p;
    }

    public static Packet getDimensionalMirror(String talk) {
        final OutPacket p = OutPacket.create(SendOpcode.NPC_TALK);
        p.writeByte(4);
        p.writeInt(NpcId.DIMENSIONAL_MIRROR);
        p.writeByte(0x0E);
        p.writeByte(0);
        p.writeInt(0);
        p.writeString(talk);
        return p;
    }

    public static Packet getNPCTalkStyle(int npc, String talk, int[] styles) {
        final OutPacket p = OutPacket.create(SendOpcode.NPC_TALK);
        p.writeByte(4);
        p.writeInt(npc);
        p.writeByte(7);
        p.writeByte(0);
        p.writeString(talk);
        p.writeByte(styles.length);
        for (int style : styles) {
            p.writeInt(style);
        }
        return p;
    }

    public static Packet getNPCTalkNum(int npc, String talk, int def, int min, int max) {
        final OutPacket p = OutPacket.create(SendOpcode.NPC_TALK);
        p.writeByte(4);
        p.writeInt(npc);
        p.writeByte(3);
        p.writeByte(0);
        p.writeString(talk);
        p.writeInt(def);
        p.writeInt(min);
        p.writeInt(max);
        p.writeInt(0);
        return p;
    }

    public static Packet getNPCTalkNum(int npc, String talk, int def, int min, int max, byte speaker) {
        final OutPacket p = OutPacket.create(SendOpcode.NPC_TALK);
        p.writeByte(4);
        p.writeInt(npc);
        p.writeByte(3);
        p.writeByte(speaker);
        p.writeString(talk);
        p.writeInt(def);
        p.writeInt(min);
        p.writeInt(max);
        p.writeInt(0);
        return p;
    }

    public static Packet getNPCTalkText(int npc, String talk, String def) {
        final OutPacket p = OutPacket.create(SendOpcode.NPC_TALK);
        p.writeByte(4);
        p.writeInt(npc);
        p.writeByte(2);
        p.writeByte(0);
        p.writeString(talk);
        p.writeString(def);
        p.writeInt(0);
        return p;
    }

    public static Packet getNPCTalkText(int npc, String talk, String def, byte speaker) {
        final OutPacket p = OutPacket.create(SendOpcode.NPC_TALK);
        p.writeByte(4);
        p.writeInt(npc);
        p.writeByte(2);
        p.writeByte(speaker);
        p.writeString(talk);
        p.writeString(def);
        p.writeInt(0);
        return p;
    }

    public static Packet OnAskQuiz(int nSpeakerTypeID, int nSpeakerTemplateID, int nResCode, String sTitle, String sProblemText, String sHintText, int nMinInput, int nMaxInput, int tRemainInitialQuiz) {
        OutPacket p = OutPacket.create(SendOpcode.NPC_TALK);
        p.writeByte(nSpeakerTypeID);
        p.writeInt(nSpeakerTemplateID);
        p.writeByte(0x6);
        p.writeByte(0);
        p.writeByte(nResCode);
        if (nResCode == 0x0) {
            p.writeString(sTitle);
            p.writeString(sProblemText);
            p.writeString(sHintText);
            p.writeShort(nMinInput);
            p.writeShort(nMaxInput);
            p.writeInt(tRemainInitialQuiz);
        }
        return p;
    }

    public static Packet OnAskSpeedQuiz(int nSpeakerTypeID, int nSpeakerTemplateID, int nResCode, int nType, int dwAnswer, int nCorrect, int nRemain, int tRemainInitialQuiz) {
        OutPacket p = OutPacket.create(SendOpcode.NPC_TALK);
        p.writeByte(nSpeakerTypeID);
        p.writeInt(nSpeakerTemplateID);
        p.writeByte(0x7);
        p.writeByte(0);
        p.writeByte(nResCode);
        if (nResCode == 0x0) {
            p.writeInt(nType);
            p.writeInt(dwAnswer);
            p.writeInt(nCorrect);
            p.writeInt(nRemain);
            p.writeInt(tRemainInitialQuiz);
        }
        return p;
    }

    public static Packet getNPCShop(Client c, int sid, List<ShopItem> items) {
        ItemInformationProvider ii = ItemInformationProvider.getInstance();
        final OutPacket p = OutPacket.create(SendOpcode.OPEN_NPC_SHOP);
        p.writeInt(sid);
        p.writeShort(items.size());
        for (ShopItem item : items) {
            p.writeInt(item.getItemId());
            p.writeInt(item.getPrice());
            p.writeInt(item.getPrice() == 0 ? item.getPitch() : 0);
            p.writeInt(0);
            p.writeInt(0);
            if (!ItemConstants.isRechargeable(item.getItemId())) {
                p.writeShort(1);
                p.writeShort(item.getBuyable());
            } else {
                p.writeShort(0);
                p.writeInt(0);
                p.writeShort(PacketHelper.doubleToShortBits(ii.getUnitPrice(item.getItemId())));
                p.writeShort(ii.getSlotMax(c, item.getItemId()));
            }
        }
        return p;
    }

    /* 00 = /
     * 01 = You don't have enough in stock
     * 02 = You do not have enough mesos
     * 03 = Please check if your inventory is full or not
     * 05 = You don't have enough in stock
     * 06 = Due to an error, the trade did not happen
     * 07 = Due to an error, the trade did not happen
     * 08 = /
     * 0D = You need more items
     * 0E = CRASH; LENGTH NEEDS TO BE LONGER :O
     */
    public static Packet shopTransaction(byte code) {
        OutPacket p = OutPacket.create(SendOpcode.CONFIRM_SHOP_TRANSACTION);
        p.writeByte(code);
        return p;
    }

    public static Packet shopErrorMessage(int error, int type) {
        final OutPacket p = OutPacket.create(SendOpcode.PLAYER_INTERACTION);
        p.writeByte(0x0A);
        p.writeByte(type);
        p.writeByte(error);
        return p;
    }

    public static Packet spawnPlayerNPC(PlayerNPC npc) {
        final OutPacket p = OutPacket.create(SendOpcode.SPAWN_NPC_REQUEST_CONTROLLER);
        p.writeByte(1);
        p.writeInt(npc.getObjectId());
        p.writeInt(npc.getScriptId());
        p.writeShort(npc.getPosition().x);
        p.writeShort(npc.getCY());
        p.writeByte(npc.getDir());
        p.writeShort(npc.getFH());
        p.writeShort(npc.getRX0());
        p.writeShort(npc.getRX1());
        p.writeByte(1);
        return p;
    }

    public static Packet getPlayerNPC(PlayerNPC npc) {
        final OutPacket p = OutPacket.create(SendOpcode.IMITATED_NPC_DATA);
        p.writeByte(0x01);
        p.writeInt(npc.getScriptId());
        p.writeString(npc.getName());
        p.writeByte(npc.getGender());
        p.writeByte(npc.getSkin());
        p.writeInt(npc.getFace());
        p.writeByte(0);
        p.writeInt(npc.getHair());
        Map<Short, Integer> equip = npc.getEquips();
        Map<Short, Integer> myEquip = new LinkedHashMap<>();
        Map<Short, Integer> maskedEquip = new LinkedHashMap<>();
        for (short position : equip.keySet()) {
            short pos = (byte) (position * -1);
            if (pos < 100 && myEquip.get(pos) == null) {
                myEquip.put(pos, equip.get(position));
            } else if ((pos > 100 && pos != 111) || pos == -128) {
                pos -= 100;
                if (myEquip.get(pos) != null) {
                    maskedEquip.put(pos, myEquip.get(pos));
                }
                myEquip.put(pos, equip.get(position));
            } else if (myEquip.get(pos) != null) {
                maskedEquip.put(pos, equip.get(position));
            }
        }
        for (Entry<Short, Integer> entry : myEquip.entrySet()) {
            p.writeByte(entry.getKey());
            p.writeInt(entry.getValue());
        }
        p.writeByte(0xFF);
        for (Entry<Short, Integer> entry : maskedEquip.entrySet()) {
            p.writeByte(entry.getKey());
            p.writeInt(entry.getValue());
        }
        p.writeByte(0xFF);
        Integer cWeapon = equip.get((byte) -111);
        if (cWeapon != null) {
            p.writeInt(cWeapon);
        } else {
            p.writeInt(0);
        }
        for (int i = 0; i < 3; i++) {
            p.writeInt(0);
        }
        return p;
    }

    public static Packet removePlayerNPC(int oid) {
        final OutPacket p = OutPacket.create(SendOpcode.IMITATED_NPC_DATA);
        p.writeByte(0x00);
        p.writeInt(oid);
        return p;
    }

    /**
     * 使提供的 NPC 设置为可编写脚本，通知客户端搜索这些 NPC 的 js 脚本，
     * 即使它们在 wz 文件中已有条目。
     *
     * @param scriptableNpcIds 要启用脚本的 NPC ID。
     * @return 使提供的 NPC 可编写脚本的数据包。
     */
    public static Packet setNPCScriptable(Map<Integer, String> scriptableNpcIds) {
        OutPacket p = OutPacket.create(SendOpcode.SET_NPC_SCRIPTABLE);
        p.writeByte(scriptableNpcIds.size());
        scriptableNpcIds.forEach((id, name) -> {
            p.writeInt(id);
            p.writeString(name);
            p.writeInt(0); // start time
            p.writeInt(Integer.MAX_VALUE); // end time
        });
        return p;
    }
}
