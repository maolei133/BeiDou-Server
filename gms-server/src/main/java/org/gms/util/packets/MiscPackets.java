package org.gms.util.packets;

import org.gms.client.BuffStat;
import org.gms.client.Character;
import org.gms.client.Disease;
import org.gms.client.MonsterBook;
import org.gms.client.Mount;
import org.gms.client.QuestStatus;
import org.gms.client.SkillMacro;
import org.gms.client.Stat;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.Pet;
import org.gms.client.keybind.KeyBinding;
import org.gms.client.keybind.QuickslotBinding;
import org.gms.client.status.MonsterStatus;
import org.gms.constants.game.GameConstants;
import org.gms.constants.id.ItemId;
import org.gms.constants.skills.Buccaneer;
import org.gms.constants.skills.Corsair;
import org.gms.constants.skills.ThunderBreaker;
import org.gms.model.pojo.NewYearCardRecord;
import org.gms.net.opcodes.SendOpcode;
import org.gms.net.packet.ByteBufOutPacket;
import org.gms.net.packet.OutPacket;
import org.gms.net.packet.Packet;
import org.gms.net.server.Server;
import org.gms.net.server.guild.Alliance;
import org.gms.net.server.guild.Guild;
import org.gms.server.ItemInformationProvider;
import org.gms.server.events.gm.Snowball;
import org.gms.server.life.MobSkill;
import org.gms.util.HexTool;
import org.gms.util.Pair;
import org.gms.util.Randomizer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * MiscPackets
 * 处理未分类的杂项数据包构建，如 TV、状态更新、技能、UI、任务、活动等
 */
public class MiscPackets {

    /**
     * 启用电视
     * @return 数据包
     */
    public static Packet enableTV() {
        OutPacket p = OutPacket.create(SendOpcode.ENABLE_TV);
        p.writeInt(0);
        p.writeByte(0);
        return p;
    }

    /**
     * 移除电视
     * @return 数据包
     */
    public static Packet removeTV() {
        return OutPacket.create(SendOpcode.REMOVE_TV);
    }

    /**
     * 发送电视
     * @param chr 角色对象
     * @param messages 消息列表
     * @param type 类型
     * @param partner 伙伴
     * @return 数据包
     */
    public static Packet sendTV(Character chr, List<String> messages, int type, Character partner) {
        final OutPacket p = OutPacket.create(SendOpcode.SEND_TV);
        p.writeByte(partner != null ? 3 : 1);
        p.writeByte(type); // 心 = 2  星 = 1  普通 = 0
        PacketHelper.addCharLook(p, chr, false);
        p.writeString(chr.getName());
        if (partner != null) {
            p.writeString(partner.getName());
        } else {
            p.writeShort(0);
        }
        for (int i = 0; i < messages.size(); i++) {
            if (i == 4 && messages.get(4).length() > 15) {
                p.writeString(messages.get(4).substring(0, 15));
            } else {
                p.writeString(messages.get(i));
            }
        }
        p.writeInt(1337);
        if (partner != null) {
            PacketHelper.addCharLook(p, partner, false);
        }
        return p;
    }

    /**
     * 启用动作
     * @return 数据包
     */
    public static Packet enableActions() {
        return updatePlayerStats(PacketHelper.EMPTY_STATUPDATE, true, null);
    }

    /**
     * 更新玩家状态
     * @param stats 状态列表
     * @param enableActions 是否启用动作
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet updatePlayerStats(List<Pair<Stat, Integer>> stats, boolean enableActions, Character chr) {
        OutPacket p = OutPacket.create(SendOpcode.STAT_CHANGED);
        p.writeBool(enableActions);
        int updateMask = 0;
        for (Pair<Stat, Integer> statupdate : stats) {
            updateMask |= statupdate.getLeft().getValue();
        }
        List<Pair<Stat, Integer>> mystats = stats;
        if (mystats.size() > 1) {
            mystats.sort((o1, o2) -> {
                int val1 = o1.getLeft().getValue();
                int val2 = o2.getLeft().getValue();
                return (val1 < val2 ? -1 : (val1 == val2 ? 0 : 1));
            });
        }
        p.writeInt(updateMask);
        for (Pair<Stat, Integer> statupdate : mystats) {
            if (statupdate.getLeft().getValue() >= 1) {
                if (statupdate.getLeft().getValue() == 0x1) {
                    p.writeByte(statupdate.getRight().byteValue());
                } else if (statupdate.getLeft().getValue() <= 0x4) {
                    p.writeInt(statupdate.getRight());
                } else if (statupdate.getLeft().getValue() < 0x20) {
                    p.writeByte(statupdate.getRight().shortValue());
                } else if (statupdate.getLeft().getValue() == 0x8000) {
                    if (GameConstants.hasSPTable(chr.getJob())) {
                        PacketHelper.addRemainingSkillInfo(p, chr);
                    } else {
                        p.writeShort(statupdate.getRight().shortValue());
                    }
                } else if (statupdate.getLeft().getValue() < 0xFFFF) {
                    p.writeShort(statupdate.getRight().shortValue());
                } else if (statupdate.getLeft().getValue() == 0x20000) {
                    p.writeShort(statupdate.getRight().shortValue());
                } else {
                    p.writeInt(statupdate.getRight());
                }
            }
        }
        return p;
    }

    /**
     * 获取角色信息
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet getCharInfo(Character chr) {
        final OutPacket p = OutPacket.create(SendOpcode.SET_FIELD);
        p.writeInt(chr.getClient().getChannel() - 1);
        p.writeByte(1);
        p.writeByte(1);
        p.writeShort(0);
        for (int i = 0; i < 3; i++) {
            p.writeInt(Randomizer.nextInt());
        }
        PacketHelper.addCharacterInfo(p, chr);
        p.writeLong(PacketHelper.getTime(System.currentTimeMillis()));
        return p;
    }

    /**
     * 角色信息
     * @param chr 角色对象
     * @return 数据包
     */
    public static Packet charInfo(Character chr) {
        final OutPacket p = OutPacket.create(SendOpcode.CHAR_INFO);
        p.writeInt(chr.getId());
        p.writeByte(chr.getLevel());
        p.writeShort(chr.getJob().getId());
        p.writeShort(chr.getFame());
        p.writeByte(chr.getMarriageRing() != null ? 1 : 0);
        String guildName = "";
        String allianceName = "";
        if (chr.getGuildId() > 0) {
            Guild mg = Server.getInstance().getGuild(chr.getGuildId());
            if (mg != null) {
                guildName = mg.getName();
                if (mg.getAllianceId() > 0) {
                    Alliance alliance = Server.getInstance().getAlliance(mg.getAllianceId());
                    if (alliance != null) {
                        allianceName = alliance.getName();
                    }
                }
            }
        }
        p.writeString(guildName);
        p.writeString(allianceName);
        p.writeByte(0);

        Pet[] pets = chr.getPets();
        Item inv = chr.getInventory(InventoryType.EQUIPPED).getItem((short) -114);
        for (int i = 0; i < 3; i++) {
            if (pets[i] != null) {
                p.writeByte(pets[i].getUniqueId());
                p.writeInt(pets[i].getItemId()); // 宠物ID
                p.writeString(pets[i].getName());
                p.writeByte(pets[i].getLevel()); // 宠物等级
                p.writeShort(pets[i].getTameness()); // 宠物亲密度
                p.writeByte(pets[i].getFullness()); // 宠物饱食度
                p.writeShort(0);
                p.writeInt(inv != null ? inv.getItemId() : 0);
            }
        }
        p.writeByte(0); // 宠物结束

        Item mount;
        if (chr.getMapleMount() != null && (mount = chr.getInventory(InventoryType.EQUIPPED).getItem((short) -18)) != null && ItemInformationProvider.getInstance().getEquipLevelReq(mount.getItemId()) <= chr.getLevel()) {
            Mount mmount = chr.getMapleMount();
            p.writeByte(mmount.getId()); // 坐骑
            p.writeInt(mmount.getLevel()); // 等级
            p.writeInt(mmount.getExp()); // 经验
            p.writeInt(mmount.getTiredness()); // 疲劳度
        } else {
            p.writeByte(0);
        }
        p.writeByte(chr.getCashShop().getWishList().size());
        for (int sn : chr.getCashShop().getWishList()) {
            p.writeInt(sn);
        }

        MonsterBook book = chr.getMonsterBook();
        p.writeInt(book.getBookLevel());
        p.writeInt(book.getNormalCard());
        p.writeInt(book.getSpecialCard());
        p.writeInt(book.getTotalCards());
        p.writeInt(chr.getMonsterBookCover() > 0 ? ItemInformationProvider.getInstance().getCardMobId(chr.getMonsterBookCover()) : 0);
        Item medal = chr.getInventory(InventoryType.EQUIPPED).getItem((short) -49);
        if (medal != null) {
            p.writeInt(medal.getItemId());
        } else {
            p.writeInt(0);
        }
        ArrayList<Short> medalQuests = new ArrayList<>();
        List<QuestStatus> completed = chr.getCompletedQuests();
        for (QuestStatus qs : completed) {
            if (qs.getQuest().getId() >= 29000) {
                medalQuests.add(qs.getQuest().getId());
            }
        }

        Collections.sort(medalQuests);
        p.writeShort(medalQuests.size());
        for (Short s : medalQuests) {
            p.writeShort(s);
        }
        return p;
    }

    /**
     * 给予Buff
     * @param buffid Buff ID
     * @param bufflength Buff时长
     * @param statups 状态提升列表
     * @return 数据包
     */
    public static Packet giveBuff(int buffid, int bufflength, List<Pair<BuffStat, Integer>> statups) {
        final OutPacket p = OutPacket.create(SendOpcode.GIVE_BUFF);
        boolean special = false;
        PacketHelper.writeLongMask(p, statups);
        for (Pair<BuffStat, Integer> statup : statups) {
            if (statup.getLeft().equals(BuffStat.MONSTER_RIDING) || statup.getLeft().equals(BuffStat.HOMING_BEACON)) {
                special = true;
            }
            p.writeShort(statup.getRight().shortValue());
            p.writeInt(buffid);
            p.writeInt(bufflength);
        }
        p.writeInt(0);
        p.writeByte(0);
        p.writeInt(statups.get(0).getRight());

        if (special) {
            p.skip(3);
        }
        return p;
    }

    /**
     * 给予外部Buff
     * @param chrId 角色ID
     * @param statups 状态提升列表
     * @return 数据包
     */
    public static Packet giveForeignBuff(int chrId, List<Pair<BuffStat, Integer>> statups) {
        OutPacket p = OutPacket.create(SendOpcode.GIVE_FOREIGN_BUFF);
        p.writeInt(chrId);
        PacketHelper.writeLongMask(p, statups);
        for (Pair<BuffStat, Integer> statup : statups) {
            p.writeShort(statup.getRight().shortValue());
        }
        p.writeInt(0);
        p.writeShort(0);
        return p;
    }

    /**
     * 取消Buff
     * @param statups 状态列表
     * @return 数据包
     */
    public static Packet cancelBuff(List<BuffStat> statups) {
        OutPacket p = OutPacket.create(SendOpcode.CANCEL_BUFF);
        PacketHelper.writeLongMaskFromList(p, statups);
        p.writeByte(1);
        return p;
    }

    /**
     * 取消外部Buff
     * @param chrId 角色ID
     * @param statups 状态列表
     * @return 数据包
     */
    public static Packet cancelForeignBuff(int chrId, List<BuffStat> statups) {
        OutPacket p = OutPacket.create(SendOpcode.CANCEL_FOREIGN_BUFF);
        p.writeInt(chrId);
        PacketHelper.writeLongMaskFromList(p, statups);
        return p;
    }

    /**
     * 给予Debuff
     * @param statups 状态列表
     * @param skill 技能
     * @return 数据包
     */
    public static Packet giveDebuff(List<Pair<Disease, Integer>> statups, MobSkill skill) {
        final OutPacket p = OutPacket.create(SendOpcode.GIVE_BUFF);
        PacketHelper.writeLongMaskD(p, statups);
        for (Pair<Disease, Integer> statup : statups) {
            p.writeShort(statup.getRight().shortValue());
            PacketHelper.writeMobSkillId(p, skill.getId());
            p.writeInt((int) skill.getDuration());
        }
        p.writeShort(0);
        p.writeShort(900);
        p.writeByte(1);
        return p;
    }

    /**
     * 给予外部Debuff
     * @param chrId 角色ID
     * @param statups 状态列表
     * @param skill 技能
     * @return 数据包
     */
    public static Packet giveForeignDebuff(int chrId, List<Pair<Disease, Integer>> statups, MobSkill skill) {
        OutPacket p = OutPacket.create(SendOpcode.GIVE_FOREIGN_BUFF);
        p.writeInt(chrId);
        PacketHelper.writeLongMaskD(p, statups);
        for (Pair<Disease, Integer> statup : statups) {
            if (statup.getLeft() == Disease.POISON) {
                p.writeShort(statup.getRight().shortValue());
            }
            PacketHelper.writeMobSkillId(p, skill.getId());
        }
        p.writeShort(0);
        p.writeShort(900);
        return p;
    }

    /**
     * 取消Debuff
     * @param mask 掩码
     * @return 数据包
     */
    public static Packet cancelDebuff(long mask) {
        OutPacket p = OutPacket.create(SendOpcode.CANCEL_BUFF);
        p.writeLong(0);
        p.writeLong(mask);
        p.writeByte(0);
        return p;
    }

    /**
     * 取消外部Debuff
     * @param cid 角色ID
     * @param mask 掩码
     * @return 数据包
     */
    public static Packet cancelForeignDebuff(int cid, long mask) {
        final OutPacket p = OutPacket.create(SendOpcode.CANCEL_FOREIGN_BUFF);
        p.writeInt(cid);
        p.writeLong(0);
        p.writeLong(mask);
        return p;
    }

    /**
     * 取消外部首个Debuff
     * @param cid 角色ID
     * @param mask 掩码
     * @return 数据包
     */
    public static Packet cancelForeignFirstDebuff(int cid, long mask) {
        final OutPacket p = OutPacket.create(SendOpcode.CANCEL_FOREIGN_BUFF);
        p.writeInt(cid);
        p.writeLong(mask);
        p.writeLong(0);
        return p;
    }

    /**
     * 给予外部缓慢Debuff
     * @param chrId 角色ID
     * @param statups 状态列表
     * @param skill 技能
     * @return 数据包
     */
    public static Packet giveForeignSlowDebuff(int chrId, List<Pair<Disease, Integer>> statups, MobSkill skill) {
        OutPacket p = OutPacket.create(SendOpcode.GIVE_FOREIGN_BUFF);
        p.writeInt(chrId);
        PacketHelper.writeLongMaskSlowD(p);
        for (Pair<Disease, Integer> statup : statups) {
            if (statup.getLeft() == Disease.POISON) {
                p.writeShort(statup.getRight().shortValue());
            }
            PacketHelper.writeMobSkillId(p, skill.getId());
        }
        p.writeShort(0);
        p.writeShort(900);
        return p;
    }

    /**
     * 取消外部缓慢Debuff
     * @param chrId 角色ID
     * @return 数据包
     */
    public static Packet cancelForeignSlowDebuff(int chrId) {
        final OutPacket p = OutPacket.create(SendOpcode.CANCEL_FOREIGN_BUFF);
        p.writeInt(chrId);
        PacketHelper.writeLongMaskSlowD(p);
        return p;
    }

    /**
     * 给予外部WK充能特效
     * @param cid 角色ID
     * @param buffid Buff ID
     * @param statups 状态列表
     * @return 数据包
     */
    public static Packet giveForeignWKChargeEffect(int cid, int buffid, List<Pair<BuffStat, Integer>> statups) {
        OutPacket p = OutPacket.create(SendOpcode.GIVE_FOREIGN_BUFF);
        p.writeInt(cid);
        PacketHelper.writeLongMask(p, statups);
        p.writeInt(buffid);
        p.writeShort(600);
        p.writeShort(1000);
        p.writeByte(1);
        return p;
    }

    /**
     * 给予海盗Buff
     * @param statups 状态列表
     * @param buffid Buff ID
     * @param duration 持续时间
     * @return 数据包
     */
    public static Packet givePirateBuff(List<Pair<BuffStat, Integer>> statups, int buffid, int duration) {
        OutPacket p = OutPacket.create(SendOpcode.GIVE_BUFF);
        boolean infusion = buffid == Buccaneer.SPEED_INFUSION || buffid == ThunderBreaker.SPEED_INFUSION || buffid == Corsair.SPEED_INFUSION;
        PacketHelper.writeLongMask(p, statups);
        p.writeShort(0);
        for (Pair<BuffStat, Integer> stat : statups) {
            p.writeInt(stat.getRight().shortValue());
            p.writeInt(buffid);
            p.skip(infusion ? 10 : 5);
            p.writeShort(duration);
        }
        p.skip(3);
        return p;
    }

    /**
     * 给予外部海盗Buff
     * @param cid 角色ID
     * @param buffid Buff ID
     * @param time 时间
     * @param statups 状态列表
     * @return 数据包
     */
    public static Packet giveForeignPirateBuff(int cid, int buffid, int time, List<Pair<BuffStat, Integer>> statups) {
        OutPacket p = OutPacket.create(SendOpcode.GIVE_FOREIGN_BUFF);
        boolean infusion = buffid == Buccaneer.SPEED_INFUSION || buffid == ThunderBreaker.SPEED_INFUSION || buffid == Corsair.SPEED_INFUSION;
        p.writeInt(cid);
        PacketHelper.writeLongMask(p, statups);
        p.writeShort(0);
        for (Pair<BuffStat, Integer> statup : statups) {
            p.writeInt(statup.getRight().shortValue());
            p.writeInt(buffid);
            p.skip(infusion ? 10 : 5);
            p.writeShort(time);
        }
        p.writeShort(0);
        p.writeByte(2);
        return p;
    }

    /**
     * 给予终极攻击
     * @param skillid 技能ID
     * @param time 时间
     * @return 数据包
     */
    public static Packet giveFinalAttack(int skillid, int time) {
        final OutPacket p = OutPacket.create(SendOpcode.GIVE_BUFF);
        p.writeLong(0);
        p.writeShort(0);
        p.writeByte(0);
        p.writeByte(0x80);
        p.writeInt(0);
        p.writeShort(1);
        p.writeInt(skillid);
        p.writeInt(time);
        p.writeInt(0);
        return p;
    }

    /**
     * 更新技能
     * @param skillId 技能ID
     * @param level 等级
     * @param masterlevel 大师等级
     * @param expiration 过期时间
     * @return 数据包
     */
    public static Packet updateSkill(int skillId, int level, int masterlevel, long expiration) {
        OutPacket p = OutPacket.create(SendOpcode.UPDATE_SKILLS);
        p.writeByte(1);
        p.writeShort(1);
        p.writeInt(skillId);
        p.writeInt(level);
        p.writeInt(masterlevel);
        PacketHelper.addExpirationTime(p, expiration);
        p.writeByte(4);
        return p;
    }

    /**
     * 技能冷却
     * @param sid 技能ID
     * @param time 时间
     * @return 数据包
     */
    public static Packet skillCooldown(int sid, int time) {
        final OutPacket p = OutPacket.create(SendOpcode.COOLDOWN);
        p.writeInt(sid);
        p.writeShort(time);
        return p;
    }

    /**
     * 技能书结果
     * @param chr 角色对象
     * @param skillid 技能ID
     * @param maxlevel 最大等级
     * @param canuse 是否可用
     * @param success 是否成功
     * @return 数据包
     */
    public static Packet skillBookResult(Character chr, int skillid, int maxlevel, boolean canuse, boolean success) {
        final OutPacket p = OutPacket.create(SendOpcode.SKILL_LEARN_ITEM_RESULT);
        p.writeInt(chr.getId());
        p.writeByte(1);
        p.writeInt(skillid);
        p.writeInt(maxlevel);
        p.writeByte(canuse ? 1 : 0);
        p.writeByte(success ? 1 : 0);
        return p;
    }

    /**
     * 获取宏
     * @param macros 宏数组
     * @return 数据包
     */
    public static Packet getMacros(SkillMacro[] macros) {
        final OutPacket p = OutPacket.create(SendOpcode.MACRO_SYS_DATA_INIT);
        int count = 0;
        for (int i = 0; i < 5; i++) {
            if (macros[i] != null) {
                count++;
            }
        }
        p.writeByte(count);
        for (int i = 0; i < 5; i++) {
            SkillMacro macro = macros[i];
            if (macro != null) {
                p.writeString(macro.getName());
                p.writeByte(macro.getShout());
                p.writeInt(macro.getSkill1());
                p.writeInt(macro.getSkill2());
                p.writeInt(macro.getSkill3());
            }
        }
        return p;
    }

    /**
     * 更新坐骑
     * @param charid 角色ID
     * @param mount 坐骑对象
     * @param levelup 是否升级
     * @return 数据包
     */
    public static Packet updateMount(int charid, Mount mount, boolean levelup) {
        final OutPacket p = OutPacket.create(SendOpcode.SET_TAMING_MOB_INFO);
        p.writeInt(charid);
        p.writeInt(mount.getLevel());
        p.writeInt(mount.getExp());
        p.writeInt(mount.getTiredness());
        p.writeByte(levelup ? (byte) 1 : (byte) 0);
        return p;
    }

    /**
     * 显示怪物骑乘
     * @param cid 角色ID
     * @param mount 坐骑对象
     * @return 数据包
     */
    public static Packet showMonsterRiding(int cid, Mount mount) {
        final OutPacket p = OutPacket.create(SendOpcode.GIVE_FOREIGN_BUFF);
        p.writeInt(cid);
        p.writeLong(BuffStat.MONSTER_RIDING.getValue());
        p.writeLong(0);
        p.writeShort(0);
        p.writeInt(mount.getItemId());
        p.writeInt(mount.getSkillId());
        p.writeInt(0);
        p.writeShort(0);
        p.writeByte(0);
        return p;
    }

    /**
     * 使用黑板
     * @param chr 角色对象
     * @param close 是否关闭
     * @return 数据包
     */
    public static Packet useChalkboard(Character chr, boolean close) {
        OutPacket p = OutPacket.create(SendOpcode.CHALKBOARD);
        p.writeInt(chr.getId());
        if (close) {
            p.writeByte(0);
        } else {
            p.writeByte(1);
            p.writeString(chr.getChalkboard());
        }
        return p;
    }

    /**
     * 打开UI
     * @param ui UI ID
     * @return 数据包
     */
    public static Packet openUI(byte ui) {
        OutPacket p = OutPacket.create(SendOpcode.OPEN_UI);
        p.writeByte(ui);
        return p;
    }

    /**
     * 锁定UI
     * @param enable 是否启用
     * @return 数据包
     */
    public static Packet lockUI(boolean enable) {
        OutPacket p = OutPacket.create(SendOpcode.LOCK_UI);
        p.writeByte(enable ? 1 : 0);
        return p;
    }

    /**
     * 禁用UI
     * @param enable 是否启用
     * @return 数据包
     */
    public static Packet disableUI(boolean enable) {
        final OutPacket p = OutPacket.create(SendOpcode.DISABLE_UI);
        p.writeByte(enable ? 1 : 0);
        return p;
    }

    /**
     * 获取键位映射
     * @param keybindings 键位映射
     * @return 数据包
     */
    public static Packet getKeymap(Map<Integer, KeyBinding> keybindings) {
        final OutPacket p = OutPacket.create(SendOpcode.KEYMAP);
        p.writeByte(0);
        for (int x = 0; x < 90; x++) {
            KeyBinding binding = keybindings.get(x);
            if (binding != null) {
                p.writeByte(binding.getType());
                p.writeInt(binding.getAction());
            } else {
                p.writeByte(0);
                p.writeInt(0);
            }
        }
        return p;
    }

    /**
     * 快捷键初始化
     * @param pQuickslot 快捷键绑定
     * @return 数据包
     */
    public static Packet QuickslotMappedInit(QuickslotBinding pQuickslot) {
        OutPacket p = OutPacket.create(SendOpcode.QUICKSLOT_INIT);
        pQuickslot.encode(p);
        return p;
    }

    /**
     * 显示连击
     * @param count 连击数
     * @return 数据包
     */
    public static Packet showCombo(int count) {
        OutPacket p = OutPacket.create(SendOpcode.SHOW_COMBO);
        p.writeInt(count);
        return p;
    }

    /**
     * 重置强制状态
     * @return 数据包
     */
    public static Packet resetForcedStats() {
        return OutPacket.create(SendOpcode.FORCED_STAT_RESET);
    }

    /**
     * 战神神级状态
     * @return 数据包
     */
    public static Packet aranGodlyStats() {
        OutPacket p = OutPacket.create(SendOpcode.FORCED_STAT_SET);
        p.writeBytes(new byte[]{
                (byte) 0x1F, (byte) 0x0F, 0, 0,
                (byte) 0xE7, 3, (byte) 0xE7, 3,
                (byte) 0xE7, 3, (byte) 0xE7, 3,
                (byte) 0xFF, 0, (byte) 0xE7, 3,
                (byte) 0xE7, 3, (byte) 0x78, (byte) 0x8C});
        return p;
    }

    /**
     * 更新区域信息
     * @param area 区域
     * @param info 信息
     * @return 数据包
     */
    public static Packet updateAreaInfo(int area, String info) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        p.writeByte(0x0A);
        p.writeShort(area);
        p.writeString(info);
        return p;
    }

    /**
     * 获取GP消息
     * @param gpChange GP变化
     * @return 数据包
     */
    public static Packet getGPMessage(int gpChange) {
        OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        p.writeByte(6);
        p.writeInt(gpChange);
        return p;
    }

    /**
     * 添加卡片
     * @param full 是否满
     * @param cardid 卡片ID
     * @param level 等级
     * @return 数据包
     */
    public static Packet addCard(boolean full, int cardid, int level) {
        OutPacket p = OutPacket.create(SendOpcode.MONSTER_BOOK_SET_CARD);
        p.writeByte(full ? 0 : 1);
        p.writeInt(cardid);
        p.writeInt(level);
        return p;
    }

    /**
     * 显示获得卡片
     * @return 数据包
     */
    public static Packet showGainCard() {
        OutPacket p = OutPacket.create(SendOpcode.SHOW_ITEM_GAIN_INCHAT);
        p.writeByte(0x0D);
        return p;
    }

    /**
     * 显示外部卡片特效
     * @param id ID
     * @return 数据包
     */
    public static Packet showForeignCardEffect(int id) {
        OutPacket p = OutPacket.create(SendOpcode.SHOW_FOREIGN_EFFECT);
        p.writeInt(id);
        p.writeByte(0x0D);
        return p;
    }

    /**
     * 更改封面
     * @param cardid 卡片ID
     * @return 数据包
     */
    public static Packet changeCover(int cardid) {
        OutPacket p = OutPacket.create(SendOpcode.MONSTER_BOOK_SET_COVER);
        p.writeInt(cardid);
        return p;
    }

    /**
     * 新年卡片响应
     * @param user 用户
     * @param cardId 卡片ID
     * @param mode 模式
     * @param msg 消息
     * @return 数据包
     */
    public static Packet onNewYearCardRes(Character user, int cardId, int mode, int msg) {
        NewYearCardRecord newyear = user.getNewYearRecord(cardId);
        return PacketHelper.onNewYearCardRes(user, newyear, mode, msg);
    }

    /**
     * 获得称号消息
     * @param msg 消息
     * @return 数据包
     */
    public static Packet earnTitleMessage(String msg) {
        final OutPacket p = OutPacket.create(SendOpcode.SCRIPT_PROGRESS_MESSAGE);
        p.writeString(msg);
        return p;
    }

    /**
     * 发送黄色提示
     * @param tip 提示内容
     * @return 数据包
     */
    public static Packet sendYellowTip(String tip) {
        final OutPacket p = OutPacket.create(SendOpcode.SET_WEEK_EVENT_MESSAGE);
        p.writeByte(0xFF);
        p.writeString(tip);
        p.writeShort(0);
        return p;
    }

    /**
     * 扭蛋消息
     * @param item 物品对象
     * @param town 城镇
     * @param player 玩家
     * @return 数据包
     */
    public static Packet gachaponMessage(Item item, String town, Character player) {
        final OutPacket p = OutPacket.create(SendOpcode.SERVERMESSAGE);
        p.writeByte(0x0B);
        p.writeString(player.getName() + " : 获得了");
        p.writeInt(0);
        p.writeString(town);
        PacketHelper.addItemInfo(p, item, true);
        return p;
    }

    /**
     * 显示活动说明
     * @return 数据包
     */
    public static Packet showEventInstructions() {
        final OutPacket p = OutPacket.create(SendOpcode.GMEVENT_INSTRUCTIONS);
        p.writeByte(0);
        return p;
    }

    /**
     * 兔子包
     * @return 数据包
     */
    public static Packet bunnyPacket() {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        p.writeByte(9);
        p.writeFixedString("Protect the Moon Bunny!!!");
        return p;
    }

    /**
     * HPQ消息
     * @param text 文本
     * @return 数据包
     */
    public static Packet hpqMessage(String text) {
        final OutPacket p = OutPacket.create(SendOpcode.BLOW_WEATHER);
        p.writeByte(0);
        p.writeInt(ItemId.NPC_WEATHER_GROWLIE);
        p.writeFixedString(text);
        return p;
    }

    /**
     * 滚雪球
     * @param entermap 是否进入地图
     * @param state 状态
     * @param ball0 雪球0
     * @param ball1 雪球1
     * @return 数据包
     */
    public static Packet rollSnowBall(boolean entermap, int state, Snowball ball0, Snowball ball1) {
        OutPacket p = OutPacket.create(SendOpcode.SNOWBALL_STATE);
        if (entermap) {
            p.skip(21);
        } else {
            p.writeByte(state);
            p.writeInt(ball0.getSnowmanHP() / 75);
            p.writeInt(ball1.getSnowmanHP() / 75);
            p.writeShort(ball0.getPosition());
            p.writeByte(-1);
            p.writeShort(ball1.getPosition());
            p.writeByte(-1);
        }
        return p;
    }

    /**
     * 击中雪球
     * @param what 什么
     * @param damage 伤害
     * @return 数据包
     */
    public static Packet hitSnowBall(int what, int damage) {
        OutPacket p = OutPacket.create(SendOpcode.HIT_SNOWBALL);
        p.writeByte(what);
        p.writeInt(damage);
        return p;
    }

    /**
     * 雪球消息
     * @param team 队伍
     * @param message 消息
     * @return 数据包
     */
    public static Packet snowballMessage(int team, int message) {
        OutPacket p = OutPacket.create(SendOpcode.SNOWBALL_MESSAGE);
        p.writeByte(team);
        p.writeInt(message);
        return p;
    }

    /**
     * 椰子得分
     * @param team1 队伍1
     * @param team2 队伍2
     * @return 数据包
     */
    public static Packet coconutScore(int team1, int team2) {
        OutPacket p = OutPacket.create(SendOpcode.COCONUT_SCORE);
        p.writeShort(team1);
        p.writeShort(team2);
        return p;
    }

    /**
     * 击中椰子
     * @param spawn 是否生成
     * @param id ID
     * @param type 类型
     * @return 数据包
     */
    public static Packet hitCoconut(boolean spawn, int id, int type) {
        OutPacket p = OutPacket.create(SendOpcode.COCONUT_HIT);
        if (spawn) {
            p.writeShort(-1);
            p.writeShort(5000);
            p.writeByte(0);
        } else {
            p.writeShort(id);
            p.writeShort(1000);
            p.writeByte(type);
        }
        return p;
    }

    /**
     * CP更新
     * @param party 是否队伍
     * @param curCP 当前CP
     * @param totalCP 总CP
     * @param team 队伍
     * @return 数据包
     */
    public static Packet CPUpdate(boolean party, int curCP, int totalCP, int team) {
        final OutPacket p;
        if (!party) {
            p = OutPacket.create(SendOpcode.MONSTER_CARNIVAL_OBTAINED_CP);
        } else {
            p = OutPacket.create(SendOpcode.MONSTER_CARNIVAL_PARTY_CP);
            p.writeByte(team);
        }
        p.writeShort(curCP);
        p.writeShort(totalCP);
        return p;
    }

    /**
     * CPQ消息
     * @param message 消息
     * @return 数据包
     */
    public static Packet CPQMessage(byte message) {
        OutPacket p = OutPacket.create(SendOpcode.MONSTER_CARNIVAL_MESSAGE);
        p.writeByte(message);
        return p;
    }

    /**
     * 玩家召唤
     * @param name 名称
     * @param tab 标签
     * @param number 编号
     * @return 数据包
     */
    public static Packet playerSummoned(String name, int tab, int number) {
        OutPacket p = OutPacket.create(SendOpcode.MONSTER_CARNIVAL_SUMMON);
        p.writeByte(tab);
        p.writeByte(number);
        p.writeString(name);
        return p;
    }

    /**
     * 玩家死亡消息
     * @param name 名称
     * @param lostCP 损失CP
     * @param team 队伍
     * @return 数据包
     */
    public static Packet playerDiedMessage(String name, int lostCP, int team) {
        OutPacket p = OutPacket.create(SendOpcode.MONSTER_CARNIVAL_DIED);
        p.writeByte(team);
        p.writeString(name);
        p.writeByte(lostCP);
        return p;
    }

    /**
     * 开始怪物嘉年华
     * @param chr 角色对象
     * @param team 队伍
     * @param opposition 对手
     * @return 数据包
     */
    public static Packet startMonsterCarnival(Character chr, int team, int opposition) {
        OutPacket p = OutPacket.create(SendOpcode.MONSTER_CARNIVAL_START);
        p.writeByte(team);
        p.writeShort(chr.getCP());
        p.writeShort(chr.getTotalCP());
        p.writeShort(chr.getMonsterCarnival().getCP(team));
        p.writeShort(chr.getMonsterCarnival().getTotalCP(team));
        p.writeShort(chr.getMonsterCarnival().getCP(opposition));
        p.writeShort(chr.getMonsterCarnival().getTotalCP(opposition));
        p.writeShort(0);
        p.writeLong(0);
        return p;
    }

    /**
     * 牧羊场信息
     * @param wolf 狼
     * @param sheep 羊
     * @return 数据包
     */
    public static Packet sheepRanchInfo(byte wolf, byte sheep) {
        final OutPacket p = OutPacket.create(SendOpcode.SHEEP_RANCH_INFO);
        p.writeByte(wolf);
        p.writeByte(sheep);
        return p;
    }

    /**
     * 牧羊场衣服
     * @param id ID
     * @param clothes 衣服
     * @return 数据包
     */
    public static Packet sheepRanchClothes(int id, byte clothes) {
        final OutPacket p = OutPacket.create(SendOpcode.SHEEP_RANCH_CLOTHES);
        p.writeInt(id);
        p.writeByte(clothes);
        return p;
    }

    /**
     * 金字塔计量条
     * @param gauge 计量值
     * @return 数据包
     */
    public static Packet pyramidGauge(int gauge) {
        OutPacket p = OutPacket.create(SendOpcode.PYRAMID_GAUGE);
        p.writeInt(gauge);
        return p;
    }

    /**
     * 金字塔得分
     * @param score 得分
     * @param exp 经验
     * @return 数据包
     */
    public static Packet pyramidScore(byte score, int exp) {
        OutPacket p = OutPacket.create(SendOpcode.PYRAMID_SCORE);
        p.writeByte(score);
        p.writeInt(exp);
        return p;
    }

    /**
     * 孵化器结果
     * @return 数据包
     */
    public static Packet incubatorResult() {
        OutPacket p = OutPacket.create(SendOpcode.INCUBATOR_RESULT);
        p.skip(6);
        return p;
    }

    /**
     * 获取道场信息
     * @param info 信息
     * @return 数据包
     */
    public static Packet getDojoInfo(String info) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        p.writeByte(10);
        p.writeBytes(new byte[]{(byte) 0xB7, 4});
        p.writeString(info);
        return p;
    }

    /**
     * 获取道场信息消息
     * @param message 消息
     * @return 数据包
     */
    public static Packet getDojoInfoMessage(String message) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        p.writeByte(9);
        p.writeString(message);
        return p;
    }

    /**
     * 发送道场动画
     * @param firstByte 首字节
     * @param animation 动画
     * @return 数据包
     */
    public static Packet sendDojoAnimation(byte firstByte, String animation) {
        final OutPacket p = OutPacket.create(SendOpcode.FIELD_EFFECT);
        p.writeByte(firstByte);
        p.writeString(animation);
        return p;
    }

    /**
     * 更新道场状态
     * @param chr 角色对象
     * @param belt 腰带
     * @return 数据包
     */
    public static Packet updateDojoStats(Character chr, int belt) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        p.writeByte(10);
        p.writeBytes(new byte[]{(byte) 0xB7, 4});
        p.writeString("pt=" + chr.getDojoPoints() + ";belt=" + belt + ";tuto=" + (chr.isFinishedDojoTutorial() ? "1" : "0"));
        return p;
    }

    /**
     * 道场传送
     * @return 数据包
     */
    public static Packet dojoWarpUp() {
        final OutPacket p = OutPacket.create(SendOpcode.DOJO_WARP_UP);
        p.writeByte(0);
        p.writeByte(6);
        return p;
    }

    /**
     * 获取能量
     * @param info 信息
     * @param amount 数量
     * @return 数据包
     */
    public static Packet getEnergy(String info, int amount) {
        final OutPacket p = OutPacket.create(SendOpcode.SESSION_VALUE);
        p.writeString(info);
        p.writeString(Integer.toString(amount));
        return p;
    }

    /**
     * 显示阿里安特计分板
     * @return 数据包
     */
    public static Packet showAriantScoreBoard() {
        return OutPacket.create(SendOpcode.ARIANT_ARENA_SHOW_RESULT);
    }

    /**
     * 更新阿里安特PQ排名
     * @param chr 角色对象
     * @param score 得分
     * @return 数据包
     */
    public static Packet updateAriantPQRanking(final Character chr, final int score) {
        return updateAriantPQRanking(new LinkedHashMap<Character, Integer>() {{
            put(chr, score);
        }});
    }

    /**
     * 更新阿里安特PQ排名
     * @param playerScore 玩家得分映射
     * @return 数据包
     */
    public static Packet updateAriantPQRanking(Map<Character, Integer> playerScore) {
        OutPacket p = OutPacket.create(SendOpcode.ARIANT_ARENA_USER_SCORE);
        p.writeByte(playerScore.size());
        for (Entry<Character, Integer> e : playerScore.entrySet()) {
            p.writeString(e.getKey().getName());
            p.writeInt(e.getValue());
        }
        return p;
    }

    /**
     * 更新女巫塔得分
     * @param score 得分
     * @return 数据包
     */
    public static Packet updateWitchTowerScore(int score) {
        OutPacket p = OutPacket.create(SendOpcode.WITCH_TOWER_SCORE_UPDATE);
        p.writeByte(score);
        return p;
    }

    /**
     * 制造者结果
     * @param success 是否成功
     * @param itemMade 制造物品
     * @param itemCount 物品数量
     * @param mesos 金币
     * @param itemsLost 消耗物品列表
     * @param catalystID 催化剂ID
     * @param INCBuffGems 增益宝石列表
     * @return 数据包
     */
    public static Packet makerResult(boolean success, int itemMade, int itemCount, int mesos, List<Pair<Integer, Integer>> itemsLost, int catalystID, List<Integer> INCBuffGems) {
        final OutPacket p = OutPacket.create(SendOpcode.MAKER_RESULT);
        p.writeInt(success ? 0 : 1);
        p.writeInt(1);
        p.writeBool(!success);
        if (success) {
            p.writeInt(itemMade);
            p.writeInt(itemCount);
        }
        p.writeInt(itemsLost.size());
        for (Pair<Integer, Integer> item : itemsLost) {
            p.writeInt(item.getLeft());
            p.writeInt(item.getRight());
        }
        p.writeInt(INCBuffGems.size());
        for (Integer gem : INCBuffGems) {
            p.writeInt(gem);
        }
        if (catalystID != -1) {
            p.writeByte(1);
            p.writeInt(catalystID);
        } else {
            p.writeByte(0);
        }

        p.writeInt(mesos);
        return p;
    }

    /**
     * 制造者结果（水晶）
     * @param itemIdGained 获得物品ID
     * @param itemIdLost 消耗物品ID
     * @return 数据包
     */
    public static Packet makerResultCrystal(int itemIdGained, int itemIdLost) {
        final OutPacket p = OutPacket.create(SendOpcode.MAKER_RESULT);
        p.writeInt(0);
        p.writeInt(3);
        p.writeInt(itemIdGained);
        p.writeInt(itemIdLost);
        return p;
    }

    /**
     * 制造者结果（分解）
     * @param itemId 物品ID
     * @param mesos 金币
     * @param itemsGained 获得物品列表
     * @return 数据包
     */
    public static Packet makerResultDesynth(int itemId, int mesos, List<Pair<Integer, Integer>> itemsGained) {
        final OutPacket p = OutPacket.create(SendOpcode.MAKER_RESULT);
        p.writeInt(0);
        p.writeInt(4);
        p.writeInt(itemId);
        p.writeInt(itemsGained.size());
        for (Pair<Integer, Integer> item : itemsGained) {
            p.writeInt(item.getLeft());
            p.writeInt(item.getRight());
        }
        p.writeInt(mesos);
        return p;
    }

    /**
     * 制造者启用动作
     * @return 数据包
     */
    public static Packet makerEnableActions() {
        final OutPacket p = OutPacket.create(SendOpcode.MAKER_RESULT);
        p.writeInt(0);
        p.writeInt(0);
        p.writeInt(0);
        p.writeInt(0);
        return p;
    }

    /**
     * 显示制造者特效
     * @param makerSucceeded 是否成功
     * @return 数据包
     */
    public static Packet showMakerEffect(boolean makerSucceeded) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_ITEM_GAIN_INCHAT);
        p.writeByte(16);
        p.writeInt(makerSucceeded ? 0 : 1);
        return p;
    }

    /**
     * 显示外部制造者特效
     * @param cid 角色ID
     * @param makerSucceeded 是否成功
     * @return 数据包
     */
    public static Packet showForeignMakerEffect(int cid, boolean makerSucceeded) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_FOREIGN_EFFECT);
        p.writeInt(cid);
        p.writeByte(16);
        p.writeInt(makerSucceeded ? 0 : 1);
        return p;
    }

    /**
     * 显示恢复
     * @param chrId 角色ID
     * @param amount 数量
     * @return 数据包
     */
    public static Packet showRecovery(int chrId, byte amount) {
        OutPacket p = OutPacket.create(SendOpcode.SHOW_FOREIGN_EFFECT);
        p.writeInt(chrId);
        p.writeByte(0x0A);
        p.writeByte(amount);
        return p;
    }

    /**
     * 显示自身恢复
     * @param heal 治疗量
     * @return 数据包
     */
    public static Packet showOwnRecovery(byte heal) {
        OutPacket p = OutPacket.create(SendOpcode.SHOW_ITEM_GAIN_INCHAT);
        p.writeByte(0x0A);
        p.writeByte(heal);
        return p;
    }

    /**
     * 显示剩余轮子
     * @param left 剩余数
     * @return 数据包
     */
    public static Packet showWheelsLeft(int left) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_ITEM_GAIN_INCHAT);
        p.writeByte(0x15);
        p.writeByte(left);
        return p;
    }

    /**
     * 任务错误
     * @param quest 任务ID
     * @return 数据包
     */
    public static Packet questError(short quest) {
        final OutPacket p = OutPacket.create(SendOpcode.UPDATE_QUEST_INFO);
        p.writeByte(0x0A);
        p.writeShort(quest);
        return p;
    }

    /**
     * 任务失败
     * @param type 类型
     * @return 数据包
     */
    public static Packet questFailure(byte type) {
        final OutPacket p = OutPacket.create(SendOpcode.UPDATE_QUEST_INFO);
        p.writeByte(type);
        return p;
    }

    /**
     * 任务过期
     * @param quest 任务ID
     * @return 数据包
     */
    public static Packet questExpire(short quest) {
        final OutPacket p = OutPacket.create(SendOpcode.UPDATE_QUEST_INFO);
        p.writeByte(0x0F);
        p.writeShort(quest);
        return p;
    }

    /**
     * 更新任务
     * @param chr 角色对象
     * @param qs 任务状态
     * @param infoUpdate 是否信息更新
     * @return 数据包
     */
    public static Packet updateQuest(Character chr, QuestStatus qs, boolean infoUpdate) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        p.writeByte(1);
        if (infoUpdate) {
            QuestStatus iqs = chr.getQuest(qs.getInfoNumber());
            p.writeShort(iqs.getQuestID());
            p.writeByte(1);
            p.writeString(iqs.getProgressData());
        } else {
            p.writeShort(qs.getQuest().getId());
            p.writeByte(qs.getStatus().getId());
            p.writeString(qs.getProgressData());
        }
        p.skip(5);
        return p;
    }

    /**
     * 更新任务信息
     * @param quest 任务ID
     * @param npc NPC ID
     * @return 数据包
     */
    public static Packet updateQuestInfo(short quest, int npc) {
        final OutPacket p = OutPacket.create(SendOpcode.UPDATE_QUEST_INFO);
        p.writeByte(8);
        p.writeShort(quest);
        p.writeInt(npc);
        p.writeInt(0);
        return p;
    }

    /**
     * 更新任务完成
     * @param quest 任务ID
     * @param npc NPC ID
     * @param nextquest 下一个任务ID
     * @return 数据包
     */
    public static Packet updateQuestFinish(short quest, int npc, short nextquest) {
        final OutPacket p = OutPacket.create(SendOpcode.UPDATE_QUEST_INFO);
        p.writeByte(8);
        p.writeShort(quest);
        p.writeInt(npc);
        p.writeShort(nextquest);
        return p;
    }

    /**
     * 添加任务时间限制
     * @param quest 任务ID
     * @param time 时间
     * @return 数据包
     */
    public static Packet addQuestTimeLimit(final short quest, final int time) {
        final OutPacket p = OutPacket.create(SendOpcode.UPDATE_QUEST_INFO);
        p.writeByte(6);
        p.writeShort(1);
        p.writeShort(quest);
        p.writeInt(time);
        return p;
    }

    /**
     * 移除任务时间限制
     * @param quest 任务ID
     * @return 数据包
     */
    public static Packet removeQuestTimeLimit(final short quest) {
        final OutPacket p = OutPacket.create(SendOpcode.UPDATE_QUEST_INFO);
        p.writeByte(7);
        p.writeShort(1);
        p.writeShort(quest);
        return p;
    }

    /**
     * 放弃任务
     * @param quest 任务ID
     * @return 数据包
     */
    public static Packet forfeitQuest(short quest) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        p.writeByte(1);
        p.writeShort(quest);
        p.writeByte(0);
        return p;
    }

    /**
     * 完成任务
     * @param quest 任务ID
     * @param time 时间
     * @return 数据包
     */
    public static Packet completeQuest(short quest, long time) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        p.writeByte(1);
        p.writeShort(quest);
        p.writeByte(2);
        p.writeLong(PacketHelper.getTime(time));
        return p;
    }

    /**
     * 获取显示任务完成
     * @param id ID
     * @return 数据包
     */
    public static Packet getShowQuestCompletion(int id) {
        final OutPacket p = OutPacket.create(SendOpcode.QUEST_CLEAR);
        p.writeShort(id);
        return p;
    }

    /**
     * 字段HP减少通知
     * @param change 变化量
     * @return 数据包
     */
    public static Packet onNotifyHPDecByField(int change) {
        final OutPacket p = OutPacket.create(SendOpcode.ON_NOTIFY_HP_DEC_BY_FIELD);
        p.writeInt(change);
        return p;
    }

    /**
     * 自定义数据包（字符串）
     * @param packet 数据包内容
     * @return 数据包
     */
    public static Packet customPacket(String packet) {
        OutPacket p = new ByteBufOutPacket();
        p.writeBytes(HexTool.toBytes(packet));
        return p;
    }

    /**
     * 自定义数据包（字节数组）
     * @param packet 数据包内容
     * @return 数据包
     */
    public static Packet customPacket(byte[] packet) {
        OutPacket p = new ByteBufOutPacket();
        p.writeBytes(packet);
        return p;
    }
}
