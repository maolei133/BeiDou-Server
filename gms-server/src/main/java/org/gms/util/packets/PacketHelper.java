package org.gms.util.packets;

import com.mybatisflex.annotation.Column;
import org.gms.client.BuffStat;
import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.Disease;
import org.gms.client.FamilyEntitlement;
import org.gms.client.FamilyEntry;
import org.gms.client.MonsterBook;
import org.gms.client.Mount;
import org.gms.client.QuestStatus;
import org.gms.client.Ring;
import org.gms.client.Skill;
import org.gms.client.Stat;
import org.gms.client.inventory.Equip;
import org.gms.client.inventory.Inventory;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.Pet;
import org.gms.client.status.MonsterStatus;
import org.gms.client.status.MonsterStatusEffect;
import org.gms.constants.game.CommodityFlag;
import org.gms.constants.game.ExpTable;
import org.gms.constants.game.GameConstants;
import org.gms.constants.id.ItemId;
import org.gms.constants.inventory.ItemConstants;
import org.gms.dao.entity.ModifiedCashItemDO;
import org.gms.model.pojo.NewYearCardRecord;
import org.gms.model.pojo.SkillEntry;
import org.gms.net.opcodes.SendOpcode;
import org.gms.net.packet.ByteBufOutPacket;
import org.gms.net.packet.InPacket;
import org.gms.net.packet.OutPacket;
import org.gms.net.packet.Packet;
import org.gms.net.server.PlayerCoolDownValueHolder;
import org.gms.net.server.Server;
import org.gms.net.server.guild.GuildSummary;
import org.gms.net.server.world.Party;
import org.gms.net.server.world.PartyCharacter;
import org.gms.server.ItemInformationProvider;
import org.gms.server.life.MobSkill;
import org.gms.server.life.MobSkillId;
import org.gms.server.life.Monster;
import org.gms.server.maps.AbstractMapObject;
import org.gms.server.maps.Door;
import org.gms.server.maps.DoorObject;
import org.gms.server.maps.HiredMerchant;
import org.gms.server.maps.MiniGame;
import org.gms.server.maps.MiniGame.MiniGameResult;
import org.gms.server.maps.PlayerShop;
import org.gms.server.maps.PlayerShopItem;
import org.gms.server.movement.LifeMovementFragment;
import org.gms.util.HexTool;
import org.gms.util.Pair;
import org.gms.util.Randomizer;
import org.gms.util.RequireUtil;
import org.gms.util.StringUtil;

import java.awt.*;
import java.lang.reflect.Field;
import java.util.*;
import java.util.List;
import java.util.Map.Entry;
import java.util.stream.Collectors;

/**
 * PacketHelper
 * 包含 PacketCreator 中通用的辅助方法
 */
public class PacketHelper {

    public static final List<Pair<Stat, Integer>> EMPTY_STATUPDATE = Collections.emptyList();
    private final static long FT_UT_OFFSET = 116444736010800000L + (10000L * TimeZone.getDefault().getOffset(System.currentTimeMillis())); // 根据 Ari 的建议，使用时区偏移进行标准化
    private final static long DEFAULT_TIME = 150842304000000000L;//00 80 05 BB 46 E6 17 02
    public final static long ZERO_TIME = 94354848000000000L;//00 40 E0 FD 3B 37 4F 01
    private final static long PERMANENT = 150841440000000000L; // 00 C0 9B 90 7D E5 17 02

    public static class WhisperFlag {
        public static final byte LOCATION = 0x01;
        public static final byte WHISPER = 0x02;
        public static final byte REQUEST = 0x04;
        public static final byte RESULT = 0x08;
        public static final byte RECEIVE = 0x10;
        public static final byte BLOCKED = 0x20;
        public static final byte LOCATION_FRIEND = 0x40;
    }

    /**
     * 获取时间戳
     * @param utcTimestamp UTC时间戳
     * @return 转换后的时间戳
     */
    public static long getTime(long utcTimestamp) {
        if (utcTimestamp < 0 && utcTimestamp >= -3) {
            if (utcTimestamp == -1) {
                return DEFAULT_TIME;    // 高数值 ll
            } else if (utcTimestamp == -2) {
                return ZERO_TIME;
            } else {
                return PERMANENT;
            }
        }
        return utcTimestamp * 10000 + FT_UT_OFFSET;
    }

    /**
     * 写入怪物技能ID
     * @param packet 数据包
     * @param msId 怪物技能ID
     */
    public static void writeMobSkillId(OutPacket packet, MobSkillId msId) {
        packet.writeShort(msId.type().getId());
        packet.writeShort(msId.level());
    }

    /**
     * 添加剩余技能信息
     * @param p 数据包
     * @param chr 角色对象
     */
    public static void addRemainingSkillInfo(final OutPacket p, Character chr) {
        int[] remainingSp = chr.getRemainingSps();
        int effectiveLength = 0;
        for (int j : remainingSp) {
            if (j > 0) {
                effectiveLength++;
            }
        }

        p.writeByte(effectiveLength);
        for (int i = 0; i < remainingSp.length; i++) {
            if (remainingSp[i] > 0) {
                p.writeByte(i + 1);
                p.writeByte(remainingSp[i]);
            }
        }
    }

    /**
     * 添加角色属性
     * @param p 数据包
     * @param chr 角色对象
     */
    public static void addCharStats(OutPacket p, Character chr) {
        p.writeInt(chr.getId()); // 角色ID
        p.writeFixedString(StringUtil.getRightPaddedStr(chr.getName(), '\0', 13));
        p.writeByte(chr.getGender()); // 性别 (0 = 男, 1 = 女)
        p.writeByte(chr.getSkinColor().getId()); // 肤色
        p.writeInt(chr.getFace()); // 脸型
        p.writeInt(chr.getHair()); // 发型

        for (int i = 0; i < 3; i++) {
            Pet pet = chr.getPet(i);
            if (pet != null) { // 检查 GMS.. 进入商城时宠物会保留。
                p.writeLong(pet.getUniqueId());
            } else {
                p.writeLong(0);
            }
        }

        p.writeByte(chr.getLevel()); // 等级
        p.writeShort(chr.getJob().getId()); // 职业
        p.writeShort(chr.getStr()); // 力量
        p.writeShort(chr.getDex()); // 敏捷
        p.writeShort(chr.getInt()); // 智力
        p.writeShort(chr.getLuk()); // 运气
        p.writeShort(chr.getHp()); // HP (?)
        p.writeShort(chr.getClientMaxHp()); // 最大HP
        p.writeShort(chr.getMp()); // MP (?)
        p.writeShort(chr.getClientMaxMp()); // 最大MP
        p.writeShort(chr.getRemainingAp()); // 剩余AP
        if (GameConstants.hasSPTable(chr.getJob())) {
            addRemainingSkillInfo(p, chr);
        } else {
            p.writeShort(chr.getRemainingSp()); // 剩余SP
        }
        p.writeInt(chr.getExp()); // 当前经验
        p.writeShort(chr.getFame()); // 人气
        p.writeInt(chr.getGachaExp()); // 扭蛋经验
        p.writeInt(chr.getMapId()); // 当前地图ID
        p.writeByte(chr.getInitialSpawnPoint()); // 出生点
        p.writeInt(0);
    }

    /**
     * 添加角色外观
     * @param p 数据包
     * @param chr 角色对象
     * @param mega 是否大喇叭
     */
    public static void addCharLook(final OutPacket p, Character chr, boolean mega) {
        p.writeByte(chr.getGender());
        p.writeByte(chr.getSkinColor().getId()); // 肤色
        p.writeInt(chr.getFace()); // 脸型
        p.writeBool(!mega);
        p.writeInt(chr.getHair()); // 发型
        addCharEquips(p, chr);
    }

    /**
     * 添加角色信息
     * @param p 数据包
     * @param chr 角色对象
     */
    public static void addCharacterInfo(OutPacket p, Character chr) {
        p.writeLong(-1);
        p.writeByte(0);
        addCharStats(p, chr);
        p.writeByte(chr.getBuddylist().getCapacity());

        if (chr.getLinkedName() == null) {
            p.writeByte(0);
        } else {
            p.writeByte(1);
            p.writeString(chr.getLinkedName());
        }

        p.writeInt(chr.getMeso());
        addInventoryInfo(p, chr);
        addSkillInfo(p, chr);
        addQuestInfo(p, chr);
        addMiniGameInfo(p, chr);
        addRingInfo(p, chr);
        addTeleportInfo(p, chr);
        addMonsterBookInfo(p, chr);
        addNewYearInfo(p, chr);
        addAreaInfo(p, chr); // 假设它留在这里 xd
        p.writeShort(0);
    }

    /**
     * 添加新年信息
     * @param p 数据包
     * @param chr 角色对象
     */
    public static void addNewYearInfo(OutPacket p, Character chr) {
        Set<NewYearCardRecord> received = chr.getReceivedNewYearRecords();

        p.writeShort(received.size());
        for (NewYearCardRecord nyc : received) {
            encodeNewYearCard(nyc, p);
        }
    }

    /**
     * 添加传送信息
     * @param p 数据包
     * @param chr 角色对象
     */
    public static void addTeleportInfo(OutPacket p, Character chr) {
        final List<Integer> tele = chr.getTrockMaps();
        final List<Integer> viptele = chr.getVipTrockMaps();
        for (int i = 0; i < 5; i++) {
            p.writeInt(tele.get(i));
        }
        for (int i = 0; i < 10; i++) {
            p.writeInt(viptele.get(i));
        }
    }

    /**
     * 添加小游戏信息
     * @param p 数据包
     * @param chr 角色对象
     */
    public static void addMiniGameInfo(OutPacket p, Character chr) {
        p.writeShort(0);
        /*for (int m = size; m > 0; m--) {//nexon does this :P
         p.writeInt(0);
         p.writeInt(0);
         p.writeInt(0);
         p.writeInt(0);
         p.writeInt(0);
         }*/
    }

    /**
     * 添加区域信息
     * @param p 数据包
     * @param chr 角色对象
     */
    public static void addAreaInfo(OutPacket p, Character chr) {
        Map<Short, String> areaInfos = chr.getAreaInfos();
        p.writeShort(areaInfos.size());
        for (Short area : areaInfos.keySet()) {
            p.writeShort(area);
            p.writeString(areaInfos.get(area));
        }
    }

    /**
     * 添加角色装备
     * @param p 数据包
     * @param chr 角色对象
     */
    public static void addCharEquips(final OutPacket p, Character chr) {
        Inventory equip = chr.getInventory(InventoryType.EQUIPPED);
        Collection<Item> ii = ItemInformationProvider.getInstance().canWearEquipment(chr, equip.list());
        Map<Short, Integer> myEquip = new LinkedHashMap<>();
        Map<Short, Integer> maskedEquip = new LinkedHashMap<>();
        for (Item item : ii) {
            short pos = (short) (item.getPosition() * -1); // 修复其他角色无法看到现金勋章
            if (pos < 100 && myEquip.get(pos) == null) {
                myEquip.put(pos, item.getItemId());
            } else if (pos > 100 && pos != 111) { // 别问。o.o
                pos -= 100;
                if (myEquip.get(pos) != null) {
                    maskedEquip.put(pos, myEquip.get(pos));
                }
                myEquip.put(pos, item.getItemId());
            } else if (myEquip.get(pos) != null) {
                maskedEquip.put(pos, item.getItemId());
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
        Item cWeapon = equip.getItem((short) -111);
        p.writeInt(cWeapon != null ? cWeapon.getItemId() : 0);
        for (int i = 0; i < 3; i++) {
            if (chr.getPet(i) != null) {
                p.writeInt(chr.getPet(i).getItemId());
            } else {
                p.writeInt(0);
            }
        }
    }

    /**
     * 添加角色条目
     * @param p 数据包
     * @param chr 角色对象
     * @param viewall 是否查看全部
     */
    public static void addCharEntry(OutPacket p, Character chr, boolean viewall) {
        addCharStats(p, chr);
        addCharLook(p, chr, false);
        if (!viewall) {
            p.writeByte(0);
        }
        if (chr.isGM() || chr.isGmJob()) { // 感谢 Daddy Egg (Ubaware), resinate 发现 GM 职业在非 GM 玩家账户上崩溃的问题
            p.writeByte(0);
            return;
        }
        p.writeByte(1); // 启用世界排名（如果禁用，则不发送接下来的 4 个 int）Short??
        p.writeInt(chr.getRank()); // 世界排名
        p.writeInt(chr.getRankMove()); // 移动（负数表示向下）
        p.writeInt(chr.getJobRank()); // 职业排名
        p.writeInt(chr.getJobRankMove()); // 移动（负数表示向下）
    }

    /**
     * 添加任务信息
     * @param p 数据包
     * @param chr 角色对象
     */
    public static void addQuestInfo(OutPacket p, Character chr) {
        List<QuestStatus> started = chr.getStartedQuests();
        int startedSize = 0;
        for (QuestStatus qs : started) {
            if (qs.getInfoNumber() > 0) {
                startedSize++;
            }
            startedSize++;
        }
        p.writeShort(startedSize);
        for (QuestStatus qs : started) {
            p.writeShort(qs.getQuest().getId());
            p.writeString(qs.getProgressData());

            short infoNumber = qs.getInfoNumber();
            if (infoNumber > 0) {
                QuestStatus iqs = chr.getQuest(infoNumber);
                p.writeShort(infoNumber);
                p.writeString(iqs.getProgressData());
            }
        }
        List<QuestStatus> completed = chr.getCompletedQuests();
        p.writeShort(completed.size());
        for (QuestStatus qs : completed) {
            p.writeShort(qs.getQuest().getId());
            p.writeLong(getTime(qs.getCompletionTime()));
        }
    }

    /**
     * 添加过期时间
     * @param p 数据包
     * @param time 时间
     */
    public static void addExpirationTime(final OutPacket p, long time) {
        p.writeLong(getTime(time)); // 感谢 Thora 发现的过期时间偏移问题
    }

    /**
     * 添加物品信息
     * @param p 数据包
     * @param item 物品对象
     */
    public static void addItemInfo(OutPacket p, Item item) {
        addItemInfo(p, item, false);
    }

    /**
     * 添加物品信息
     * @param p 数据包
     * @param item 物品对象
     * @param zeroPosition 是否零位置
     */
    public static void addItemInfo(final OutPacket p, Item item, boolean zeroPosition) {
        ItemInformationProvider ii = ItemInformationProvider.getInstance();
        boolean isCash = ii.isCash(item.getItemId());
        boolean isPet = item.getPetId() > -1;
        boolean isRing = false;
        Equip equip = null;
        short pos = item.getPosition();
        byte itemType = item.getItemType();
        if (itemType == 1) {
            equip = (Equip) item;
            isRing = equip.getRingId() > -1;
        }
        if (!zeroPosition) {
            if (equip != null) {
                if (pos < 0) {
                    pos *= -1;
                }
                p.writeShort(pos > 100 ? pos - 100 : pos);
            } else {
                p.writeByte(pos);
            }
        }
        p.writeByte(itemType);
        p.writeInt(item.getItemId());
        p.writeBool(isCash);
        if (isCash) {
            p.writeLong(isPet ? item.getPetId() : isRing ? equip.getRingId() : item.getCashId());
        }
        addExpirationTime(p, item.getExpiration());
        if (isPet) {
            Pet pet = item.getPet();
            p.writeFixedString(StringUtil.getRightPaddedStr(pet.getName(), '\0', 13));
            p.writeByte(pet.getLevel());
            p.writeShort(pet.getTameness());
            p.writeByte(pet.getFullness());
            addExpirationTime(p, item.getExpiration());
            p.writeShort(pet.getPetAttribute()); // lrenex & Spoon 发现的宠物属性
            p.writeShort(0); // 宠物技能
            p.writeInt(18000); // 剩余生命
            p.writeShort(0); // 属性
            return;
        }
        if (equip == null) {
            p.writeShort(item.getQuantity());
            p.writeString(item.getOwner());
            p.writeShort(item.getFlag()); // 标志

            if (ItemConstants.isRechargeable(item.getItemId())) {
                p.writeInt(2);
                p.writeBytes(new byte[]{(byte) 0x54, 0, 0, (byte) 0x34});
            }
            return;
        }
        p.writeByte(equip.getUpgradeSlots()); // 升级槽
        p.writeByte(equip.getLevel()); // 等级
        p.writeShort(equip.getStr()); // 力量
        p.writeShort(equip.getDex()); // 敏捷
        p.writeShort(equip.getInt()); // 智力
        p.writeShort(equip.getLuk()); // 运气
        p.writeShort(equip.getHp()); // hp
        p.writeShort(equip.getMp()); // mp
        p.writeShort(equip.getWatk()); // 物理攻击
        p.writeShort(equip.getMatk()); // 魔法攻击
        p.writeShort(equip.getWdef()); // 物理防御
        p.writeShort(equip.getMdef()); // 魔法防御
        p.writeShort(equip.getAcc()); // 命中率
        p.writeShort(equip.getAvoid()); // 回避率
        p.writeShort(equip.getHands()); // 手技
        p.writeShort(equip.getSpeed()); // 速度
        p.writeShort(equip.getJump()); // 跳跃
        p.writeString(equip.getOwner()); // 拥有者名称
        p.writeShort(equip.getFlag()); // 物品标志

        if (isCash) {
            for (int i = 0; i < 10; i++) {
                p.writeByte(0x40);
            }
        } else {
            int itemLevel = equip.getItemLevel();

            long expNibble = (ExpTable.getExpNeededForLevel(ii.getEquipLevelReq(item.getItemId())) * equip.getItemExp());
            expNibble /= ExpTable.getEquipExpNeededForLevel(itemLevel);

            p.writeByte(0);
            p.writeByte(itemLevel); // 物品等级
            p.writeInt((int) expNibble);
            p.writeInt(equip.getVicious()); // 纳尼 NEXON 你是认真的吗？
            p.writeLong(0);
        }
        p.writeLong(getTime(-2));
        p.writeInt(-1);
    }

    /**
     * 添加背包信息
     * @param p 数据包
     * @param chr 角色对象
     */
    public static void addInventoryInfo(OutPacket p, Character chr) {
        for (byte i = 1; i <= 5; i++) {
            p.writeByte(chr.getInventory(InventoryType.getByType(i)).getSlotLimit());
        }
        p.writeLong(getTime(-2));
        Inventory iv = chr.getInventory(InventoryType.EQUIPPED);
        Collection<Item> equippedC = iv.list();
        List<Item> equipped = new ArrayList<>(equippedC.size());
        List<Item> equippedCash = new ArrayList<>(equippedC.size());
        for (Item item : equippedC) {
            if (item.getPosition() <= -100) {
                equippedCash.add(item);
            } else {
                equipped.add(item);
            }
        }
        for (Item item : equipped) {    // 已装备物品实际上不需要排序，感谢 Pllsz
            addItemInfo(p, item);
        }
        p.writeShort(0); // 现金装备开始
        for (Item item : equippedCash) {
            addItemInfo(p, item);
        }
        p.writeShort(0); // 装备栏开始
        for (Item item : chr.getInventory(InventoryType.EQUIP).list()) {
            addItemInfo(p, item);
        }
        p.writeInt(0);
        for (Item item : chr.getInventory(InventoryType.USE).list()) {
            addItemInfo(p, item);
        }
        p.writeByte(0);
        for (Item item : chr.getInventory(InventoryType.SETUP).list()) {
            addItemInfo(p, item);
        }
        p.writeByte(0);
        for (Item item : chr.getInventory(InventoryType.ETC).list()) {
            addItemInfo(p, item);
        }
        p.writeByte(0);
        for (Item item : chr.getInventory(InventoryType.CASH).list()) {
            addItemInfo(p, item);
        }
    }

    /**
     * 添加技能信息
     * @param p 数据包
     * @param chr 角色对象
     */
    public static void addSkillInfo(OutPacket p, Character chr) {
        p.writeByte(0); // 技能开始
        Map<Skill, SkillEntry> skills = chr.getSkills();
        int skillsSize = skills.size();
        // 我们不想包含任何隐藏技能，所以从大小列表中减去它们并忽略它们。
        for (Entry<Skill, SkillEntry> skill : skills.entrySet()) {
            if (GameConstants.isHiddenSkills(skill.getKey().getId())) {
                skillsSize--;
            }
        }
        p.writeShort(skillsSize);
        for (Entry<Skill, SkillEntry> skill : skills.entrySet()) {
            if (GameConstants.isHiddenSkills(skill.getKey().getId())) {
                continue;
            }
            p.writeInt(skill.getKey().getId());
            p.writeInt(skill.getValue().skillLevel);
            addExpirationTime(p, skill.getValue().expiration);
            if (skill.getKey().isFourthJob()) {
                p.writeInt(skill.getValue().masterLevel);
            }
        }
        p.writeShort(chr.getAllCooldowns().size());
        for (PlayerCoolDownValueHolder cooling : chr.getAllCooldowns()) {
            p.writeInt(cooling.skillId);
            int timeLeft = (int) (cooling.length + cooling.startTime - System.currentTimeMillis());
            p.writeShort(timeLeft / 1000);
        }
    }

    /**
     * 添加怪物图鉴信息
     * @param p 数据包
     * @param chr 角色对象
     */
    public static void addMonsterBookInfo(OutPacket p, Character chr) {
        p.writeInt(chr.getMonsterBookCover()); // 封面
        p.writeByte(0);
        Map<Integer, Integer> cards = chr.getMonsterBook().getCards();
        p.writeShort(cards.size());
        for (Entry<Integer, Integer> all : cards.entrySet()) {
            p.writeShort(all.getKey() % 10000); // ID
            p.writeByte(all.getValue()); // 等级
        }
    }

    /**
     * 写入外部Buff
     * @param p 数据包
     * @param chr 角色对象
     */
    public static void writeForeignBuffs(OutPacket p, Character chr) {
        p.writeInt(0);
        p.writeShort(0); //v83
        p.writeByte(0xFC);
        p.writeByte(1);
        if (chr.getBuffedValue(BuffStat.MORPH) != null) {
            p.writeInt(2);
        } else {
            p.writeInt(0);
        }
        long buffmask = 0;
        Integer buffvalue = null;
        if ((chr.getBuffedValue(BuffStat.DARKSIGHT) != null || chr.getBuffedValue(BuffStat.WIND_WALK) != null) && !chr.isHidden()) {
            buffmask |= BuffStat.DARKSIGHT.getValue();
        }
        if (chr.getBuffedValue(BuffStat.COMBO) != null) {
            buffmask |= BuffStat.COMBO.getValue();
            buffvalue = Integer.valueOf(chr.getBuffedValue(BuffStat.COMBO));
        }
        if (chr.getBuffedValue(BuffStat.SHADOWPARTNER) != null) {
            buffmask |= BuffStat.SHADOWPARTNER.getValue();
        }
        if (chr.getBuffedValue(BuffStat.SOULARROW) != null) {
            buffmask |= BuffStat.SOULARROW.getValue();
        }
        if (chr.getBuffedValue(BuffStat.MORPH) != null) {
            buffvalue = Integer.valueOf(chr.getBuffedValue(BuffStat.MORPH));
        }
        p.writeInt((int) ((buffmask >> 32) & 0xffffffffL));
        if (buffvalue != null) {
            if (chr.getBuffedValue(BuffStat.MORPH) != null) { //测试
                p.writeShort(buffvalue);
            } else {
                p.writeByte(buffvalue.byteValue());
            }
        }
        p.writeInt((int) (buffmask & 0xffffffffL));

        // 能量充能
        p.writeInt(chr.getEnergyBar() == 15000 ? 1 : 0);
        p.writeShort(0);
        p.skip(4);

        boolean dashBuff = chr.getBuffedValue(BuffStat.DASH) != null;
        // 冲刺速度
        p.writeInt(dashBuff ? 1 << 24 : 0);
        p.skip(11);
        p.writeShort(0);
        // 冲刺跳跃
        p.skip(9);
        p.writeInt(dashBuff ? 1 << 24 : 0);
        p.writeShort(0);
        p.writeByte(0);

        // 怪物骑乘
        Integer bv = chr.getBuffedValue(BuffStat.MONSTER_RIDING);
        if (bv != null) {
            Mount mount = chr.getMapleMount();
            if (mount != null) {
                p.writeInt(mount.getItemId());
                p.writeInt(mount.getSkillId());
            } else {
                p.writeLong(0);
            }
        } else {
            p.writeLong(0);
        }

        int CHAR_MAGIC_SPAWN = Randomizer.nextInt();    // 技能引用发现感谢 Rien 开发团队
        p.writeInt(CHAR_MAGIC_SPAWN);
        // 速度注入
        p.skip(8);
        p.writeInt(CHAR_MAGIC_SPAWN);
        p.writeByte(0);
        p.writeInt(CHAR_MAGIC_SPAWN);
        p.writeShort(0);
        // 导航灯
        p.skip(9);
        p.writeInt(CHAR_MAGIC_SPAWN);
        p.writeInt(0);
        // 僵尸化
        p.skip(9);
        p.writeInt(CHAR_MAGIC_SPAWN);
        p.writeShort(0);
        p.writeShort(0);
    }

    /**
     * 编码新年卡片信息
     * @param p 数据包
     * @param chr 角色对象
     */
    public static void encodeNewYearCardInfo(OutPacket p, Character chr) {
        Set<NewYearCardRecord> newyears = chr.getReceivedNewYearRecords();
        if (!newyears.isEmpty()) {
            p.writeByte(1);

            p.writeInt(newyears.size());
            for (NewYearCardRecord nyc : newyears) {
                p.writeInt(nyc.getId());
            }
        } else {
            p.writeByte(0);
        }
    }

    /**
     * 编码新年卡片
     * @param newyear 新年卡片记录
     * @param p 数据包
     */
    public static void encodeNewYearCard(NewYearCardRecord newyear, OutPacket p) {
        p.writeInt(newyear.getId());
        p.writeInt(newyear.getSenderId());
        p.writeString(newyear.getSenderName());
        p.writeBool(newyear.isSenderDiscardCard());
        p.writeLong(newyear.getDateSent());
        p.writeInt(newyear.getReceiverId());
        p.writeString(newyear.getReceiverName());
        p.writeBool(newyear.isReceiverDiscardCard());
        p.writeBool(newyear.isReceiverReceivedCard());
        p.writeLong(newyear.getDateReceived());
        p.writeString(newyear.getMessage());
    }

    /**
     * 添加戒指外观
     * @param p 数据包
     * @param chr 角色对象
     * @param crush 是否情侣戒指
     */
    public static void addRingLook(final OutPacket p, Character chr, boolean crush) {
        List<Ring> rings;
        if (crush) {
            rings = chr.getCrushRings();
        } else {
            rings = chr.getFriendshipRings();
        }
        boolean yes = false;
        for (Ring ring : rings) {
            if (ring.equipped()) {
                if (yes == false) {
                    yes = true;
                    p.writeByte(1);
                }
                p.writeInt(ring.getRingId());
                p.writeInt(0);
                p.writeInt(ring.getPartnerRingId());
                p.writeInt(0);
                p.writeInt(ring.getItemId());
            }
        }
        if (yes == false) {
            p.writeByte(0);
        }
    }

    /**
     * 添加结婚戒指外观
     * @param target 目标客户端
     * @param p 数据包
     * @param chr 角色对象
     */
    public static void addMarriageRingLook(Client target, final OutPacket p, Character chr) {
        Ring ring = chr.getMarriageRing();

        if (ring == null || !ring.equipped()) {
            p.writeByte(0);
        } else {
            p.writeByte(1);

            Character targetChr = target.getPlayer();
            if (targetChr != null && targetChr.getPartnerId() == chr.getId()) {
                p.writeInt(0);
                p.writeInt(0);
            } else {
                p.writeInt(chr.getId());
                p.writeInt(ring.getPartnerChrId());
            }

            p.writeInt(ring.getItemId());
        }
    }

    /**
     * 添加公告盒
     * @param p 数据包
     * @param shop 玩家商店
     * @param availability 可用性
     */
    public static void addAnnounceBox(final OutPacket p, PlayerShop shop, int availability) {
        p.writeByte(4);
        p.writeInt(shop.getObjectId());
        p.writeString(shop.getDescription());
        p.writeByte(0);
        p.writeByte(0);
        p.writeByte(1);
        p.writeByte(availability);
        p.writeByte(0);
    }

    /**
     * 添加公告盒
     * @param p 数据包
     * @param game 小游戏
     * @param ammount 数量
     * @param joinable 是否可加入
     */
    public static void addAnnounceBox(final OutPacket p, MiniGame game, int ammount, int joinable) {
        p.writeByte(game.getGameType().getValue());
        p.writeInt(game.getObjectId()); // 游戏ID/商店ID
        p.writeString(game.getDescription()); // 描述
        p.writeBool(!game.getPassword().isEmpty());    // 密码在这里，感谢 GabrielSin
        p.writeByte(game.getPieceType());
        p.writeByte(ammount);
        p.writeByte(2);         // 玩家容量
        p.writeByte(joinable);
    }

    /**
     * 更新雇佣商人盒信息
     * @param p 数据包
     * @param hm 雇佣商人
     */
    public static void updateHiredMerchantBoxInfo(OutPacket p, HiredMerchant hm) {
        byte[] roomInfo = hm.getShopRoomInfo();

        p.writeByte(5);
        p.writeInt(hm.getObjectId());
        p.writeString(hm.getDescription());
        p.writeByte(hm.getItemId() % 100);
        p.writeBytes(roomInfo);    // 访客容量在这里，感谢 GabrielSin
    }

    /**
     * 更新玩家商店盒信息
     * @param p 数据包
     * @param shop 玩家商店
     */
    public static void updatePlayerShopBoxInfo(OutPacket p, PlayerShop shop) {
        byte[] roomInfo = shop.getShopRoomInfo();

        p.writeByte(4);
        p.writeInt(shop.getObjectId());
        p.writeString(shop.getDescription());
        p.writeByte(0);                 // 密码
        p.writeByte(shop.getItemId() % 100);
        p.writeByte(roomInfo[0]);       // 当前玩家
        p.writeByte(roomInfo[1]);       // 最大玩家
        p.writeByte(0);
    }

    /**
     * 重新广播移动列表
     * @param op 输出数据包
     * @param ip 输入数据包
     * @param movementDataLength 移动数据长度
     */
    public static void rebroadcastMovementList(OutPacket op, InPacket ip, long movementDataLength) {
        // 移动命令长度由客户端发送，可能不是大问题？（可以在服务器端计算）
        // 如果多次读写很慢，可以使用（并缓存？）byte[] 缓冲区
        for (long i = 0; i < movementDataLength; i++) {
            op.writeByte(ip.readByte());
        }
    }

    /**
     * 序列化移动列表
     * @param p 数据包
     * @param moves 移动列表
     */
    public static void serializeMovementList(OutPacket p, List<LifeMovementFragment> moves) {
        p.writeByte(moves.size());
        for (LifeMovementFragment move : moves) {
            move.serialize(p);
        }
    }

    /**
     * 添加攻击主体
     * @param p 数据包
     * @param chr 角色对象
     * @param skill 技能ID
     * @param skilllevel 技能等级
     * @param stance 姿态
     * @param numAttackedAndDamage 攻击数量和伤害
     * @param projectile 投掷物
     * @param damage 伤害列表
     * @param speed 速度
     * @param direction 方向
     * @param display 显示
     */
    public static void addAttackBody(OutPacket p, Character chr, int skill, int skilllevel, int stance, int numAttackedAndDamage, int projectile, Map<Integer, List<Integer>> damage, int speed, int direction, int display) {
        p.writeInt(chr.getId());
        p.writeByte(numAttackedAndDamage);
        p.writeByte(0x5B);//?
        p.writeByte(skilllevel);
        if (skilllevel > 0) {
            p.writeInt(skill);
        }
        p.writeByte(display);
        p.writeByte(direction);
        p.writeByte(stance);
        p.writeByte(speed);
        p.writeByte(0x0A);
        p.writeInt(projectile);
        for (Integer oned : damage.keySet()) {
            List<Integer> onedList = damage.get(oned);
            if (onedList != null) {
                p.writeInt(oned);
                p.writeByte(0x0);
                if (skill == 4211006) {
                    p.writeByte(onedList.size());
                }
                for (Integer eachd : onedList) {
                    p.writeInt(eachd);
                }
            }
        }
    }

    /**
     * 双精度转短整型位
     * @param d 双精度值
     * @return 短整型位
     */
    public static int doubleToShortBits(double d) {
        return (int) (Double.doubleToLongBits(d) >> 48);
    }

    /**
     * 写入长整型掩码D
     * @param p 数据包
     * @param statups 状态提升列表
     */
    public static void writeLongMaskD(final OutPacket p, List<Pair<Disease, Integer>> statups) {
        long firstmask = 0;
        long secondmask = 0;
        for (Pair<Disease, Integer> statup : statups) {
            if (statup.getLeft().isFirst()) {
                firstmask |= statup.getLeft().getValue();
            } else {
                secondmask |= statup.getLeft().getValue();
            }
        }
        p.writeLong(firstmask);
        p.writeLong(secondmask);
    }

    /**
     * 写入长整型掩码
     * @param p 数据包
     * @param statups 状态提升列表
     */
    public static void writeLongMask(final OutPacket p, List<Pair<BuffStat, Integer>> statups) {
        long firstmask = 0;
        long secondmask = 0;
        for (Pair<BuffStat, Integer> statup : statups) {
            if (statup.getLeft().isFirst()) {
                firstmask |= statup.getLeft().getValue();
            } else {
                secondmask |= statup.getLeft().getValue();
            }
        }
        p.writeLong(firstmask);
        p.writeLong(secondmask);
    }

    /**
     * 从列表写入长整型掩码
     * @param p 数据包
     * @param statups 状态列表
     */
    public static void writeLongMaskFromList(OutPacket p, List<BuffStat> statups) {
        long firstmask = 0;
        long secondmask = 0;
        for (BuffStat statup : statups) {
            if (statup.isFirst()) {
                firstmask |= statup.getValue();
            } else {
                secondmask |= statup.getValue();
            }
        }
        p.writeLong(firstmask);
        p.writeLong(secondmask);
    }

    /**
     * 写入长整型编码临时掩码
     * @param p 数据包
     * @param stati 状态集合
     */
    public static void writeLongEncodeTemporaryMask(final OutPacket p, Collection<MonsterStatus> stati) {
        int[] masks = new int[4];

        for (MonsterStatus statup : stati) {
            int pos = statup.isFirst() ? 0 : 2;
            for (int i = 0; i < 2; i++) {
                masks[pos + i] |= statup.getValue() >> 32 * i;
            }
        }

        for (int mask : masks) {
            p.writeInt(mask);
        }
    }

    /**
     * 写入长整型掩码SlowD
     * @param p 数据包
     */
    public static void writeLongMaskSlowD(final OutPacket p) {
        p.writeInt(0);
        p.writeInt(2048);
        p.writeLong(0);
    }

    /**
     * 写入长整型掩码椅子
     * @param p 数据包
     */
    public static void writeLongMaskChair(OutPacket p) {
        p.writeInt(0);
        p.writeInt(262144);
        p.writeLong(0);
    }

    /**
     * 写入整型掩码
     * @param p 数据包
     * @param stats 状态映射
     */
    public static void writeIntMask(OutPacket p, Map<MonsterStatus, Integer> stats) {
        int firstmask = 0;
        int secondmask = 0;
        for (MonsterStatus stat : stats.keySet()) {
            if (stat.isFirst()) {
                firstmask |= stat.getValue();
            } else {
                secondmask |= stat.getValue();
            }
        }
        p.writeInt(firstmask);
        p.writeInt(secondmask);
    }

    /**
     * 获取右填充字符串
     * @param in 输入字符串
     * @param padchar 填充字符
     * @param length 长度
     * @return 填充后的字符串
     */
    public static String getRightPaddedStr(String in, char padchar, int length) {
        StringBuilder builder = new StringBuilder(in);
        for (int x = in.length(); x < length; x++) {
            builder.append(padchar);
        }
        return builder.toString();
    }

    /**
     * 添加戒指信息
     * @param p 数据包
     * @param chr 角色对象
     */
    public static void addRingInfo(OutPacket p, Character chr) {
        p.writeShort(chr.getCrushRings().size());
        for (Ring ring : chr.getCrushRings()) {
            p.writeInt(ring.getPartnerChrId());
            p.writeFixedString(getRightPaddedStr(ring.getPartnerName(), '\0', 13));
            p.writeInt(ring.getRingId());
            p.writeInt(0);
            p.writeInt(ring.getPartnerRingId());
            p.writeInt(0);
        }
        p.writeShort(chr.getFriendshipRings().size());
        for (Ring ring : chr.getFriendshipRings()) {
            p.writeInt(ring.getPartnerChrId());
            p.writeFixedString(getRightPaddedStr(ring.getPartnerName(), '\0', 13));
            p.writeInt(ring.getRingId());
            p.writeInt(0);
            p.writeInt(ring.getPartnerRingId());
            p.writeInt(0);
            p.writeInt(ring.getItemId());
        }

        if (chr.getPartnerId() > 0) {
            Ring marriageRing = chr.getMarriageRing();

            p.writeShort(1);
            p.writeInt(chr.getRelationshipId());
            p.writeInt(chr.getGender() == 0 ? chr.getId() : chr.getPartnerId());
            p.writeInt(chr.getGender() == 0 ? chr.getPartnerId() : chr.getId());
            p.writeShort((marriageRing != null) ? 3 : 1);
            if (marriageRing != null) {
                p.writeInt(marriageRing.getItemId());
                p.writeInt(marriageRing.getItemId());
            } else {
                p.writeInt(ItemId.WEDDING_RING_MOONSTONE); // 订婚戒指的结果（对于订婚并不重要）
                p.writeInt(ItemId.WEDDING_RING_MOONSTONE); // 订婚戒指的结果（对于订婚并不重要）
            }
            p.writeFixedString(StringUtil.getRightPaddedStr(chr.getGender() == 0 ? chr.getName() : Character.getNameById(chr.getPartnerId()), '\0', 13));
            p.writeFixedString(StringUtil.getRightPaddedStr(chr.getGender() == 0 ? Character.getNameById(chr.getPartnerId()) : chr.getName(), '\0', 13));
        } else {
            p.writeShort(0);
        }
    }

    /**
     * 添加宠物信息
     * @param p 数据包
     * @param pet 宠物对象
     * @param showpet 是否显示宠物
     */
    public static void addPetInfo(final OutPacket p, Pet pet, boolean showpet) {
        p.writeByte(1);
        if (showpet) {
            p.writeByte(0);
        }

        p.writeInt(pet.getItemId());
        p.writeString(pet.getName());
        p.writeLong(pet.getUniqueId());
        p.writePos(pet.getPos());
        p.writeByte(pet.getStance());
        p.writeInt(pet.getFh());
    }

    /**
     * 添加现金物品信息
     * @param p 数据包
     * @param item 物品对象
     * @param accountId 账号ID
     */
    public static void addCashItemInformation(OutPacket p, Item item, int accountId) {
        addCashItemInformation(p, item, accountId, null);
    }

    /**
     * 添加现金物品信息
     * @param p 数据包
     * @param item 物品对象
     * @param accountId 账号ID
     * @param giftMessage 礼物消息
     */
    public static void addCashItemInformation(OutPacket p, Item item, int accountId, String giftMessage) {
        boolean isGift = giftMessage != null;
        boolean isRing = false;
        Equip equip = null;
        if (item.getInventoryType().equals(InventoryType.EQUIP)) {
            equip = (Equip) item;
            isRing = equip.getRingId() > -1;
        }
        p.writeLong(item.getPetId() > -1 ? item.getPetId() : isRing ? equip.getRingId() : item.getCashId());
        if (!isGift) {
            p.writeInt(accountId);
            p.writeInt(0);
        }
        p.writeInt(item.getItemId());
        if (!isGift) {
            p.writeInt(item.getSN());
            p.writeShort(item.getQuantity());
        }
        p.writeFixedString(StringUtil.getRightPaddedStr(item.getGiftFrom(), '\0', 13));
        if (isGift) {
            p.writeFixedString(giftMessage, 73);
            return;
        }
        addExpirationTime(p, item.getExpiration());
        p.writeLong(0);
    }

    /**
     * 写入修改后的现金物品
     * @param p 数据包
     * @param item 修改后的现金物品对象
     */
    public static void writeModifiedCashItem(OutPacket p, ModifiedCashItemDO item) {
        List<Pair<CommodityFlag, Number>> writeList = new ArrayList<>();
        for (CommodityFlag commodityFlag : CommodityFlag.getAvailableSortedValues()) {
            for (Field field : item.getClass().getDeclaredFields()) {
                Column column = field.getAnnotation(Column.class);
                String columnName;
                if (column == null || RequireUtil.isEmpty(column.value())) {
                    columnName = com.mybatisflex.core.util.StringUtil.camelToUnderline(field.getName());
                } else {
                    columnName = column.value();
                }

                if (!Objects.equals(commodityFlag.name(), columnName.toUpperCase())) {
                    continue;
                }
                Number fieldVal = null;
                try {
                    field.setAccessible(true);
                    fieldVal = (Number) field.get(item);
                } catch (IllegalAccessException ignore) {

                }
                if (fieldVal != null) {
                    writeList.add(new Pair<>(commodityFlag, fieldVal));
                }
                break;
            }
        }
        if (writeList.isEmpty()) {
            return;
        }
        writeList.add(CommodityFlag.FLAG.getSort(), new Pair<>(CommodityFlag.FLAG, writeList.stream().mapToLong(pair -> pair.getLeft().getFlag()).sum()));
        writeList.forEach(w -> {
            CommodityFlag commodityFlag = w.getLeft();
            Number fieldVal = w.getRight();
            commodityFlag.getWriteMapper().accept(p, fieldVal);
        });
    }

    /**
     * 添加家谱条目
     * @param p 数据包
     * @param entry 家族条目
     */
    public static void addPedigreeEntry(OutPacket p, FamilyEntry entry) {
        Character chr = entry.getChr();
        boolean isOnline = chr != null;
        p.writeInt(entry.getChrId()); //ID
        p.writeInt(entry.getSenior() != null ? entry.getSenior().getChrId() : 0); //parent ID
        p.writeShort(entry.getJob().getId()); //job id
        p.writeByte(entry.getLevel()); //level
        p.writeBool(isOnline); //isOnline
        p.writeInt(entry.getReputation()); //current rep
        p.writeInt(entry.getTotalReputation()); //total rep
        p.writeInt(entry.getRepsToSenior()); //reps recorded to senior
        p.writeInt(entry.getTodaysRep());
        p.writeInt(isOnline ? ((chr.isAwayFromWorld() || chr.getCashShop().isOpened()) ? -1 : chr.getClient().getChannel() - 1) : 0);
        p.writeInt(isOnline ? (int) (chr.getLoggedInTime() / 60000) : 0); //time online in minutes
        p.writeString(entry.getName()); //name
    }

    /**
     * 编码无父级怪物生成特效
     * @param p 数据包
     * @param newSpawn 是否新生成
     * @param effect 特效
     */
    public static void encodeParentlessMobSpawnEffect(OutPacket p, boolean newSpawn, int effect) {
        if (effect > 0) {
            p.writeByte(effect);
            p.writeByte(0);
            p.writeShort(0);
            if (effect == 15) {
                p.writeByte(0);
            }
        }
        p.writeByte(newSpawn ? -2 : -1);
    }

    /**
     * 编码临时状态
     * @param p 数据包
     * @param stati 状态映射
     */
    public static void encodeTemporary(OutPacket p, Map<MonsterStatus, MonsterStatusEffect> stati) {
        int pCounter = -1;
        int mCounter = -1;

        stati = stati.entrySet()  // 修复一些导致玩家崩溃的状态
                .stream()
                .filter(e -> !(e.getKey().equals(MonsterStatus.WATK) || e.getKey().equals(MonsterStatus.WDEF)))
                .collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue()));

        writeLongEncodeTemporaryMask(p, stati.keySet());    // 数据包结构映射感谢 Eric

        for (Entry<MonsterStatus, MonsterStatusEffect> s : stati.entrySet()) {
            MonsterStatusEffect mse = s.getValue();
            p.writeShort(mse.getStati().get(s.getKey()));

            MobSkill mobSkill = mse.getMobSkill();
            if (mobSkill != null) {
                writeMobSkillId(p, mobSkill.getId());

                switch (s.getKey()) {
                    case WEAPON_REFLECT -> pCounter = mobSkill.getX();
                    case MAGIC_REFLECT -> mCounter = mobSkill.getY();
                }
            } else {
                Skill skill = mse.getSkill();
                p.writeInt(skill != null ? skill.getId() : 0);
            }

            p.writeShort(-1);    // 持续时间
        }

        // 反射数据包结构发现感谢 Arnah (Vertisy)
        if (pCounter != -1) {
            p.writeInt(pCounter);// wPCounter_
        }
        if (mCounter != -1) {
            p.writeInt(mCounter);// wMCounter_
        }
        if (pCounter != -1 || mCounter != -1) {
            p.writeInt(100);// nCounterProb_
        }
    }

    /**
     * 归一化自定义最大HP
     * @param currHP 当前HP
     * @param maxHP 最大HP
     * @return 归一化后的HP对
     */
    public static Pair<Integer, Integer> normalizedCustomMaxHP(long currHP, long maxHP) {
        int sendHP, sendMaxHP;

        if (maxHP <= Integer.MAX_VALUE) {
            sendHP = (int) currHP;
            sendMaxHP = (int) maxHP;
        } else {
            float f = ((float) currHP) / maxHP;

            sendHP = (int) (Integer.MAX_VALUE * f);
            sendMaxHP = Integer.MAX_VALUE;
        }

        return new Pair<>(sendHP, sendMaxHP);
    }

    /**
     * 添加队伍状态
     * @param forchannel 频道
     * @param party 队伍对象
     * @param p 数据包
     * @param leaving 是否离开
     */
    public static void addPartyStatus(int forchannel, Party party, OutPacket p, boolean leaving) {
        List<PartyCharacter> partymembers = new ArrayList<>(party.getMembers());
        while (partymembers.size() < 6) {
            partymembers.add(new PartyCharacter());
        }
        for (PartyCharacter partychar : partymembers) {
            p.writeInt(partychar.getId());
        }
        for (PartyCharacter partychar : partymembers) {
            p.writeFixedString(getRightPaddedStr(partychar.getName(), '\0', 13));
        }
        for (PartyCharacter partychar : partymembers) {
            p.writeInt(partychar.getJobId());
        }
        for (PartyCharacter partychar : partymembers) {
            p.writeInt(partychar.getLevel());
        }
        for (PartyCharacter partychar : partymembers) {
            if (partychar.isOnline()) {
                p.writeInt(partychar.getChannel() - 1);
            } else {
                p.writeInt(-2);
            }
        }
        p.writeInt(party.getLeader().getId());
        for (PartyCharacter partychar : partymembers) {
            if (partychar.getChannel() == forchannel) {
                p.writeInt(partychar.getMapId());
            } else {
                p.writeInt(0);
            }
        }

        Map<Integer, Door> partyDoors = party.getDoors();
        for (PartyCharacter partychar : partymembers) {
            if (partychar.getChannel() == forchannel && !leaving) {
                if (partyDoors.size() > 0) {
                    Door door = partyDoors.get(partychar.getId());
                    if (door != null) {
                        DoorObject mdo = door.getTownDoor();
                        p.writeInt(mdo.getTown().getId());
                        p.writeInt(mdo.getArea().getId());
                        p.writeInt(mdo.getPosition().x);
                        p.writeInt(mdo.getPosition().y);
                    } else {
                        p.writeInt(0); // MapId.NONE
                        p.writeInt(0); // MapId.NONE
                        p.writeInt(0);
                        p.writeInt(0);
                    }
                } else {
                    p.writeInt(0); // MapId.NONE
                    p.writeInt(0); // MapId.NONE
                    p.writeInt(0);
                    p.writeInt(0);
                }
            } else {
                p.writeInt(0); // MapId.NONE
                p.writeInt(0); // MapId.NONE
                p.writeInt(0);
                p.writeInt(0);
            }
        }
    }

    /**
     * 显示HP恢复
     * @param cid 角色ID
     * @param amount 恢复量
     * @return 数据包
     */
    public static Packet showHpHealed(int cid, int amount) {
        OutPacket p = OutPacket.create(SendOpcode.SHOW_FOREIGN_EFFECT);
        p.writeInt(cid);
        p.writeByte(0x0A); //Type
        p.writeByte(amount);
        return p;
    }

    /**
     * 新年卡片响应
     * @param user 用户
     * @param newyear 新年卡片记录
     * @param mode 模式
     * @param msg 消息
     * @return 数据包
     */
    public static Packet onNewYearCardRes(Character user, NewYearCardRecord newyear, int mode, int msg) {
        OutPacket p = OutPacket.create(SendOpcode.NEW_YEAR_CARD_RES);
        p.writeByte(mode);
        switch (mode) {
            case 4: // 成功发送新年卡片\r\n 给 %s。
            case 6: // 成功接收新年卡片。
                encodeNewYearCard(newyear, p);
                break;

            case 8: // 成功删除新年卡片。
                p.writeInt(newyear.getId());
                break;

            case 5: // Nexon 很蠢，让 4 种模式做同样的操作..
            case 7:
            case 9:
            case 0xB:
                // 0x10: 您没有空闲插槽来存储卡片。\r\n请稍后再试。
                // 0x11: 您没有卡片可发送。
                // 0x12: 错误的库存信息！
                // 0x13: 找不到该角色！
                // 0x14: 数据不连贯！
                // 0x15: 数据库操作期间发生错误。
                // 0x16: 发生未知错误！
                // 0xF: 您不能给自己发送卡片！
                p.writeByte(msg);
                break;

            case 0xA:   // GetUnreceivedList_Done
                int nSN = 1;
                p.writeInt(nSN);
                if ((nSN - 1) <= 98 && nSN > 0) {//呵呵 Nexon 你在开玩笑吗
                    for (int i = 0; i < nSN; i++) {
                        p.writeInt(newyear.getId());
                        p.writeInt(newyear.getSenderId());
                        p.writeString(newyear.getSenderName());
                    }
                }
                break;

            case 0xC:   // NotiArrived
                p.writeInt(newyear.getId());
                p.writeString(newyear.getSenderName());
                break;

            case 0xD:   // BroadCast_AddCardInfo
                p.writeInt(newyear.getId());
                p.writeInt(user.getId());
                break;

            case 0xE:   // BroadCast_RemoveCardInfo
                p.writeInt(newyear.getId());
                break;
        }
        return p;
    }

    /**
     * 刷新传送地图列表
     * @param chr 角色对象
     * @param delete 是否删除
     * @param vip 是否VIP
     * @return 数据包
     */
    public static Packet trockRefreshMapList(Character chr, boolean delete, boolean vip) {
        final OutPacket p = OutPacket.create(SendOpcode.MAP_TRANSFER_RESULT);
        p.writeByte(delete ? 2 : 3);
        if (vip) {
            p.writeByte(1);
            List<Integer> map = chr.getVipTrockMaps();
            for (int i = 0; i < 10; i++) {
                p.writeInt(map.get(i));
            }
        } else {
            p.writeByte(0);
            List<Integer> map = chr.getTrockMaps();
            for (int i = 0; i < 5; i++) {
                p.writeInt(map.get(i));
            }
        }
        return p;
    }

    /**
     * 给予名声错误响应
     * @param status 状态
     * @return 数据包
     */
    public static Packet giveFameErrorResponse(int status) {
        final OutPacket p = OutPacket.create(SendOpcode.FAME_RESPONSE);
        p.writeByte(status);
        return p;
    }

    /**
     * 左侧击退
     * @return 数据包
     */
    public static Packet leftKnockBack() {
        return OutPacket.create(SendOpcode.LEFT_KNOCK_BACK);
    }

    /**
     * 发送自动HP药水
     * @param itemId 物品ID
     * @return 数据包
     */
    public static Packet sendAutoHpPot(int itemId) {
        final OutPacket p = OutPacket.create(SendOpcode.AUTO_HP_POT);
        p.writeInt(itemId);
        return p;
    }

    /**
     * 发送自动MP药水
     * @param itemId 物品ID
     * @return 数据包
     */
    public static Packet sendAutoMpPot(int itemId) {
        OutPacket p = OutPacket.create(SendOpcode.AUTO_MP_POT);
        p.writeInt(itemId);
        return p;
    }

    /**
     * 发送Vega卷轴
     * @param op 操作
     * @return 数据包
     */
    public static Packet sendVegaScroll(int op) {
        OutPacket p = OutPacket.create(SendOpcode.VEGA_SCROLL);
        p.writeByte(op);
        return p;
    }

    /**
     * 获取显示经验获得
     * @param gain 获得量
     * @param equip 装备
     * @param party 队伍
     * @param inChat 是否在聊天框显示
     * @param white 是否白色
     * @return 数据包
     */
    public static Packet getShowExpGain(int gain, int equip, int party, boolean inChat, boolean white) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        p.writeByte(3); // 3 = 经验, 4 = 人气, 5 = 金币, 6 = 公会点数
        p.writeBool(white);
        p.writeInt(gain);
        p.writeBool(inChat);
        p.writeInt(0); // 奖励活动经验
        p.writeByte(0); // 第三个怪物击杀活动
        p.writeByte(0); // RIP 字节，这总是 0
        p.writeInt(0); // 婚礼奖励
        if (inChat) { // 任务奖励倍率相关
            p.writeByte(0);
        }

        p.writeByte(0); // 0 = 组队奖励, 100 = 1x 奖励经验, 200 = 2x 奖励经验
        p.writeInt(party); // 组队奖励
        p.writeInt(equip); // 装备奖励
        p.writeInt(0); // 网吧奖励
        p.writeInt(0); // 彩虹周奖励
        return p;
    }

    /**
     * 给予名声响应
     * @param mode 模式
     * @param charname 角色名
     * @param newfame 新名声
     * @return 数据包
     */
    public static Packet giveFameResponse(int mode, String charname, int newfame) {
        final OutPacket p = OutPacket.create(SendOpcode.FAME_RESPONSE);
        p.writeByte(0);
        p.writeString(charname);
        p.writeByte(mode);
        p.writeShort(newfame);
        p.writeShort(0);
        return p;
    }

    /**
     * 接收名声
     * @param mode 模式
     * @param charnameFrom 来源角色名
     * @return 数据包
     */
    public static Packet receiveFame(int mode, String charnameFrom) {
        final OutPacket p = OutPacket.create(SendOpcode.FAME_RESPONSE);
        p.writeByte(5);
        p.writeString(charnameFrom);
        p.writeByte(mode);
        return p;
    }

    /**
     * 获取显示名声获得
     * @param gain 获得量
     * @return 数据包
     */
    public static Packet getShowFameGain(int gain) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        p.writeByte(4);
        p.writeInt(gain);
        return p;
    }

    /**
     * 获取显示金币获得
     * @param gain 获得量
     * @param inChat 是否在聊天框显示
     * @return 数据包
     */
    public static Packet getShowMesoGain(int gain, boolean inChat) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        if (!inChat) {
            p.writeByte(0);
            p.writeShort(1); //v83
        } else {
            p.writeByte(5);
        }
        p.writeInt(gain);
        p.writeShort(0);
        return p;
    }

    /**
     * 显示OX测验
     * @param questionSet 问题集
     * @param questionId 问题ID
     * @param askQuestion 是否提问
     * @return 数据包
     */
    public static Packet showOXQuiz(int questionSet, int questionId, boolean askQuestion) {
        OutPacket p = OutPacket.create(SendOpcode.OX_QUIZ);
        p.writeByte(askQuestion ? 1 : 0);
        p.writeByte(questionSet);
        p.writeShort(questionId);
        return p;
    }
}
