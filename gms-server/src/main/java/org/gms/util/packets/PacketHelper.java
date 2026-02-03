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
    private final static long FT_UT_OFFSET = 116444736010800000L + (10000L * TimeZone.getDefault().getOffset(System.currentTimeMillis()));
    private final static long DEFAULT_TIME = 150842304000000000L;
    public final static long ZERO_TIME = 94354848000000000L;
    private final static long PERMANENT = 150841440000000000L;

    public static class WhisperFlag {
        public static final byte LOCATION = 0x01;
        public static final byte WHISPER = 0x02;
        public static final byte REQUEST = 0x04;
        public static final byte RESULT = 0x08;
        public static final byte RECEIVE = 0x10;
        public static final byte BLOCKED = 0x20;
        public static final byte LOCATION_FRIEND = 0x40;
    }

    public static long getTime(long utcTimestamp) {
        if (utcTimestamp < 0 && utcTimestamp >= -3) {
            if (utcTimestamp == -1) {
                return DEFAULT_TIME;
            } else if (utcTimestamp == -2) {
                return ZERO_TIME;
            } else {
                return PERMANENT;
            }
        }
        return utcTimestamp * 10000 + FT_UT_OFFSET;
    }

    public static void writeMobSkillId(OutPacket packet, MobSkillId msId) {
        packet.writeShort(msId.type().getId());
        packet.writeShort(msId.level());
    }

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

    public static void addCharStats(OutPacket p, Character chr) {
        p.writeInt(chr.getId()); // character id
        p.writeFixedString(StringUtil.getRightPaddedStr(chr.getName(), '\0', 13));
        p.writeByte(chr.getGender()); // gender (0 = male, 1 = female)
        p.writeByte(chr.getSkinColor().getId()); // skin color
        p.writeInt(chr.getFace()); // face
        p.writeInt(chr.getHair()); // hair

        for (int i = 0; i < 3; i++) {
            Pet pet = chr.getPet(i);
            if (pet != null) {
                p.writeLong(pet.getUniqueId());
            } else {
                p.writeLong(0);
            }
        }

        p.writeByte(chr.getLevel()); // level
        p.writeShort(chr.getJob().getId()); // job
        p.writeShort(chr.getStr()); // str
        p.writeShort(chr.getDex()); // dex
        p.writeShort(chr.getInt()); // int
        p.writeShort(chr.getLuk()); // luk
        p.writeShort(chr.getHp()); // hp (?)
        p.writeShort(chr.getClientMaxHp()); // maxhp
        p.writeShort(chr.getMp()); // mp (?)
        p.writeShort(chr.getClientMaxMp()); // maxmp
        p.writeShort(chr.getRemainingAp()); // remaining ap
        if (GameConstants.hasSPTable(chr.getJob())) {
            addRemainingSkillInfo(p, chr);
        } else {
            p.writeShort(chr.getRemainingSp()); // remaining sp
        }
        p.writeInt(chr.getExp()); // current exp
        p.writeShort(chr.getFame()); // fame
        p.writeInt(chr.getGachaExp()); //Gacha Exp
        p.writeInt(chr.getMapId()); // current map id
        p.writeByte(chr.getInitialSpawnPoint()); // spawnpoint
        p.writeInt(0);
    }

    public static void addCharLook(final OutPacket p, Character chr, boolean mega) {
        p.writeByte(chr.getGender());
        p.writeByte(chr.getSkinColor().getId()); // skin color
        p.writeInt(chr.getFace()); // face
        p.writeBool(!mega);
        p.writeInt(chr.getHair()); // hair
        addCharEquips(p, chr);
    }

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
        addAreaInfo(p, chr);
        p.writeShort(0);
    }

    public static void addNewYearInfo(OutPacket p, Character chr) {
        Set<NewYearCardRecord> received = chr.getReceivedNewYearRecords();

        p.writeShort(received.size());
        for (NewYearCardRecord nyc : received) {
            encodeNewYearCard(nyc, p);
        }
    }

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

    public static void addMiniGameInfo(OutPacket p, Character chr) {
        p.writeShort(0);
    }

    public static void addAreaInfo(OutPacket p, Character chr) {
        Map<Short, String> areaInfos = chr.getAreaInfos();
        p.writeShort(areaInfos.size());
        for (Short area : areaInfos.keySet()) {
            p.writeShort(area);
            p.writeString(areaInfos.get(area));
        }
    }

    public static void addCharEquips(final OutPacket p, Character chr) {
        Inventory equip = chr.getInventory(InventoryType.EQUIPPED);
        Collection<Item> ii = ItemInformationProvider.getInstance().canWearEquipment(chr, equip.list());
        Map<Short, Integer> myEquip = new LinkedHashMap<>();
        Map<Short, Integer> maskedEquip = new LinkedHashMap<>();
        for (Item item : ii) {
            short pos = (short) (item.getPosition() * -1);
            if (pos < 100 && myEquip.get(pos) == null) {
                myEquip.put(pos, item.getItemId());
            } else if (pos > 100 && pos != 111) {
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

    public static void addCharEntry(OutPacket p, Character chr, boolean viewall) {
        addCharStats(p, chr);
        addCharLook(p, chr, false);
        if (!viewall) {
            p.writeByte(0);
        }
        if (chr.isGM() || chr.isGmJob()) {
            p.writeByte(0);
            return;
        }
        p.writeByte(1);
        p.writeInt(chr.getRank());
        p.writeInt(chr.getRankMove());
        p.writeInt(chr.getJobRank());
        p.writeInt(chr.getJobRankMove());
    }

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

    public static void addExpirationTime(final OutPacket p, long time) {
        p.writeLong(getTime(time));
    }

    public static void addItemInfo(OutPacket p, Item item) {
        addItemInfo(p, item, false);
    }

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
            p.writeShort(pet.getPetAttribute());
            p.writeShort(0);
            p.writeInt(18000);
            p.writeShort(0);
            return;
        }
        if (equip == null) {
            p.writeShort(item.getQuantity());
            p.writeString(item.getOwner());
            p.writeShort(item.getFlag());

            if (ItemConstants.isRechargeable(item.getItemId())) {
                p.writeInt(2);
                p.writeBytes(new byte[]{(byte) 0x54, 0, 0, (byte) 0x34});
            }
            return;
        }
        p.writeByte(equip.getUpgradeSlots());
        p.writeByte(equip.getLevel());
        p.writeShort(equip.getStr());
        p.writeShort(equip.getDex());
        p.writeShort(equip.getInt());
        p.writeShort(equip.getLuk());
        p.writeShort(equip.getHp());
        p.writeShort(equip.getMp());
        p.writeShort(equip.getWatk());
        p.writeShort(equip.getMatk());
        p.writeShort(equip.getWdef());
        p.writeShort(equip.getMdef());
        p.writeShort(equip.getAcc());
        p.writeShort(equip.getAvoid());
        p.writeShort(equip.getHands());
        p.writeShort(equip.getSpeed());
        p.writeShort(equip.getJump());
        p.writeString(equip.getOwner());
        p.writeShort(equip.getFlag());

        if (isCash) {
            for (int i = 0; i < 10; i++) {
                p.writeByte(0x40);
            }
        } else {
            int itemLevel = equip.getItemLevel();

            long expNibble = (ExpTable.getExpNeededForLevel(ii.getEquipLevelReq(item.getItemId())) * equip.getItemExp());
            expNibble /= ExpTable.getEquipExpNeededForLevel(itemLevel);

            p.writeByte(0);
            p.writeByte(itemLevel);
            p.writeInt((int) expNibble);
            p.writeInt(equip.getVicious());
            p.writeLong(0);
        }
        p.writeLong(getTime(-2));
        p.writeInt(-1);
    }

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
        for (Item item : equipped) {
            addItemInfo(p, item);
        }
        p.writeShort(0);
        for (Item item : equippedCash) {
            addItemInfo(p, item);
        }
        p.writeShort(0);
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

    public static void addSkillInfo(OutPacket p, Character chr) {
        p.writeByte(0);
        Map<Skill, SkillEntry> skills = chr.getSkills();
        int skillsSize = skills.size();
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

    public static void addMonsterBookInfo(OutPacket p, Character chr) {
        p.writeInt(chr.getMonsterBookCover());
        p.writeByte(0);
        Map<Integer, Integer> cards = chr.getMonsterBook().getCards();
        p.writeShort(cards.size());
        for (Entry<Integer, Integer> all : cards.entrySet()) {
            p.writeShort(all.getKey() % 10000);
            p.writeByte(all.getValue());
        }
    }

    public static void writeForeignBuffs(OutPacket p, Character chr) {
        p.writeInt(0);
        p.writeShort(0);
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
            if (chr.getBuffedValue(BuffStat.MORPH) != null) {
                p.writeShort(buffvalue);
            } else {
                p.writeByte(buffvalue.byteValue());
            }
        }
        p.writeInt((int) (buffmask & 0xffffffffL));

        p.writeInt(chr.getEnergyBar() == 15000 ? 1 : 0);
        p.writeShort(0);
        p.skip(4);

        boolean dashBuff = chr.getBuffedValue(BuffStat.DASH) != null;
        p.writeInt(dashBuff ? 1 << 24 : 0);
        p.skip(11);
        p.writeShort(0);
        p.skip(9);
        p.writeInt(dashBuff ? 1 << 24 : 0);
        p.writeShort(0);
        p.writeByte(0);

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

        int CHAR_MAGIC_SPAWN = Randomizer.nextInt();
        p.writeInt(CHAR_MAGIC_SPAWN);
        p.skip(8);
        p.writeInt(CHAR_MAGIC_SPAWN);
        p.writeByte(0);
        p.writeInt(CHAR_MAGIC_SPAWN);
        p.writeShort(0);
        p.skip(9);
        p.writeInt(CHAR_MAGIC_SPAWN);
        p.writeInt(0);
        p.skip(9);
        p.writeInt(CHAR_MAGIC_SPAWN);
        p.writeShort(0);
        p.writeShort(0);
    }

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

    public static void addAnnounceBox(final OutPacket p, MiniGame game, int ammount, int joinable) {
        p.writeByte(game.getGameType().getValue());
        p.writeInt(game.getObjectId());
        p.writeString(game.getDescription());
        p.writeBool(!game.getPassword().isEmpty());
        p.writeByte(game.getPieceType());
        p.writeByte(ammount);
        p.writeByte(2);
        p.writeByte(joinable);
    }

    public static void updateHiredMerchantBoxInfo(OutPacket p, HiredMerchant hm) {
        byte[] roomInfo = hm.getShopRoomInfo();

        p.writeByte(5);
        p.writeInt(hm.getObjectId());
        p.writeString(hm.getDescription());
        p.writeByte(hm.getItemId() % 100);
        p.writeBytes(roomInfo);
    }

    public static void updatePlayerShopBoxInfo(OutPacket p, PlayerShop shop) {
        byte[] roomInfo = shop.getShopRoomInfo();

        p.writeByte(4);
        p.writeInt(shop.getObjectId());
        p.writeString(shop.getDescription());
        p.writeByte(0);
        p.writeByte(shop.getItemId() % 100);
        p.writeByte(roomInfo[0]);
        p.writeByte(roomInfo[1]);
        p.writeByte(0);
    }

    public static void rebroadcastMovementList(OutPacket op, InPacket ip, long movementDataLength) {
        for (long i = 0; i < movementDataLength; i++) {
            op.writeByte(ip.readByte());
        }
    }

    public static void serializeMovementList(OutPacket p, List<LifeMovementFragment> moves) {
        p.writeByte(moves.size());
        for (LifeMovementFragment move : moves) {
            move.serialize(p);
        }
    }

    public static void addAttackBody(OutPacket p, Character chr, int skill, int skilllevel, int stance, int numAttackedAndDamage, int projectile, Map<Integer, List<Integer>> damage, int speed, int direction, int display) {
        p.writeInt(chr.getId());
        p.writeByte(numAttackedAndDamage);
        p.writeByte(0x5B);
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

    public static int doubleToShortBits(double d) {
        return (int) (Double.doubleToLongBits(d) >> 48);
    }

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

    public static void writeLongMaskSlowD(final OutPacket p) {
        p.writeInt(0);
        p.writeInt(2048);
        p.writeLong(0);
    }

    public static void writeLongMaskChair(OutPacket p) {
        p.writeInt(0);
        p.writeInt(262144);
        p.writeLong(0);
    }

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

    public static String getRightPaddedStr(String in, char padchar, int length) {
        StringBuilder builder = new StringBuilder(in);
        for (int x = in.length(); x < length; x++) {
            builder.append(padchar);
        }
        return builder.toString();
    }

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
                p.writeInt(ItemId.WEDDING_RING_MOONSTONE);
                p.writeInt(ItemId.WEDDING_RING_MOONSTONE);
            }
            p.writeFixedString(StringUtil.getRightPaddedStr(chr.getGender() == 0 ? chr.getName() : Character.getNameById(chr.getPartnerId()), '\0', 13));
            p.writeFixedString(StringUtil.getRightPaddedStr(chr.getGender() == 0 ? Character.getNameById(chr.getPartnerId()) : chr.getName(), '\0', 13));
        } else {
            p.writeShort(0);
        }
    }

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

    public static void addCashItemInformation(OutPacket p, Item item, int accountId) {
        addCashItemInformation(p, item, accountId, null);
    }

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

    public static void encodeTemporary(OutPacket p, Map<MonsterStatus, MonsterStatusEffect> stati) {
        int pCounter = -1;
        int mCounter = -1;

        stati = stati.entrySet()
                .stream()
                .filter(e -> !(e.getKey().equals(MonsterStatus.WATK) || e.getKey().equals(MonsterStatus.WDEF)))
                .collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue()));

        writeLongEncodeTemporaryMask(p, stati.keySet());

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

            p.writeShort(-1);
        }

        if (pCounter != -1) {
            p.writeInt(pCounter);
        }
        if (mCounter != -1) {
            p.writeInt(mCounter);
        }
        if (pCounter != -1 || mCounter != -1) {
            p.writeInt(100);
        }
    }

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

    public static Packet showHpHealed(int cid, int amount) {
        OutPacket p = OutPacket.create(SendOpcode.SHOW_FOREIGN_EFFECT);
        p.writeInt(cid);
        p.writeByte(0x0A); //Type
        p.writeByte(amount);
        return p;
    }

    public static Packet onNewYearCardRes(Character user, NewYearCardRecord newyear, int mode, int msg) {
        OutPacket p = OutPacket.create(SendOpcode.NEW_YEAR_CARD_RES);
        p.writeByte(mode);
        switch (mode) {
            case 4: // Successfully sent a New Year Card\r\n to %s.
            case 6: // Successfully received a New Year Card.
                encodeNewYearCard(newyear, p);
                break;

            case 8: // Successfully deleted a New Year Card.
                p.writeInt(newyear.getId());
                break;

            case 5: // Nexon's stupid and makes 4 modes do the same operation..
            case 7:
            case 9:
            case 0xB:
                // 0x10: You have no free slot to store card.\r\ntry later on please.
                // 0x11: You have no card to send.
                // 0x12: Wrong inventory information !
                // 0x13: Cannot find such character !
                // 0x14: Incoherent Data !
                // 0x15: An error occured during DB operation.
                // 0x16: An unknown error occured !
                // 0xF: You cannot send a card to yourself !
                p.writeByte(msg);
                break;

            case 0xA:   // GetUnreceivedList_Done
                int nSN = 1;
                p.writeInt(nSN);
                if ((nSN - 1) <= 98 && nSN > 0) {//lol nexon are you kidding
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

    public static Packet giveFameErrorResponse(int status) {
        final OutPacket p = OutPacket.create(SendOpcode.FAME_RESPONSE);
        p.writeByte(status);
        return p;
    }

    public static Packet leftKnockBack() {
        return OutPacket.create(SendOpcode.LEFT_KNOCK_BACK);
    }

    public static Packet sendAutoHpPot(int itemId) {
        final OutPacket p = OutPacket.create(SendOpcode.AUTO_HP_POT);
        p.writeInt(itemId);
        return p;
    }

    public static Packet sendAutoMpPot(int itemId) {
        OutPacket p = OutPacket.create(SendOpcode.AUTO_MP_POT);
        p.writeInt(itemId);
        return p;
    }

    public static Packet sendVegaScroll(int op) {
        OutPacket p = OutPacket.create(SendOpcode.VEGA_SCROLL);
        p.writeByte(op);
        return p;
    }

    public static Packet getShowExpGain(int gain, int equip, int party, boolean inChat, boolean white) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        p.writeByte(3); // 3 = exp, 4 = fame, 5 = mesos, 6 = guildpoints
        p.writeBool(white);
        p.writeInt(gain);
        p.writeBool(inChat);
        p.writeInt(0); // bonus event exp
        p.writeByte(0); // third monster kill event
        p.writeByte(0); // RIP byte, this is always a 0
        p.writeInt(0); //wedding bonus
        if (inChat) { // quest bonus rate stuff
            p.writeByte(0);
        }

        p.writeByte(0); //0 = party bonus, 100 = 1x Bonus EXP, 200 = 2x Bonus EXP
        p.writeInt(party); // party bonus
        p.writeInt(equip); //equip bonus
        p.writeInt(0); //Internet Cafe Bonus
        p.writeInt(0); //Rainbow Week Bonus
        return p;
    }

    public static Packet giveFameResponse(int mode, String charname, int newfame) {
        final OutPacket p = OutPacket.create(SendOpcode.FAME_RESPONSE);
        p.writeByte(0);
        p.writeString(charname);
        p.writeByte(mode);
        p.writeShort(newfame);
        p.writeShort(0);
        return p;
    }

    public static Packet receiveFame(int mode, String charnameFrom) {
        final OutPacket p = OutPacket.create(SendOpcode.FAME_RESPONSE);
        p.writeByte(5);
        p.writeString(charnameFrom);
        p.writeByte(mode);
        return p;
    }

    public static Packet getShowFameGain(int gain) {
        final OutPacket p = OutPacket.create(SendOpcode.SHOW_STATUS_INFO);
        p.writeByte(4);
        p.writeInt(gain);
        return p;
    }

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

    public static Packet showOXQuiz(int questionSet, int questionId, boolean askQuestion) {
        OutPacket p = OutPacket.create(SendOpcode.OX_QUIZ);
        p.writeByte(askQuestion ? 1 : 0);
        p.writeByte(questionSet);
        p.writeShort(questionId);
        return p;
    }
}
