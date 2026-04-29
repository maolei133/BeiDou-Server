/*
	This file is part of the OdinMS Maple Story Server
    Copyright (C) 2008 Patrick Huy <patrick.huy@frz.cc>
		       Matthias Butz <matze@odinms.de>
		       Jan Christian Meyer <vimes@odinms.de>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation version 3 as published by
    the Free Software Foundation. You may not use, modify or distribute
    this program under any other version of the GNU Affero General Public
    License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package org.gms.constants.inventory;

import org.gms.client.inventory.InventoryType;
import org.gms.config.GameConfig;
import org.gms.constants.id.ItemId;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * 物品常量及工具类
 * 提供物品类型判断、属性检查等静态方法。
 * 
 * @author Jay Estrella
 * @author Ronan
 */
public final class ItemConstants {
    protected static Map<Integer, InventoryType> inventoryTypeCache = new HashMap<>();

    // --- 物品标志位 (Item Flags) ---
    /** 锁定 */
    public final static short LOCK = 0x01;
    /** 防滑 (鞋子) */
    public final static short SPIKES = 0x02;
    /** 宿命剪刀 (消耗) */
    public final static short KARMA_USE = 0x02;
    /** 防寒 (鞋子) */
    public final static short COLD = 0x04;
    /** 不可交易 */
    public final static short UNTRADEABLE = 0x08;
    /** 宿命剪刀 (装备) */
    public final static short KARMA_EQP = 0x10;
    /** 沙盒模式 (保留) */
    public final static short SANDBOX = 0x40;             // let 0x40 until it's proven something uses this
    /** 宠物召唤 */
    public final static short PET_COME = 0x80;
    /** 账号共享 */
    public final static short ACCOUNT_SHARING = 0x100;
    /** 合并不可交易 */
    public final static short MERGE_UNTRADEABLE = 0x200;

    // --- 物品ID前缀常量 (Item ID Prefixes) ---
    // 装备 (1xxxxxx)
    /** 装备栏前缀 */
    private static final int PREFIX_EQUIP = 1;
    /** 武器起始前缀 */
    private static final int PREFIX_WEAPON_START = 130;
    /** 武器结束前缀 */
    private static final int PREFIX_WEAPON_END = 149;
    /** 宠物装备前缀 */
    private static final int PREFIX_PET_EQUIP = 18;
    /** 可升级宠物装备前缀 */
    private static final int PREFIX_UPGRADABLE_PET_EQUIP = 180;
    /** 骑宠前缀 */
    private static final int PREFIX_TAMING_MOB = 190;
    /** 鞍具前缀 */
    private static final int PREFIX_SADDLE = 191;
    /** 饰品起始前缀 */
    private static final int PREFIX_ACCESSORY_START = 111;
    /** 饰品结束前缀 */
    private static final int PREFIX_ACCESSORY_END = 113;
    /** 套服前缀 */
    private static final int PREFIX_OVERALL = 105;
    /** 脸型前缀1 */
    private static final int PREFIX_FACE_1 = 2;
    /** 脸型前缀2 */
    private static final int PREFIX_FACE_2 = 5;
    /** 发型前缀1 */
    private static final int PREFIX_HAIR_1 = 3;
    /** 发型前缀2 */
    private static final int PREFIX_HAIR_2 = 4;
    /** 发型前缀3 */
    private static final int PREFIX_HAIR_3 = 6;
    /** 勋章前缀 */
    private static final int PREFIX_MEDAL = 114;

    // 消耗 (2xxxxxx)
    /** 消耗栏前缀 */
    private static final int PREFIX_CONSUME = 2;
    /** 药水前缀 */
    private static final int PREFIX_POTION = 200;
    /** 食物前缀1 */
    private static final int PREFIX_FOOD_1 = 201;
    /** 食物前缀2 */
    private static final int PREFIX_FOOD_2 = 202;
    /** 回城卷轴前缀 */
    private static final int PREFIX_TOWN_SCROLL = 203;
    /** 卷轴前缀 */
    private static final int PREFIX_SCROLL = 204;
    /** 弓箭前缀 */
    private static final int PREFIX_ARROW_BOW = 2060;
    /** 弩矢前缀 */
    private static final int PREFIX_ARROW_CROSSBOW = 2061;
    /** 飞镖前缀 */
    private static final int PREFIX_THROWING_STAR = 207;
    /** 子弹前缀 */
    private static final int PREFIX_BULLET = 233;
    /** 新年贺卡(消耗)前缀 */
    private static final int PREFIX_NEW_YEAR_CARD_USE = 216;
    /** 组队道具前缀1 */
    private static final int PREFIX_PARTY_ITEM_1 = 202243;
    /** 组队道具前缀2 */
    private static final int PREFIX_PARTY_ITEM_2 = 202216;

    // 设置 (3xxxxxx)
    /** 设置栏前缀 */
    private static final int PREFIX_SETUP = 3;
    /** 椅子前缀 */
    private static final int PREFIX_CHAIR = 301;

    // 其他 (4xxxxxx)
    /** 其他栏前缀 */
    private static final int PREFIX_ETC = 4;
    /** 制作材料前缀 */
    private static final int PREFIX_MAKER = 425;
    /** 新年贺卡(其他)前缀 */
    private static final int PREFIX_NEW_YEAR_CARD_ETC = 430;

    // 现金 (5xxxxxx)
    /** 现金栏前缀 */
    private static final int PREFIX_CASH = 5;
    /** 宠物前缀 */
    private static final int PREFIX_PET = 500;
    /** 雇佣商人前缀 */
    private static final int PREFIX_HIRED_MERCHANT = 503;
    /** 个人商店前缀 */
    private static final int PREFIX_PLAYER_SHOP = 514;
    /** 枫叶生命前缀 */
    private static final int PREFIX_MAPLE_LIFE = 543;
    /** 倍率卡前缀1 */
    private static final int PREFIX_RATE_COUPON_1 = 5211;
    /** 倍率卡前缀2 */
    private static final int PREFIX_RATE_COUPON_2 = 5360;

    /** 永久物品ID集合 */
    public final static Set<Integer> permanentItemids = new HashSet<>();

    static {
        // i ain't going to open one gigantic itemid cache just for 4 perma itemids, no way!
        for (int petItemId : ItemId.getPermaPets()) {
            permanentItemids.add(petItemId);
        }
    }

    /**
     * 根据整数类型获取标志位
     * @param type 类型值
     * @return 标志位
     */
    public static int getFlagByInt(int type) {
        if (type == 128) {
            return PET_COME;
        } else if (type == 256) {
            return ACCOUNT_SHARING;
        }
        return 0;
    }
    
    /**
     * 判断物品是否不可交易
     * @param flag 物品标志位
     * @return true 如果不可交易
     */
    public static boolean isUntradeable(int flag) {
        return (flag & UNTRADEABLE) == UNTRADEABLE;
    }

    // --- 消耗品判断 ---

    /**
     * 判断是否为飞镖
     * @param itemId 物品ID
     * @return true 如果是飞镖
     */
    public static boolean isThrowingStar(int itemId) {
        return itemId / 10000 == PREFIX_THROWING_STAR;
    }

    /**
     * 判断是否为子弹
     * @param itemId 物品ID
     * @return true 如果是子弹
     */
    public static boolean isBullet(int itemId) {
        return itemId / 10000 == PREFIX_BULLET;
    }

    /**
     * 判断是否为药水
     * @param itemId 物品ID
     * @return true 如果是药水
     */
    public static boolean isPotion(int itemId) {
        return itemId / 10000 == PREFIX_POTION;
    }

    /**
     * 判断是否为食物
     * @param itemId 物品ID
     * @return true 如果是食物
     */
    public static boolean isFood(int itemId) {
        int useType = itemId / 1000;
        return useType == 2022 || useType == 2010 || useType == 2020;
    }

    /**
     * 判断是否为消耗品 (药水或食物)
     * @param itemId 物品ID
     * @return true 如果是消耗品
     */
    public static boolean isConsumable(int itemId) {
        return isPotion(itemId) || isFood(itemId);
    }

    /**
     * 判断是否为可充值道具 (飞镖或子弹)
     * @param itemId 物品ID
     * @return true 如果是可充值道具
     */
    public static boolean isRechargeable(int itemId) {
        return isThrowingStar(itemId) || isBullet(itemId);
    }

    /**
     * 判断是否为弩矢
     * @param itemId 物品ID
     * @return true 如果是弩矢
     */
    public static boolean isArrowForCrossBow(int itemId) {
        return itemId / 1000 == PREFIX_ARROW_CROSSBOW;
    }

    /**
     * 判断是否为弓箭
     * @param itemId 物品ID
     * @return true 如果是弓箭
     */
    public static boolean isArrowForBow(int itemId) {
        return itemId / 1000 == PREFIX_ARROW_BOW;
    }

    /**
     * 判断是否为箭矢 (弓箭或弩矢)
     * @param itemId 物品ID
     * @return true 如果是箭矢
     */
    public static boolean isArrow(int itemId) {
        return isArrowForBow(itemId) || isArrowForCrossBow(itemId);
    }

    /**
     * 判断是否为回城卷轴
     * @param itemId 物品ID
     * @return true 如果是回城卷轴
     */
    public static boolean isTownScroll(int itemId) {
        return itemId >= 2030000 && itemId < ItemId.ANTI_BANISH_SCROLL;
    }

    /**
     * 判断是否为防驱逐卷轴
     * @param itemId 物品ID
     * @return true 如果是防驱逐卷轴
     */
    public static boolean isAntibanishScroll(int itemId) {
        return itemId == ItemId.ANTI_BANISH_SCROLL;
    }

    /**
     * 判断是否为白衣卷轴 (Clean Slate Scroll)
     * @param scrollId 卷轴ID
     * @return true 如果是白衣卷轴
     */
    public static boolean isCleanSlate(int scrollId) {
        return scrollId > 2048999 && scrollId < 2049004;
    }

    /**
     * 判断是否为特殊修饰卷轴 (如冰冷保护、刺击)
     * @param scrollId 卷轴ID
     * @return true 如果是修饰卷轴
     */
    public static boolean isModifierScroll(int scrollId) {
        return scrollId == ItemId.SPIKES_SCROLL || scrollId == ItemId.COLD_PROTECTION_SCROLl;
    }

    /**
     * 判断是否为标志位修饰符
     * @param scrollId 卷轴ID
     * @param flag 物品标志位
     * @return true 如果匹配
     */
    public static boolean isFlagModifier(int scrollId, short flag) {
        if (scrollId == ItemId.COLD_PROTECTION_SCROLl && ((flag & ItemConstants.COLD) == ItemConstants.COLD)) {
            return true;
        }
        return scrollId == ItemId.SPIKES_SCROLL && ((flag & ItemConstants.SPIKES) == ItemConstants.SPIKES);
    }

    /**
     * 判断是否为混沌卷轴
     * @param scrollId 卷轴ID
     * @return true 如果是混沌卷轴
     */
    public static boolean isChaosScroll(int scrollId) {
        return scrollId >= 2049100 && scrollId <= 2049103;
    }

    /**
     * 判断是否为倍率卡
     * @param itemId 物品ID
     * @return true 如果是倍率卡
     */
    public static boolean isRateCoupon(int itemId) {
        int itemType = itemId / 1000;
        return itemType == PREFIX_RATE_COUPON_1 || itemType == PREFIX_RATE_COUPON_2;
    }

    /**
     * 判断是否为经验卡
     * @param couponId 物品ID
     * @return true 如果是经验卡
     */
    public static boolean isExpCoupon(int couponId) {
        return couponId / 1000 == PREFIX_RATE_COUPON_1;
    }

    /**
     * 判断是否为组队道具
     * @param itemId 物品ID
     * @return true 如果是组队道具
     */
    public static boolean isPartyItem(int itemId) {
        int prefix = itemId / 10;
        return prefix == PREFIX_PARTY_ITEM_1 || prefix == PREFIX_PARTY_ITEM_2;
    }

    /**
     * 判断是否为新年贺卡 (消耗栏)
     * @param itemId 物品ID
     * @return true 如果是新年贺卡
     */
    public static boolean isNewYearCardUse(int itemId) {
        return itemId / 10000 == PREFIX_NEW_YEAR_CARD_USE;
    }

    // --- 宠物及相关 ---

    /**
     * 判断是否为宠物
     * @param itemId 物品ID
     * @return true 如果是宠物
     */
    public static boolean isPet(int itemId) {
        return itemId / 10000 == PREFIX_PET;
    }

    /**
     * 判断是否为宠物装备
     * @param itemId 物品ID
     * @return true 如果是宠物装备
     */
    public static boolean isPetEquip(int itemId) {
        return itemId / 100000 == PREFIX_PET_EQUIP;
    }

    /**
     * 判断是否为可升级的宠物装备
     * @param itemId 物品ID
     * @return true 如果是可升级的宠物装备
     */
    public static boolean isUpgradablePetEquip(int itemId) {
        return itemId / 10000 == PREFIX_UPGRADABLE_PET_EQUIP;
    }

    /**
     * 判断宠物是否可过期
     * @param itemId 物品ID
     * @return true 如果可过期
     */
    public static boolean isExpirablePet(int itemId) {
        return GameConfig.getServerBoolean("use_erase_pet_on_expiration") || itemId == ItemId.PET_SNAIL;
    }

    /**
     * 判断是否为永久物品
     * @param itemId 物品ID
     * @return true 如果是永久物品
     */
    public static boolean isPermanentItem(int itemId) {
        return permanentItemids.contains(itemId);
    }

    // --- 装备判断 ---

    /**
     * 判断是否为装备
     * @param itemId 物品ID
     * @return true 如果是装备
     */
    public static boolean isEquipment(int itemId) {
        return itemId < 2000000 && itemId != 0;
    }

    /**
     * 判断是否为武器
     * @param itemId 物品ID
     * @return true 如果是武器
     */
    public static boolean isWeapon(int itemId) {
        int cat = itemId / 10000;
        return cat >= PREFIX_WEAPON_START && cat < PREFIX_WEAPON_END;
    }

    /**
     * 判断是否为饰品
     * @param itemId 物品ID
     * @return true 如果是饰品
     */
    public static boolean isAccessory(int itemId) {
        int cat = itemId / 10000;
        return cat >= PREFIX_ACCESSORY_START && cat < PREFIX_ACCESSORY_END;
    }

    /**
     * 判断是否为坐骑
     * @param itemId 物品ID
     * @return true 如果是坐骑
     */
    public static boolean isTaming(int itemId) {
        int itemType = itemId / 10000;
        return itemType == PREFIX_TAMING_MOB || itemType == PREFIX_SADDLE;
    }

    /**
     * 判断是否为套服
     * @param itemId 物品ID
     * @return true 如果是套服
     */
    public static boolean isOverall(int itemId) {
        return itemId / 10000 == PREFIX_OVERALL;
    }

    /**
     * 判断是否为勋章
     * @param itemId 物品ID
     * @return true 如果是勋章
     */
    public static boolean isMedal(int itemId) {
        return itemId / 10000 == PREFIX_MEDAL;
    }

    /**
     * 判断是否为脸型
     * @param itemId 物品ID
     * @return true 如果是脸型
     */
    public static boolean isFace(int itemId) {
        int itemType = itemId / 10000;
        return itemType == PREFIX_FACE_1 || itemType == PREFIX_FACE_2;
    }

    /**
     * 判断是否为发型
     * @param itemId 物品ID
     * @return true 如果是发型
     */
    public static boolean isHair(int itemId) {
        int itemType = itemId / 10000;
        return itemType == PREFIX_HAIR_1 || itemType == PREFIX_HAIR_2 || itemType == PREFIX_HAIR_3;
    }

    /**
     * 判断是否为戒指
     * @param itemId 物品ID
     * @return true 如果是戒指
     */
    public static boolean isRing(int itemId) {
        return itemId >= 1110000 && itemId < 1120000;
    }

    // --- 商店与特殊道具 ---

    /**
     * 判断是否为雇佣商人
     * @param itemId 物品ID
     * @return true 如果是雇佣商人
     */
    public static boolean isHiredMerchant(int itemId) {
        return itemId / 10000 == PREFIX_HIRED_MERCHANT;
    }

    /**
     * 判断是否为个人商店
     * @param itemId 物品ID
     * @return true 如果是个人商店
     */
    public static boolean isPlayerShop(int itemId) {
        return itemId / 10000 == PREFIX_PLAYER_SHOP;
    }

    /**
     * 判断是否为现金商店开店道具 (雇佣商人或个人商店)
     * @param itemId 物品ID
     * @return true 如果是开店道具
     */
    public static boolean isCashStore(int itemId) {
        int itemType = itemId / 10000;
        return itemType == PREFIX_HIRED_MERCHANT || itemType == PREFIX_PLAYER_SHOP;
    }

    /**
     * 判断是否为 Maple Life 道具
     * @param itemId 物品ID
     * @return true 如果是 Maple Life 道具
     */
    public static boolean isMapleLife(int itemId) {
        int itemType = itemId / 10000;
        return itemType == PREFIX_MAPLE_LIFE && itemId != 5430000;
    }

    /**
     * 判断是否为钓鱼椅子
     * @param itemId 物品ID
     * @return true 如果是钓鱼椅子
     */
    public static boolean isFishingChair(int itemId) {
        return itemId == ItemId.FISHING_CHAIR;
    }

    /**
     * 判断是否为情侣或友情戒指
     * @param itemId 物品ID
     * @return true 如果是
     */
    public static boolean isFriendshipOrCoupleRing(int itemId) {
        // 情侣戒指通常在 1112000-1112999, 友情戒指在 1112800-1112899
        // 这里使用一个更宽泛但安全的范围
        return itemId >= 1112000 && itemId < 1113000;
    }

    /**
     * 判断是否为增加角色栏位券
     * @param itemId 物品ID
     * @return true 如果是
     */
    public static boolean isCharacterSlotCoupon(int itemId) {
        // 通常这类物品ID是固定的，例如 5430000
        return itemId == 5430000;
    }

    /**
     * 判断是否为增加仓库/背包栏位券
     * @param itemId 物品ID
     * @return true 如果是
     */
    public static boolean isStorageSlotCoupon(int itemId) {
        // 例如: 5021000 (4格), 5021001 (8格)
        return itemId / 1000 == 5021;
    }

    /**
     * 判断是否为改名卡
     * @param itemId 物品ID
     * @return true 如果是改名卡
     */
    public static boolean isNameChangeCoupon(int itemId) {
        return itemId == 50600000;
    }

    /**
     * 判断是否为转服券
      * @param itemId 物品ID
      * @return true 如果是转服券
     */
    public static boolean isWorldTransferCoupon(int itemId) {
        return itemId == 50600001;
    }

    // --- 其他 ---

    /**
     * 获取物品的库存类型
     * @param itemId 物品ID
     * @return 库存类型
     */
    public static InventoryType getInventoryType(final int itemId) {
        if (inventoryTypeCache.containsKey(itemId)) {
            return inventoryTypeCache.get(itemId);
        }

        InventoryType ret = InventoryType.UNDEFINED;

        final byte type = (byte) (itemId / 1000000);
        if (type >= PREFIX_EQUIP && type <= PREFIX_CASH) {
            ret = InventoryType.getByType(type);
        }

        inventoryTypeCache.put(itemId, ret);
        return ret;
    }

    /**
     * 判断是否为制作材料 (Maker Reagent)
     * @param itemId 物品ID
     * @return true 如果是制作材料
     */
    public static boolean isMakerReagent(int itemId) {
        return itemId / 10000 == PREFIX_MAKER;
    }

    /**
     * 判断是否为新年贺卡 (其他栏)
     * @param itemId 物品ID
     * @return true 如果是新年贺卡
     */
    public static boolean isNewYearCardEtc(int itemId) {
        return itemId / 10000 == PREFIX_NEW_YEAR_CARD_ETC;
    }

    // --- 角色创建默认外观判断 ---

    public static boolean isNewCharDefaultFace(int job, int gender, int faceId) {
        if (job == 0 || job == 1) {
            return switch (gender) {
                case 0 -> faceId == 20000 || faceId == 20001 || faceId == 20002;
                case 1 -> faceId == 21000 || faceId == 21001 || faceId == 21002;
                default -> false;
            };
        } else if (job == 2) {
            return switch (gender) {
                case 0 -> faceId == 20100 || faceId == 20401 || faceId == 20402;
                case 1 -> faceId == 21700 || faceId == 21201 || faceId == 21002;
                default -> false;
            };
        } else {
            return false;
        }
    }

    public static boolean isNewCharDefaultHair(int gender, int hairId) {
        return switch (gender) {
            case 0 -> hairId == 30000 || hairId == 30020 || hairId == 30030;
            case 1 -> hairId == 31000 || hairId == 31040 || hairId == 31050;
            default -> false;
        };
    }

    public static boolean isNewCharDefaultHairColor(int hairColor) {
        return hairColor == 0 || hairColor == 2 || hairColor == 3 || hairColor == 7;
    }

    public static boolean isNewCharDefaultSkinColor(int skinColor) {
        return skinColor >= 0 && skinColor < 4;
    }

    public static boolean isNewCharDefaultTop(int job, int gender, int topId) {
        if (job == 0 || job == 1) {
            return switch (gender) {
                case 0 -> topId == 1040002 || topId == 1040006 || topId == 1040010;
                case 1 -> topId == 1041002 || topId == 1041006 || topId == 1041010 || topId == 1041011;
                default -> false;
            };
        } else if (job == 2) {
            return topId == 1042167;
        } else {
            return false;
        }
    }

    public static boolean isNewCharDefaultBottom(int job, int gender, int bottomId) {
        if (job == 0 || job == 1) {
            return switch (gender) {
                case 0 -> bottomId == 1060002 || bottomId == 1060006;
                case 1 -> bottomId == 1061002 || bottomId == 1061008;
                default -> false;
            };
        } else if (job == 2) {
            return bottomId == 1062115;
        } else {
            return false;
        }
    }

    public static boolean isNewCharDefaultShoes(int job, int shoesId) {
        if (job == 0 || job == 1) {
            return shoesId == 1072001 || shoesId == 1072005 || shoesId == 1072037 || shoesId == 1072038;
        } else if (job == 2) {
            return shoesId == 1072383;
        } else {
            return false;
        }
    }

    public static boolean isNewCharDefaultWeapon(int job, int weaponId) {
        if (job == 0 || job == 1) {
            return weaponId == 1302000 || weaponId == 1322005 || weaponId == 1312004;
        } else if (job == 2) {
            return weaponId == 1442079;
        } else {
            return false;
        }
    }

    public static boolean notValidHairColor(int hairColor) {
        return hairColor > 7 || hairColor < 0;
    }
}
