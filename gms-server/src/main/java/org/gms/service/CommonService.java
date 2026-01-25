package org.gms.service;


import com.mybatisflex.core.paginate.Page;
import com.mybatisflex.core.query.QueryWrapper;
import lombok.extern.slf4j.Slf4j;
import org.gms.client.Job;
import org.gms.client.SkinColor;
import org.gms.client.inventory.Equip;
import org.gms.constants.api.InformationType;
import org.gms.constants.inventory.EquipType;
import org.gms.dao.entity.GuildsDO;
import org.gms.dao.mapper.GuildsMapper;
import org.gms.exception.BizException;
import org.gms.model.dto.*;
import org.gms.model.pojo.InformationSearch;
import org.gms.model.pojo.InformationResult;
import org.gms.net.server.Server;
import org.gms.server.CommonInformation;
import org.gms.server.ItemInformationProvider;
import org.gms.util.I18nUtil;
import org.gms.util.Pair;
import org.gms.util.RequireUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@Slf4j
public class CommonService {

    @Autowired
    private ItemService itemService;
    @Autowired
    private GuildsMapper guildsMapper;

    /**
     * 根据物品ID获取装备信息
     *
     * @param submitData 主要是装备的ID 物品的ID
     * @return EquipmentInfoRtnDTO
     */
    public EquipmentInfoRtnDTO getEquipmentInfoByItemId(EquipmentInfoReqDTO submitData) {
        if (submitData.getId() == null) {
            throw new BizException(I18nUtil.getExceptionMessage("PARAMETER_SHOULD_NOT_NULL"));
        }
        Equip equip = itemService.getEquipmentInfoByItemId(submitData.getId());
        Pair<String, String> nameDesc = itemService.getNameDesc(submitData.getId());
        EquipmentInfoRtnDTO rtn = new EquipmentInfoRtnDTO();
        rtn.setName(nameDesc.getLeft());
        rtn.setDesc(nameDesc.getRight());
        rtn.setStr(equip.getStr());
        rtn.setDex(equip.getDex());
        rtn.set_int(equip.getInt());
        rtn.setLuk(equip.getLuk());
        rtn.setHp(equip.getHp());
        rtn.setMp(equip.getMp());
        rtn.setPAtk(equip.getWatk());
        rtn.setMAtk(equip.getMatk());
        rtn.setPDef(equip.getWdef());
        rtn.setMDef(equip.getMdef());
        rtn.setAcc(equip.getAcc());
        rtn.setAvoid(equip.getAvoid());
        rtn.setHands(equip.getHands());
        rtn.setSpeed(equip.getSpeed());
        rtn.setJump(equip.getJump());
        rtn.setUpgradeSlot(equip.getUpgradeSlots());
        rtn.setExpire(equip.getExpiration());
        
        // 补充穿戴要求
        Map<String, Integer> equipStats = ItemInformationProvider.getInstance().getEquipStats(submitData.getId());
        if (equipStats != null) {
            rtn.setReqLevel(equipStats.get("reqLevel"));
            rtn.setReqJob(equipStats.get("reqJob"));
            rtn.setReqStr(equipStats.get("reqSTR"));
            rtn.setReqDex(equipStats.get("reqDEX"));
            rtn.setReqInt(equipStats.get("reqINT"));
            rtn.setReqLuk(equipStats.get("reqLUK"));
            rtn.setReqPop(equipStats.get("reqPOP"));
        }

        return rtn;
    }

    /**
     * 根据物品ID获取道具信息
     *
     * @param submitData 主要是物品的ID
     * @return ItemInfoRtnDTO
     */
    public ItemInfoRtnDTO getItemInfoByItemId(ItemInfoReqDTO submitData) {
        if (submitData.getId() == null) {
            throw new BizException(I18nUtil.getExceptionMessage("PARAMETER_SHOULD_NOT_NULL"));
        }
        Pair<String, String> nameDesc = itemService.getItemInfoByItemId(submitData.getId());
        ItemInfoRtnDTO rtn = new ItemInfoRtnDTO();
        rtn.setName(nameDesc.getLeft());
        rtn.setDesc(nameDesc.getRight());
        return rtn;
    }

    /**
     * 根据世界ID去获取当前世界在线玩家数量
     *
     * @param worldId 大区id
     * @return Integer 在线玩家数量
     */
    public Integer getOnlinePlayerCountByWorldId(Integer worldId) {
        if (worldId == null) {
            return 0;
        }
        //如果传参未序列化可能导致数据丢失Optional做兜底
        return Server.getInstance().getWorld(worldId).getPlayerStorage().getSize();
    }

    /**
     * 查询所有世界的在线玩家并加总
     * @param worldIdList 大区id
     * @return 在线玩家总数
     */
    public Integer getAllWorldsOnlinePlayersCount(List<Integer> worldIdList) {
        //使用Optional判断worldIdList,如果size为0,则给new一个,相当于就是给worldId赋值0
        if (worldIdList == null) worldIdList = new ArrayList<>();

        //直接创建好对应世界个数的集合大小,虽然扩容机制估计用不到,但万一呢
        return worldIdList.stream().map(this::getOnlinePlayerCountByWorldId).mapToInt(i -> i).sum();

    }

    public Page<InformationResult> getInformation(InformationSearch condition) {
        // RequireUtil.requireNotEmpty(condition.getFilter(), I18nUtil.getExceptionMessage("PARAMETER_SHOULD_NOT_EMPTY", "filter"));
        if (RequireUtil.isEmpty(condition.getTypes())) {
            condition.setTypes(Stream.of(InformationType.values()).map(InformationType::getType).collect(Collectors.toList()));
        }
        return CommonInformation.getInstance().getStringInformation(condition);
    }

    public List<InformationResult> getAllMaps() {
        return CommonInformation.getInstance().getAllMaps();
    }

    public List<String> getStreetNames() {
        return CommonInformation.getInstance().getStreetNames();
    }

    public List<InformationResult> getMapsByStreetName(String streetName) {
        return CommonInformation.getInstance().getMapsByStreetName(streetName);
    }
    
    public List<String> getEquipCategories() {
        return CommonInformation.getInstance().getEquipCategories();
    }

    public Map<String, List<String>> getEquipSubCategories() {
        Map<String, List<String>> subCategories = new HashMap<>();
        
        // Weapon 子分类
        List<String> weaponSubs = Arrays.stream(EquipType.values())
                .filter(type -> {
                    int val = type.getValue();
                    // 武器ID通常在 130xxxx - 149xxxx 之间
                    // EquipType 的 value 是 ID 前缀 (如 1302, 1402)
                    // 或者 130, 140 等
                    return val >= 1300 && val < 1500;
                })
                .map(Enum::name)
                .collect(Collectors.toList());
        subCategories.put("Weapon", weaponSubs);

        // Accessory 子分类
        List<String> accessorySubs = Arrays.stream(EquipType.values())
                .filter(type -> {
                    int val = type.getValue();
                    // 饰品ID通常在 101xxxx - 115xxxx 之间
                    // 排除掉 CAPE(110), RING(111) 等已经是一级分类的
                    // 虽然 RING(111) 在 EquipType 中定义了，但如果它是一级分类，这里可以保留也可以排除
                    // 根据用户反馈，CAPE, COAT, GLOVES, LONGCOAT, PANTS, RING, SHIELD, SHOES 是一级分类
                    // 它们的 ID 分别是:
                    // CAPE: 110
                    // COAT: 104
                    // GLOVES: 108
                    // LONGCOAT: 105
                    // PANTS: 106
                    // RING: 111
                    // SHIELD: 109
                    // SHOES: 107
                    // 所以我们需要排除这些 ID
                    // 修正：用户要求 RING 也归类到饰品里
                    return (val >= EquipType.FACE_ACCESSORY.getValue() && val <= EquipType.EARRINGS.getValue()) || // Face, Eye, Earrings
                           val == EquipType.RING.getValue() || // Ring
                           val == EquipType.PENDANT.getValue() || // Pendant
                           val == EquipType.BELT.getValue() || // Belt
                           val == EquipType.MEDAL.getValue() || // Medal
                           val == EquipType.SHOULDER.getValue();   // Shoulder
                })
                .map(Enum::name)
                .collect(Collectors.toList());
        subCategories.put("Accessory", accessorySubs);

        // PetEquip 子分类
        List<String> petEquipSubs = Arrays.stream(EquipType.values())
                .filter(type -> {
                    int val = type.getValue();
                    // 宠物装备ID通常在 180xxxx - 183xxxx 之间
                    return val >= EquipType.PET_EQUIP.getValue() && val <= EquipType.PET_EQUIP_QUOTE.getValue();
                })
                .map(Enum::name)
                .collect(Collectors.toList());
        subCategories.put("PetEquip", petEquipSubs);
        
        return subCategories;
    }

    public List<InformationResult> getJobs() {
        return Arrays.stream(Job.values())
                .map(job -> InformationResult.builder()
                        .id(job.getId())
                        .name(job.getName())
                        .desc(String.valueOf(job.getId()))
                        .type("JOB")
                        .build())
                .collect(Collectors.toList());
    }

    public List<InformationResult> getSkinColors() {
        return Arrays.stream(SkinColor.values())
                .map(skin -> InformationResult.builder()
                        .id(skin.getId())
                        .name(skin.name())
                        .desc(String.valueOf(skin.getId()))
                        .type("SKIN")
                        .build())
                .collect(Collectors.toList());
    }

    public List<InformationResult> getGuilds() {
        List<GuildsDO> guilds = guildsMapper.selectListByQuery(QueryWrapper.create());
        return guilds.stream()
                .map(guild -> InformationResult.builder()
                        .id(guild.getGuildid().intValue())
                        .name(guild.getName())
                        .desc(String.valueOf(guild.getGuildid()))
                        .type("GUILD")
                        .build())
                .collect(Collectors.toList());
    }

}
