package org.gms.service;

import lombok.extern.slf4j.Slf4j;
import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.Stat;
import org.gms.client.inventory.*;
import org.gms.client.inventory.manipulator.InventoryManipulator;
import org.gms.constants.inventory.ItemConstants;
import org.gms.constants.string.ExtendType;
import org.gms.dao.entity.CharactersDO;
import org.gms.dao.entity.ExtendValueDO;

import org.gms.dao.mapper.CharactersMapper;
import org.gms.model.dto.GiveResourceReqDTO;
import org.gms.exception.BizException;


import org.gms.net.server.Server;
import org.gms.server.CashShop;
import org.gms.server.ItemInformationProvider;
import org.gms.server.maps.MapleMap;
import org.gms.util.I18nUtil;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;


import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.MINUTES;


@Service
@Slf4j
public class GiveService {
    @Autowired
    CharacterService characterService;
    @Autowired
    CharactersMapper charactersMapper;

    public void give(GiveResourceReqDTO submitData) {
        if (submitData.getPlayerId() == 0) {
            giveAllOnlineChr(submitData);
        } else {
            giveChr(submitData);
        }
    }

    private void giveAllOnlineChr(GiveResourceReqDTO submitData) {
        switch (submitData.getType()) {
            case 0: // nxCredit 点券
            case 1: // nxPrepaid 信用点
            case 2: // maplePoint 抵用券
                int cashType = switch (submitData.getType()) {
                    case 1 -> CashShop.NX_PREPAID;
                    case 2 -> CashShop.MAPLE_POINT;
                    default -> CashShop.NX_CREDIT;
                };
                giveNxAllOnlineChr(submitData.getQuantity(), cashType);
                break;
            case 3: // mesos
                giveMesosAllOnlineChr(submitData.getQuantity());
                break;
            case 4: // exp
                giveExpAllOnlineChr(submitData.getQuantity());
                break;
            case 5: // item
                giveItemAllOnlineChr(submitData);
                break;
            case 6: // equip
                giveEquipAllOnlineChr(submitData);
                break;
            case 13: // change map
                changeMapAllOnlineChr(submitData.getQuantity());
                break;
        }
    }

    private void giveChr(GiveResourceReqDTO submitData) {
        Integer wId = submitData.getWorldId();
        Integer cId = submitData.getPlayerId();
        if (wId == null || wId < 0 || cId == null || cId < 1) {
            throw new BizException(I18nUtil.getExceptionMessage("CHR_OR_WORLD_ID_ERROR"));
        }
        
        // 尝试获取在线玩家
        Character chr = null;
        try {
            chr = Server.getInstance()
                    .getWorlds().get(wId)
                    .getPlayerStorage().getCharacterById(cId);
        } catch (Exception e) {
            // ignore
        }

        // 如果在线，使用在线逻辑
        if (chr != null) {
            switch (submitData.getType()) {
                case 0: // nxCredit 点券
                case 1: // nxPrepaid 信用点
                case 2: // maplePoint 抵用券
                    int cashType = switch (submitData.getType()) {
                        case 1 -> CashShop.NX_PREPAID;
                        case 2 -> CashShop.MAPLE_POINT;
                        default -> CashShop.NX_CREDIT;
                    };
                    giveNxChr(chr, submitData.getQuantity(), cashType);
                    break;
                case 3: // mesos
                    giveMesosChr(chr, submitData.getQuantity());
                    break;
                case 4: // exp
                    giveExpChr(chr, submitData.getQuantity());
                    break;
                case 5: // item
                    giveItemChr(chr, submitData);
                    break;
                case 6: // equip
                    giveEquipChr(chr, submitData);
                    break;
                case 7: // expRate
                case 8: // mesosRate
                case 9: // dropRate
                case 10: // bossRate
                    String rateType = switch (submitData.getType()) {
                        case 7 -> "expRate";
                        case 8 -> "mesoRate";
                        case 9 -> "dropRate";
                        default -> "None";
                    };
                    giveRateChr(chr, rateType, submitData.getRate());
                    break;
                case 11:
                    giveGMChr(chr, submitData.getQuantity());
                    break;
                case 12:
                    giveFameChr(chr, submitData.getQuantity());
                    break;
                case 13:
                    changeMap(chr, submitData.getQuantity(), true);
                    break;
            }
        } else {
            // 如果离线，处理离线逻辑
            // 目前仅支持离线修改地图，其他操作暂不支持或需要额外实现
            if (submitData.getType() == 13) {
                changeMapOffline(cId, submitData.getQuantity());
            } else {
                throw new BizException(I18nUtil.getExceptionMessage("CHR_OFFLINE"));
            }
        }
    }

    private void giveNxAllOnlineChr(int quantity, int type) {
        Server.getInstance().getWorlds().forEach(world -> world.getPlayerStorage().getAllCharacters().forEach(chr -> {
            doGainCash(chr, type, quantity);
            chr.message(I18nUtil.getMessage("Give.Nx.All", quantity, getCashTypeName(type)));
        }));
        log.info(I18nUtil.getLogMessage("Give.Nx.All.info1", quantity, getCashTypeName(type)));
    }

    private void giveNxChr(Character chr, int quantity, int type) {
        doGainCash(chr, type, quantity);
        chr.message(I18nUtil.getMessage("Give.Nx.Chr", quantity, getCashTypeName(type)));
        log.info(I18nUtil.getLogMessage("Give.Nx.Chr.info1", chr.getId(), chr.getName(), quantity, getCashTypeName(type)));
    }

    private String getCashTypeName(int type) {
        return switch (type) {
            case 1 -> I18nUtil.getMessage("Give.Nx.Type.1");
            case 2 -> I18nUtil.getMessage("Give.Nx.Type.2");
            default -> I18nUtil.getMessage("Give.Nx.Type.default");
        };
    }

    private void giveMesosAllOnlineChr(int quantity) {
        Server.getInstance().getWorlds().forEach(world -> world.getPlayerStorage().getAllCharacters().forEach(chr -> {
            doGainMeso(chr, quantity);
            chr.message(I18nUtil.getMessage("Give.Mesos.All", quantity));
        }));
        log.info(I18nUtil.getLogMessage("Give.Mesos.All.info1", quantity));
    }

    private void giveMesosChr(Character chr, int quantity) {
        doGainMeso(chr, quantity);
        chr.message(I18nUtil.getMessage("Give.Mesos.Chr", quantity));
        log.info(I18nUtil.getLogMessage("Give.Mesos.Chr.info1", chr.getId(), chr.getName(), quantity));
    }

    private void giveExpAllOnlineChr(int quantity) {
        Server.getInstance().getWorlds().forEach(world -> world.getPlayerStorage().getAllCharacters().forEach(chr -> {
            doGainExp(chr, quantity);
            chr.message(I18nUtil.getMessage("Give.Exp.All", quantity));
        }));
        log.info(I18nUtil.getLogMessage("Give.Exp.All.info1", quantity));
    }

    private void giveExpChr(Character chr, int quantity) {
        doGainExp(chr, quantity);
        chr.message(I18nUtil.getMessage("Give.Exp.Chr", quantity));
        log.info(I18nUtil.getLogMessage("Give.Exp.Chr.info1", chr.getId(), chr.getName(), quantity));
    }

    private void giveItemAllOnlineChr(GiveResourceReqDTO submitData) {
        int itemId = submitData.getId();
        short quantity = Short.parseShort(submitData.getQuantity() != null ? submitData.getQuantity().toString() : "1");
        String owner = submitData.getOwner();
        short flag = submitData.getFlag() != null ? submitData.getFlag() : 0;
        long expiration = submitData.getExpire() != null ? submitData.getExpire() : -1;

        ItemInformationProvider ii = ItemInformationProvider.getInstance();

        String itemName = ii.getName(itemId);
        if (itemName == null) {
            throw new BizException(I18nUtil.getExceptionMessage("ITEM_NOT_FOUND"));
        }
        if (ItemConstants.getInventoryType(itemId).equals(InventoryType.EQUIP)) {
            throw new BizException(I18nUtil.getExceptionMessage("ONLY_SUPPORT_GIVE_ITEM"));
        }

        boolean isPet = ItemConstants.isPet(itemId);

        long finalExpiration;
        int petId;
        if (isPet) {
            long days = Math.max(1, quantity);
            finalExpiration = System.currentTimeMillis() + DAYS.toMillis(days);
            petId = Pet.createPet(itemId);
        } else {
            if (expiration > 0) {
                finalExpiration = System.currentTimeMillis() + MINUTES.toMillis(expiration);
            } else {
                finalExpiration = expiration;
            }
            petId = 0;
        }

        Server.getInstance().getWorlds().forEach(world -> world.getPlayerStorage().getAllCharacters().forEach(chr -> {
            if (isPet) {
                InventoryManipulator.addById(chr.getClient(), itemId, quantity, owner, petId, flag, finalExpiration);
                chr.message(I18nUtil.getMessage("Give.Pet.All", quantity, itemName));
            } else {
                InventoryManipulator.addById(chr.getClient(), itemId, quantity, owner, -1, flag, finalExpiration);
                chr.message(I18nUtil.getMessage("Give.Item.All", quantity, itemName));
            }
        }));

        String flagDetail = getFlagDetail(flag);
        String expirationDetail = getExpirationDetail(finalExpiration);
        if (isPet) {
            log.info(I18nUtil.getLogMessage("Give.Pet.All.info1", quantity, itemName, String.valueOf(itemId), flagDetail));
        } else {
            log.info(I18nUtil.getLogMessage("Give.Item.All.info1", quantity, itemName, String.valueOf(itemId), flagDetail, expirationDetail));
        }

    }

    private void giveItemChr(Character chr, GiveResourceReqDTO submitData) {
        int itemId = submitData.getId();
        short quantity = Short.parseShort(submitData.getQuantity().toString());
        String owner = submitData.getOwner();
        short flag = submitData.getFlag() != null ? submitData.getFlag() : 0;
        long expiration = submitData.getExpire() != null ? submitData.getExpire() : -1;

        ItemInformationProvider ii = ItemInformationProvider.getInstance();

        String itemName = ii.getName(itemId);
        if (itemName == null) {
            throw new BizException(I18nUtil.getExceptionMessage("ITEM_NOT_FOUND"));
        }
        if (ItemConstants.getInventoryType(itemId).equals(InventoryType.EQUIP)) {
            throw new BizException(I18nUtil.getExceptionMessage("ONLY_SUPPORT_GIVE_ITEM"));
        }

        boolean isPet = ItemConstants.isPet(itemId);

        long finalExpiration;
        int petId = 0;
        if (isPet) {
            long days = Math.max(1, quantity);
            finalExpiration = System.currentTimeMillis() + DAYS.toMillis(days);
            petId = Pet.createPet(itemId);
        } else {
            if (expiration > 0) {
                finalExpiration = System.currentTimeMillis() + MINUTES.toMillis(expiration);
            } else {
                finalExpiration = expiration;
            }
        }

        if (isPet) {
            InventoryManipulator.addById(chr.getClient(), itemId, quantity, owner, petId, flag, finalExpiration);
            chr.message(I18nUtil.getMessage("Give.Pet.Chr", quantity, itemName));
        } else {
            InventoryManipulator.addById(chr.getClient(), itemId, quantity, owner, -1, flag, finalExpiration);
            chr.message(I18nUtil.getMessage("Give.Item.Chr", quantity, itemName));
        }

        String flagDetail = getFlagDetail(flag);
        String expirationDetail = getExpirationDetail(finalExpiration);
        if (isPet) {
            log.info(I18nUtil.getLogMessage("Give.Pet.Chr.info1", chr.getId(), chr.getName(), quantity, itemName, String.valueOf(itemId), flagDetail));
        } else {
            log.info(I18nUtil.getLogMessage("Give.Item.Chr.info1", chr.getId(), chr.getName(), quantity, itemName, String.valueOf(itemId), flagDetail, expirationDetail));
        }
    }

    private void giveEquipAllOnlineChr(GiveResourceReqDTO submitData) {
        ItemInformationProvider ii = ItemInformationProvider.getInstance();

        String itemName = ii.getName(submitData.getId());
        if (ii.getEquipById(submitData.getId()) == null || itemName == null) {
            throw new BizException(I18nUtil.getExceptionMessage("EQUIP_NOT_FOUND"));
        }
        if (!ItemConstants.getInventoryType(submitData.getId()).equals(InventoryType.EQUIP)) {
            throw new BizException(I18nUtil.getExceptionMessage("ONLY_SUPPORT_GIVE_EQUIP"));
        }
        Server.getInstance().getWorlds().forEach(world -> world.getPlayerStorage().getAllCharacters().forEach(chr -> {
            chr.gainEquip(
                    submitData.getId(),
                    submitData.getStr(),
                    submitData.getDex(),
                    submitData.get_int(),
                    submitData.getLuk(),
                    submitData.getHp(),
                    submitData.getMp(),
                    submitData.getPAtk(),
                    submitData.getMAtk(),
                    submitData.getPDef(),
                    submitData.getMDef(),
                    submitData.getAcc(),
                    submitData.getAvoid(),
                    submitData.getHands(),
                    submitData.getSpeed(),
                    submitData.getJump(),
                    submitData.getUpgradeSlot(),
                    submitData.getLevel(),
                    submitData.getItemLevel(),
                    submitData.getExpire(),
                    submitData.getOwner(),
                    submitData.getFlag()
            );
            chr.message(I18nUtil.getMessage("Give.Equip.All", submitData.getId().toString(), itemName));
        }));
        log.info(I18nUtil.getLogMessage("Give.Equip.All.info1",
                itemName,
                String.valueOf(submitData.getId()),
                getFlagDetail(submitData.getFlag()),
                getEquipDetail(submitData)
        ));
    }

    private void giveEquipChr(Character chr, GiveResourceReqDTO submitData) {
        ItemInformationProvider ii = ItemInformationProvider.getInstance();

        String itemName = ii.getName(submitData.getId());
        if (itemName == null) {
            throw new BizException(I18nUtil.getExceptionMessage("EQUIP_NOT_FOUND"));
        }

        if (!ItemConstants.getInventoryType(submitData.getId()).equals(InventoryType.EQUIP)) {
            throw new BizException(I18nUtil.getExceptionMessage("ONLY_SUPPORT_GIVE_EQUIP"));
        }
        chr.gainEquip(
                submitData.getId(),
                submitData.getStr(),
                submitData.getDex(),
                submitData.get_int(),
                submitData.getLuk(),
                submitData.getHp(),
                submitData.getMp(),
                submitData.getPAtk(),
                submitData.getMAtk(),
                submitData.getPDef(),
                submitData.getMDef(),
                submitData.getAcc(),
                submitData.getAvoid(),
                submitData.getHands(),
                submitData.getSpeed(),
                submitData.getJump(),
                submitData.getUpgradeSlot(),
                submitData.getLevel(),
                submitData.getItemLevel(),
                submitData.getExpire(),
                submitData.getOwner(),
                submitData.getFlag()
            );
        chr.message(I18nUtil.getMessage("Give.Equip.Chr", submitData.getId().toString(), itemName));
        log.info(I18nUtil.getLogMessage("Give.Equip.Chr.info1",
                chr.getId(),
                chr.getName(),
                itemName,
                String.valueOf(submitData.getId()),
                getFlagDetail(submitData.getFlag()),
                getEquipDetail(submitData)
        ));
    }

    private void giveRateChr(Character chr, String type, float rate) {
        ExtendValueDO data = ExtendValueDO.builder()
                .extendId(String.valueOf(chr.getId()))
                .extendType(ExtendType.CHARACTER_EXTEND.getType())
                .extendName(type)
                .extendValue(String.valueOf(rate))
                .build();
        characterService.updateRate(data);

        chr.message(I18nUtil.getMessage("Give.Rate.Chr", type, rate));
        log.info(I18nUtil.getLogMessage("Give.Rate.Chr.info1", chr.getId(), chr.getName(), type, rate));
    }

    private void giveGMChr(Character chr, Integer level) {
        if (level < 0  || level > 127) {
            throw new BizException(I18nUtil.getExceptionMessage("ILLEGAL_PARAMETERS",level));
        }
        if (level < 3) {
            chr.hide(false);
            chr.setGMLevel(level);
        } else {
            chr.setGMLevel(level);
            chr.hide(true);
        }
        chr.message(I18nUtil.getMessage("Give.GM.Chr", level));
        log.info(I18nUtil.getLogMessage("Give.GM.Chr.info1", chr.getId(), chr.getName(), level));
    }

    private void giveFameChr(Character chr, Integer fame) {
        chr.setFame(fame);
        chr.updateSingleStat(Stat.FAME, fame);
        chr.message(I18nUtil.getMessage("Give.Fame.Chr", fame));
        log.info(I18nUtil.getLogMessage("Give.Fame.Chr.info1", chr.getId(), chr.getName(), fame));
    }

    private void changeMap(Character chr, Integer mapId, boolean showLog) {
        if (910000000 == mapId) {
            chr.saveLocation("FREE_MARKET");
            chr.changeMap(mapId, "out00");
        } else {
            chr.changeMap(mapId);
        }
        String mapName = chr.getMap().getMapName();
        chr.message(I18nUtil.getMessage("Give.Map.Chr", mapName));
        if (showLog) {
            log.info(I18nUtil.getLogMessage("Give.Map.Chr.info1", chr.getId(), chr.getName(), mapName + " [" + mapId + "]"));
        }
    }

    private void changeMapOffline(Integer charId, Integer mapId) {
        CharactersDO charactersDO = new CharactersDO();
        charactersDO.setId(charId);
        charactersDO.setMap(mapId);
        charactersDO.setSpawnpoint(0); // 重置出生点，防止卡死
        charactersMapper.update(charactersDO);
        
        // 获取角色名用于日志
        CharactersDO chr = charactersMapper.selectOneById(charId);
        String name = (chr != null) ? chr.getName() : "未知";
        
        log.info(I18nUtil.getLogMessage("Give.Map.Chr.info1", charId, name, "离线变更地图 [" + mapId + "]"));
    }

    private void changeMapAllOnlineChr(Integer mapId) {
        String[] mapName = {null};
        Server.getInstance().getWorlds().forEach(world -> world.getPlayerStorage().getAllCharacters().forEach(chr -> {
            changeMap(chr, mapId, false);
            if (mapName[0] == null) {
                mapName[0] = chr.getMap().getMapName();
            }
        }));
        if (mapName[0] != null) {
            log.info(I18nUtil.getLogMessage("Give.Map.All.info1", mapName[0] + " [" + mapId + "]"));
        }
    }

    private void doGainCash(Character chr, int type, int quantity) {
        int cash = chr.getCashShop().getCash(type);
        long sum = (long) cash + (long) quantity;
        if (sum < 0) {
            quantity = -cash;
        }
        if (sum > Integer.MAX_VALUE) {
            quantity = Integer.MAX_VALUE - cash;
        }
        chr.getCashShop().gainCash(type, quantity);
    }

    private void doGainExp(Character chr, int quantity) {
        int exp = chr.getExp();
        long sum = (long) exp + (long) quantity;
        if (sum < 0) {
            sum = -exp;
        } else {
            sum = quantity;
        }
        chr.gainExp((int) sum);
    }

    private void doGainMeso(Character chr, int quantity) {
        int meso = chr.getMeso();
        long sum = (long) meso + (long) quantity;
        if (sum < 0) {
            quantity = -meso;
        }
        if (sum > Integer.MAX_VALUE) {
            quantity = Integer.MAX_VALUE - meso;
        }
        chr.gainMeso(quantity);
    }

    private String getFlagDetail(Short flag) {
        if (flag == null || flag == 0) {
            return "";
        }
        List<String> flags = new ArrayList<>();
        if ((flag & ItemConstants.LOCK) != 0) flags.add(I18nUtil.getMessage("Give.Flag.Lock"));
        if ((flag & ItemConstants.SPIKES) != 0) flags.add(I18nUtil.getMessage("Give.Flag.Spikes"));
        if ((flag & ItemConstants.COLD) != 0) flags.add(I18nUtil.getMessage("Give.Flag.Cold"));
        if ((flag & ItemConstants.UNTRADEABLE) != 0) flags.add(I18nUtil.getMessage("Give.Flag.Untradeable"));
        if ((flag & ItemConstants.KARMA_EQP) != 0) flags.add(I18nUtil.getMessage("Give.Flag.Karma"));
        if ((flag & ItemConstants.PET_COME) != 0) flags.add(I18nUtil.getMessage("Give.Flag.PetCome"));
        if ((flag & ItemConstants.ACCOUNT_SHARING) != 0) flags.add(I18nUtil.getMessage("Give.Flag.AccountSharing"));
        if ((flag & ItemConstants.MERGE_UNTRADEABLE) != 0) flags.add(I18nUtil.getMessage("Give.Flag.MergeUntradeable"));
        return "标记 [" + String.join(", ", flags) + "]";
    }

    private String getEquipDetail(GiveResourceReqDTO data) {
        List<String> details = new ArrayList<>();
        if (data.getStr() != null && data.getStr() != 0) details.add(I18nUtil.getMessage("Give.Equip.Str", data.getStr()));
        if (data.getDex() != null && data.getDex() != 0) details.add(I18nUtil.getMessage("Give.Equip.Dex", data.getDex()));
        if (data.get_int() != null && data.get_int() != 0) details.add(I18nUtil.getMessage("Give.Equip.Int", data.get_int()));
        if (data.getLuk() != null && data.getLuk() != 0) details.add(I18nUtil.getMessage("Give.Equip.Luk", data.getLuk()));
        if (data.getHp() != null && data.getHp() != 0) details.add(I18nUtil.getMessage("Give.Equip.Hp", data.getHp()));
        if (data.getMp() != null && data.getMp() != 0) details.add(I18nUtil.getMessage("Give.Equip.Mp", data.getMp()));
        if (data.getPAtk() != null && data.getPAtk() != 0) details.add(I18nUtil.getMessage("Give.Equip.PAtk", data.getPAtk()));
        if (data.getMAtk() != null && data.getMAtk() != 0) details.add(I18nUtil.getMessage("Give.Equip.MAtk", data.getMAtk()));
        if (data.getPDef() != null && data.getPDef() != 0) details.add(I18nUtil.getMessage("Give.Equip.PDef", data.getPDef()));
        if (data.getMDef() != null && data.getMDef() != 0) details.add(I18nUtil.getMessage("Give.Equip.MDef", data.getMDef()));
        if (data.getAcc() != null && data.getAcc() != 0) details.add(I18nUtil.getMessage("Give.Equip.Acc", data.getAcc()));
        if (data.getAvoid() != null && data.getAvoid() != 0) details.add(I18nUtil.getMessage("Give.Equip.Avoid", data.getAvoid()));
        if (data.getHands() != null && data.getHands() != 0) details.add(I18nUtil.getMessage("Give.Equip.Hands", data.getHands()));
        if (data.getSpeed() != null && data.getSpeed() != 0) details.add(I18nUtil.getMessage("Give.Equip.Speed", data.getSpeed()));
        if (data.getJump() != null && data.getJump() != 0) details.add(I18nUtil.getMessage("Give.Equip.Jump", data.getJump()));
        if (data.getUpgradeSlot() != null && data.getUpgradeSlot() != 0) details.add(I18nUtil.getMessage("Give.Equip.UpgradeSlot", data.getUpgradeSlot()));
        if (data.getLevel() != null && data.getLevel() != 0) details.add(I18nUtil.getMessage("Give.Equip.Level", data.getLevel()));
        if (data.getItemLevel() != null && data.getItemLevel() != 0) details.add(I18nUtil.getMessage("Give.Equip.ItemLevel", data.getItemLevel()));
        if (data.getExpire() != null && data.getExpire() != -1) details.add(getExpirationDetail(System.currentTimeMillis() + MINUTES.toMillis(data.getExpire())));
        if (data.getOwner() != null && !data.getOwner().isEmpty()) details.add(I18nUtil.getMessage("Give.Equip.Owner", data.getOwner()));
        return String.join(" ", details);
    }

    private String getExpirationDetail(long expiration) {
        if (expiration == -1) {
            return I18nUtil.getMessage("Give.Expiration.Permanent");
        }
        return I18nUtil.getMessage("Give.Expiration.Time", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(expiration)));
    }
}
