package org.gms.service;

import com.mybatisflex.core.query.QueryWrapper;
import lombok.AllArgsConstructor;
import org.gms.client.Character;
import org.gms.client.inventory.Pet;
import org.gms.dao.entity.PetsDO;
import org.gms.dao.mapper.PetignoresMapper;
import org.gms.dao.mapper.PetsMapper;
import org.gms.util.CashIdGenerator;
import org.gms.server.ItemInformationProvider;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import static org.gms.dao.entity.table.PetignoresDOTableDef.PETIGNORES_DO;

@Service
@AllArgsConstructor
public class PetService {

    private final PetsMapper petsMapper;
    private final PetignoresMapper petignoresMapper;

    public Pet loadFromDb(int itemid, short position, int petid) {
        PetsDO petDO = petsMapper.selectOneById(petid);
        if (petDO == null) {
            return null;
        }

        Pet ret = new Pet(itemid, position, petid);
        ret.setName(petDO.getName());
        ret.setTameness(Math.min(petDO.getCloseness().intValue(), 30000));
        ret.setLevel((byte) Math.min(petDO.getLevel(), 30));
        ret.setFullness(Math.min(petDO.getFullness().intValue(), 100));
        ret.setSummoned(petDO.getSummoned());
        ret.setPetAttribute(petDO.getFlag().intValue());
        return ret;
    }

    @Transactional
    public void deleteFromDb(Character owner, int petid) {
        petsMapper.deleteById(petid);
        petignoresMapper.deleteByQuery(QueryWrapper.create().where(PETIGNORES_DO.PETID.eq(petid)));
        owner.resetExcluded(petid);
        CashIdGenerator.freeCashId(petid);
    }

    public void saveToDb(Pet pet) {
        PetsDO petDO = PetsDO.builder()
                .petid((long) pet.getUniqueId())
                .name(pet.getName())
                .level((long) pet.getLevel())
                .closeness((long) pet.getTameness())
                .fullness((long) pet.getFullness())
                .summoned(pet.isSummoned())
                .flag((long) pet.getPetAttribute())
                .build();
        petsMapper.update(petDO);
    }

    public int createPet(int itemid) {
        return createPet(itemid, (byte) 1, 0, 100);
    }

    public int createPet(int itemid, byte level, int tameness, int fullness) {
        int ret = CashIdGenerator.generateCashId();
        PetsDO petDO = PetsDO.builder()
                .petid((long) ret)
                .name(ItemInformationProvider.getInstance().getName(itemid))
                .level((long) level)
                .closeness((long) tameness)
                .fullness((long) fullness)
                .summoned(false)
                .flag(0L)
                .build();
        petsMapper.insert(petDO);
        return ret;
    }
}
