package org.gms.dao.mapper;

import com.mybatisflex.core.BaseMapper;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;
import org.gms.dao.entity.CharactersDO;

import java.util.List;

/**
 *  映射层。
 *
 * @author sleep
 * @since 2024-05-24
 */
public interface CharactersMapper extends BaseMapper<CharactersDO> {
    @Update("UPDATE characters SET HasMerchant = #{value}")
    void updateAllHasMerchant(Integer value);

    @Select("SELECT id, world FROM characters WHERE accountid = #{accountId}")
    List<CharactersDO> selectIdAndWorldListByAccountId(int accountId);

    @Select("SELECT id, name, level, job, guildrank, allianceRank FROM characters WHERE guildid = #{guildId} ORDER BY guildrank ASC, name ASC")
    List<CharactersDO> selectGuildMembers(int guildId);

    @Update("UPDATE characters SET guildid = #{guildId}, guildrank = #{guildRank} WHERE id = #{charId}")
    void updateGuildInfo(int charId, int guildId, int guildRank);

    @Update("UPDATE characters SET guildid = 0, guildrank = 5 WHERE guildid = #{guildId}")
    void resetGuildInfoByGuildId(int guildId);

    @Update("UPDATE characters SET allianceRank = #{rank} WHERE guildid = #{guildId}")
    void updateAllianceRankByGuildId(int guildId, int rank);

    @Update("UPDATE characters SET familyid = #{familyId} WHERE id = #{charId}")
    void updateFamilyId(int charId, int familyId);
}
