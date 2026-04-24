package org.gms.server.life;

import org.gms.client.Character;

public interface MonsterListener {

    /**
     * 怪物死亡
     *
     * @param aniTime   死亡动画时间
     * @param hasKiller 是否有击杀者
     * @param world     世界ID
     * @param channel   频道ID
     * @param mapid     地图ID
     */
    void monsterKilled(int aniTime, boolean hasKiller, int world, int channel, int mapid);

    /**
     * 怪物攻击
     *
     * @param from    攻击者
     * @param trueDmg 真实伤害
     */
    void monsterDamaged(Character from, int trueDmg);

    /**
     * 怪物被治愈
     *
     * @param trueHeal 真实治愈
     */
    void monsterHealed(int trueHeal);
}
