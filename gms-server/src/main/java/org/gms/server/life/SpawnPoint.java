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
package org.gms.server.life;

import lombok.Getter;
import lombok.Setter;
import org.gms.client.Character;
import org.gms.net.server.Server;
import org.gms.server.maps.MapleMap;
import org.gms.service.BossScheduleService;

import java.awt.*;
import java.util.concurrent.atomic.AtomicInteger;

import static java.util.concurrent.TimeUnit.SECONDS;

@Setter @Getter
public class SpawnPoint {
    private final int monster;
    private final int mobTime;
    private final int team;
    private final int fh;
    private final int f;
    private final Point pos;
    private long nextPossibleSpawn;
    private int mobInterval = 5000;
    private final AtomicInteger spawnedMonsters = new AtomicInteger(0);
    private final boolean immobile;
    private boolean denySpawn = false;
    // [新增] 用于持久化BOSS刷新计划的属性
    private final boolean shouldPersist;
    private int shouldId; // [修改] 允许被更新
    private final String msgRebirth, msgDeath; //出场广播消息和死亡广播消息，在当前地图广播


    public SpawnPoint(final Monster monster, Point pos, boolean immobile, int mobTime, int mobInterval, int team) {
        this.monster = monster.getId();
        this.pos = new Point(pos);
        this.mobTime = mobTime;
        this.team = team;
        this.fh = monster.getFh();
        this.f = monster.getF();
        this.immobile = immobile;
        this.mobInterval = mobInterval;
        this.nextPossibleSpawn = Server.getInstance().getCurrentTime();
        // [修改] 在构造时保存 shouldPersist 和 shouldId 属性
        this.shouldPersist = monster.isShouldPersist();
        this.shouldId = monster.getShouldId();
        this.msgRebirth = monster.getMsgRebirth();
        this.msgDeath = monster.getMsgDeath();
    }

    public int getSpawned() {
        return spawnedMonsters.intValue();
    }

    public boolean getDenySpawn() {
        return denySpawn;
    }

    public boolean shouldSpawn() {
        if (denySpawn || mobTime < 0 || spawnedMonsters.get() > 0) {
            return false;
        }
        return nextPossibleSpawn <= Server.getInstance().getCurrentTime();
    }

    public boolean shouldForceSpawn() {
        return mobTime >= 0 && spawnedMonsters.get() <= 0;
    }

    public Monster getMonster() {
        Monster mob = new Monster(LifeFactory.getMonster(monster));
        mob.setPosition(new Point(pos));
        mob.setTeam(team);
        mob.setFh(fh);
        mob.setF(f);
        // [修改] 将保存的属性应用到新创建的怪物实例上
        mob.setShouldPersist(this.shouldPersist);
        mob.setShouldId(this.shouldId);
        mob.setMsgRebirth(this.msgRebirth);
        mob.setMsgDeath(this.msgDeath);
        spawnedMonsters.incrementAndGet();
        mob.addListener(new MonsterListener() {
            @Override
            public void monsterKilled(int aniTime, boolean hasKiller,int world, int channel, int mapid) {
                if (mob.getMsgDeath() != null && !mob.getMsgDeath().isEmpty()) {
                    mob.getMap().dropMessage(5,mob.getMsgDeath());  // 广播死亡文案
                }
                nextPossibleSpawn = Server.getInstance().getCurrentTime();
                if (mobTime > 0) {
                    nextPossibleSpawn += SECONDS.toMillis(mobTime);
                } else {
                    nextPossibleSpawn += aniTime;
                }
                // 有击杀者、非其他怪物召唤的，才将下次刷新时间添加到数据库，避免关服等情况导致插入数据库报错影响关服
                if (hasKiller && mob.getParentMobOid() <= 0 && mob.isShouldPersist()) {
                    if (mob.getShouldId() > 0) {
                        BossScheduleService.getInstance().updateNextSpawnTime(mob.getShouldId(), nextPossibleSpawn);
                    } else {
                        // [修改] 调用新的 findOrCreateSchedule 方法，并更新当前刷新点的 shouldId
                        int newId = BossScheduleService.getInstance().findOrCreateSchedule(world, channel, mapid, mob.getId(), nextPossibleSpawn);
                        setShouldId(newId); // 更新当前SpawnPoint的ID，以便下次getMonster时传递正确的ID
                    }
                }
                spawnedMonsters.decrementAndGet();
            }

            @Override
            public void monsterDamaged(Character from, int trueDmg) {}

            @Override
            public void monsterHealed(int trueHeal) {}
        });
        if (mobTime == 0) {
            nextPossibleSpawn = Server.getInstance().getCurrentTime() + mobInterval;
        }
        return mob;
    }

    public int getMonsterId() {
        return monster;
    }

    public Point getPosition() {
        return pos;
    }

    public final int getF() {
        return f;
    }

    public final int getFh() {
        return fh;
    }

}
