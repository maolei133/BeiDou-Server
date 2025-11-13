/*
    This file is part of the HeavenMS MapleStory Server
    Copyleft (L) 2016 - 2019 RonanLana

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
package org.gms.util;

import org.gms.dao.mapper.PetsMapper;
import org.gms.dao.mapper.RingsMapper;
import org.gms.manager.ServerManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;

/**
 * 现金物品ID生成器
 * 用于为游戏中的现金物品（如戒指、宠物等）生成唯一ID
 * 
 * @author RonanLana
 */
public class CashIdGenerator {
    private static final Logger log = LoggerFactory.getLogger(CashIdGenerator.class);
    /**
     * 已存在的现金物品ID集合
     * 用于避免生成重复的ID
     */
    private final static Set<Integer> existentCashIds = new HashSet<>(10000);
    /**
     * 当前正在尝试的现金物品ID
     */
    private static Integer runningCashId = 0;
    /**
     * 最大尝试次数，防止无限循环
     */
    private static final int MAX_GENERATE_ATTEMPTS = 10000;

    /**
     * 从数据库加载所有已存在的现金物品ID
     * 包括戒指和宠物的ID
     */
    public static synchronized void loadExistentCashIdsFromDb() {
        RingsMapper ringsMapper = ServerManager.getApplicationContext().getBean(RingsMapper.class);
        existentCashIds.clear();
        ringsMapper.selectAll().forEach(ringsDO -> {
            if (ringsDO.getId() != null) {
                existentCashIds.add(ringsDO.getId());
            }
        });
        PetsMapper petsMapper = ServerManager.getApplicationContext().getBean(PetsMapper.class);
        petsMapper.selectAll().forEach(petsDO -> {
            if (petsDO.getPetid() != null) {
                existentCashIds.add(petsDO.getPetid().intValue());
            }
        });

        runningCashId = 0;
        do {
            runningCashId++;    // 希望ID永远不会超过为宠物/戒指分配的数量
        } while (existentCashIds.contains(runningCashId));
    }

    /**
     * 获取下一个可用的现金物品ID
     * 当ID达到上限时重新从数据库加载
     */
    private static void getNextAvailableCashId() {
        runningCashId++;
        if (runningCashId >= 777000000) {
            loadExistentCashIdsFromDb();
        }
    }

    /**
     * 生成一个唯一的现金物品ID
     * 
     * @return 唯一的现金物品ID
     * @throws RuntimeException 当无法在最大尝试次数内生成ID时抛出异常
     */
    public static synchronized int generateCashId() {
        int attempts = 0;
        while (attempts < MAX_GENERATE_ATTEMPTS) {
            if (!existentCashIds.contains(runningCashId)) {
                int ret = runningCashId;
                getNextAvailableCashId();

                // existentCashids.add(ret)... 不需要这样做，因为循环结束后会从数据库重新获取已使用的现金ID
                return ret;
            }

            getNextAvailableCashId();
            attempts++;
        }
        
        // 如果达到最大尝试次数，记录错误并抛出异常
        log.error("在 {} 次尝试后无法生成现金ID。当前runningCashId: {}", MAX_GENERATE_ATTEMPTS, runningCashId);
        throw new RuntimeException("在" + MAX_GENERATE_ATTEMPTS + "次尝试后无法生成现金ID");
    }

    /**
     * 释放一个现金物品ID
     * 当现金物品被删除时调用此方法
     * 
     * @param cashId 要释放的现金物品ID
     */
    public static synchronized void freeCashId(int cashId) {
        existentCashIds.remove(cashId);
    }

}