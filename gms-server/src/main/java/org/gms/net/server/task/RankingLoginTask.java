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
package org.gms.net.server.task;

import com.mybatisflex.core.query.QueryWrapper;
import com.mybatisflex.core.update.UpdateChain;
import org.gms.client.Job;
import org.gms.config.GameConfig;
import org.gms.dao.entity.AccountsDO;
import org.gms.dao.entity.CharactersDO;
import org.gms.dao.mapper.CharactersMapper;
import org.gms.net.server.Server;
import org.gms.util.SpringContextUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

import static org.gms.dao.entity.table.CharactersDOTableDef.CHARACTERS_DO;

/**
 * 角色排名更新定时任务
 * @author Matze
 * @author Quit
 * @author Ronan
 */
public class RankingLoginTask implements Runnable {
    private static final Logger log = LoggerFactory.getLogger(RankingLoginTask.class);
    private long lastUpdate = System.currentTimeMillis();

    private void resetMoveRank(boolean isJobRank) {
        if (isJobRank) {
            UpdateChain.of(CharactersDO.class)
                    .set(CharactersDO::getJobRankMove, 0)
                    .where(CHARACTERS_DO.ID.gt(0))
                    .update();
        } else {
            UpdateChain.of(CharactersDO.class)
                    .set(CharactersDO::getRankMove, 0)
                    .where(CHARACTERS_DO.ID.gt(0))
                    .update();
        }
    }

    private void updateRanking(int job, int world) {
        CharactersMapper mapper = SpringContextUtil.getBean(CharactersMapper.class);

        QueryWrapper query = QueryWrapper.create()
                .select("c.id",
                        (job != -1 ? "c.jobRank" : "c.rank"),
                        (job != -1 ? "c.jobRankMove" : "c.rankMove"),
                        "a.lastlogin",
                        "a.loggedin")
                .from(CharactersDO.class).as("c")
                .leftJoin(AccountsDO.class).as("a").on("c.accountid = a.id")
                .where("c.gm < 2")
                .and("c.world = ?", world);

        if (job != -1) {
            // 使用原生 SQL 片段替代 QueryMethods.divide
            query.and("c.job DIV 100 = ?", job);
        }

        query.orderBy("c.level DESC", "c.exp DESC", "c.lastExpGainTime ASC", "c.fame DESC", "c.meso DESC");

        List<RankingInfoDTO> results = mapper.selectListByQueryAs(query, RankingInfoDTO.class);

        List<CharactersDO> toUpdate = new ArrayList<>();
        int rank = 0;
        for (RankingInfoDTO dto : results) {
            rank++;
            int rankMove = 0;
            if (dto.getLastlogin() == null || dto.getLastlogin().getTime() < lastUpdate || dto.getLoggedin() > 0) {
                rankMove = (job != -1 ? dto.getJobRankMove() : dto.getRankMove());
            }
            rankMove += (job != -1 ? dto.getJobRank() : dto.getRank()) - rank;

            CharactersDO charUpdate = new CharactersDO();
            charUpdate.setId(dto.getId());
            if (job != -1) {
                charUpdate.setJobRank(rank);
                charUpdate.setJobRankMove(rankMove);
            } else {
                charUpdate.setRank(rank);
                charUpdate.setRankMove(rankMove);
            }
            toUpdate.add(charUpdate);
        }

        if (!toUpdate.isEmpty()) {
            // Mapper没有默认的updateBatch，改为循环调用update
            for (CharactersDO charUpdate : toUpdate) {
                mapper.update(charUpdate);
            }
        }
    }

    // 手动添加Getters/Setters以避免Lombok问题
    public static class RankingInfoDTO {
        private Integer id;
        private Integer rank;
        private Integer rankMove;
        private Integer jobRank;
        private Integer jobRankMove;
        private Timestamp lastlogin;
        private Integer loggedin;

        public Integer getId() { return id; }
        public void setId(Integer id) { this.id = id; }
        public Integer getRank() { return rank; }
        public void setRank(Integer rank) { this.rank = rank; }
        public Integer getRankMove() { return rankMove; }
        public void setRankMove(Integer rankMove) { this.rankMove = rankMove; }
        public Integer getJobRank() { return jobRank; }
        public void setJobRank(Integer jobRank) { this.jobRank = jobRank; }
        public Integer getJobRankMove() { return jobRankMove; }
        public void setJobRankMove(Integer jobRankMove) { this.jobRankMove = jobRankMove; }
        public Timestamp getLastlogin() { return lastlogin; }
        public void setLastlogin(Timestamp lastlogin) { this.lastlogin = lastlogin; }
        public Integer getLoggedin() { return loggedin; }
        public void setLoggedin(Integer loggedin) { this.loggedin = loggedin; }
    }

    @Override
    @Transactional // 建议在调用此方法的服务层添加事务注解
    public void run() {
        try {
            if (GameConfig.getServerBoolean("use_refresh_rank_move")) {
                resetMoveRank(true);
                resetMoveRank(false);
            }

            for (int j = 0; j < Server.getInstance().getWorldsSize(); j++) {
                updateRanking(-1, j);    // 综合排名
                for (int i = 0; i <= Job.getMax(); i++) {
                    updateRanking(i, j); // 职业排名
                }
            }
            lastUpdate = System.currentTimeMillis();
        } catch (Exception e) {
            log.error("更新角色排名时发生错误", e);
        }
    }
}
