package org.gms.service;

import com.mybatisflex.core.query.QueryWrapper;
import lombok.AllArgsConstructor;
import org.gms.dao.entity.PlifeDO;
import org.gms.dao.mapper.PlifeMapper;
import org.gms.util.Pair;
import org.springframework.stereotype.Service;

import java.awt.*;
import java.util.List;
import java.util.stream.Collectors;

import static org.gms.dao.entity.table.PlifeDOTableDef.PLIFE_D_O;

@Service
@AllArgsConstructor
public class PlifeService {

    private final PlifeMapper plifeMapper;

    public List<Pair<Integer, Pair<Integer, Integer>>> removePnpc(int world, int mapId, int npcId, Point pos) {
        QueryWrapper queryWrapper = QueryWrapper.create()
                .from(PLIFE_D_O)
                .where(PLIFE_D_O.WORLD.eq(world))
                .and(PLIFE_D_O.MAP.eq(mapId))
                .and(PLIFE_D_O.TYPE.eq("n"));

        if (npcId > -1) {
            queryWrapper.and(PLIFE_D_O.LIFE.eq(npcId));
        } else {
            queryWrapper.and(PLIFE_D_O.X.between(pos.x - 50, pos.x + 50))
                    .and(PLIFE_D_O.Y.between(pos.y - 50, pos.y + 50));
        }

        List<PlifeDO> toRemove = plifeMapper.selectListByQuery(queryWrapper);
        if (!toRemove.isEmpty()) {
            plifeMapper.deleteBatchByIds(toRemove.stream().map(PlifeDO::getId).collect(Collectors.toList()));
        }

        return toRemove.stream()
                .map(plife -> new Pair<>(plife.getLife(), new Pair<>(plife.getX(), plife.getY())))
                .collect(Collectors.toList());
    }

    public List<Pair<Integer, Pair<Integer, Integer>>> removePmob(int world, int mapId, int mobId, Point pos) {
        QueryWrapper queryWrapper = QueryWrapper.create()
                .from(PLIFE_D_O)
                .where(PLIFE_D_O.WORLD.eq(world))
                .and(PLIFE_D_O.MAP.eq(mapId))
                .and(PLIFE_D_O.TYPE.eq("m"));

        if (mobId > -1) {
            queryWrapper.and(PLIFE_D_O.LIFE.eq(mobId));
        } else {
            queryWrapper.and(PLIFE_D_O.X.between(pos.x - 50, pos.x + 50))
                    .and(PLIFE_D_O.Y.between(pos.y - 50, pos.y + 50));
        }

        List<PlifeDO> toRemove = plifeMapper.selectListByQuery(queryWrapper);
        if (!toRemove.isEmpty()) {
            plifeMapper.deleteBatchByIds(toRemove.stream().map(PlifeDO::getId).collect(Collectors.toList()));
        }

        return toRemove.stream()
                .map(plife -> new Pair<>(plife.getLife(), new Pair<>(plife.getX(), plife.getY())))
                .collect(Collectors.toList());
    }

    public void addPmob(int world, int mapId, int mobId, int mobTime, Point pos, int fh) {
        PlifeDO plifeDO = new PlifeDO();
        plifeDO.setLife(mobId);
        plifeDO.setF(0);
        plifeDO.setFh(fh);
        plifeDO.setCy(pos.y);
        plifeDO.setRx0(pos.x + 50);
        plifeDO.setRx1(pos.x - 50);
        plifeDO.setType("m");
        plifeDO.setX(pos.x);
        plifeDO.setY(pos.y);
        plifeDO.setWorld(world);
        plifeDO.setMap(mapId);
        plifeDO.setMobtime(mobTime);
        plifeDO.setHide(0);
        plifeMapper.insert(plifeDO);
    }

    public void addPnpc(int world, int mapId, int npcId, Point pos, int fh) {
        PlifeDO plifeDO = new PlifeDO();
        plifeDO.setLife(npcId);
        plifeDO.setF(0);
        plifeDO.setFh(fh);
        plifeDO.setCy(pos.y);
        plifeDO.setRx0(pos.x + 50);
        plifeDO.setRx1(pos.x - 50);
        plifeDO.setType("n");
        plifeDO.setX(pos.x);
        plifeDO.setY(pos.y);
        plifeDO.setWorld(world);
        plifeDO.setMap(mapId);
        plifeDO.setMobtime(-1);
        plifeDO.setHide(0);
        plifeMapper.insert(plifeDO);
    }
}
