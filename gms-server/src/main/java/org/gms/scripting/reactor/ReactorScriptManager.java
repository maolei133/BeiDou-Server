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
package org.gms.scripting.reactor;

import com.mybatisflex.core.query.QueryWrapper;
import org.gms.client.Client;
import org.gms.dao.entity.ReactordropsDO;
import org.gms.dao.mapper.ReactordropsMapper;
import org.gms.manager.ServerManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.gms.scripting.AbstractScriptManager;
import org.gms.server.maps.Reactor;
import org.gms.server.maps.ReactorDropEntry;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.gms.dao.entity.table.ReactordropsDOTableDef.REACTORDROPS_D_O;

/**
 * @author Lerk
 */
public class ReactorScriptManager extends AbstractScriptManager {
    private static final Logger log = LoggerFactory.getLogger(ReactorScriptManager.class);
    private static final ReactorScriptManager instance = new ReactorScriptManager();
    private static final ReactordropsMapper reactordropsMapper = ServerManager.getApplicationContext().getBean(ReactordropsMapper.class);

    private final Map<Integer, List<ReactorDropEntry>> drops = new HashMap<>();

    public static ReactorScriptManager getInstance() {
        return instance;
    }

    public void onHit(Client c, Reactor reactor) {
        try {
            Invocable iv = initializeInvocable(c, reactor);
            if (iv == null) {
                return;
            }

            iv.invokeFunction("hit");
        } catch (final NoSuchMethodException e) {
            //do nothing, hit is OPTIONAL
        } catch (final ScriptException | NullPointerException e) {
            log.error("Error during onHit script for reactor: {}", reactor.getId(), e);
        }
    }

    public void act(Client c, Reactor reactor) {
        try {
            Invocable iv = initializeInvocable(c, reactor);
            if (iv == null) {
                return;
            }

            iv.invokeFunction("act");
        } catch (final ScriptException | NoSuchMethodException | NullPointerException e) {
            log.error("Error during act script for reactor: {}", reactor.getId(), e);
        }
    }

    public List<ReactorDropEntry> getDrops(int reactorId) {
        List<ReactorDropEntry> ret = drops.get(reactorId);
        if (ret == null) {
            List<ReactordropsDO> dropList = reactordropsMapper.selectListByQuery(QueryWrapper.create()
                    .where(REACTORDROPS_D_O.REACTORID.eq(reactorId))
                    .and(REACTORDROPS_D_O.CHANCE.ge(0)));
            ret = dropList.stream()
                    .map(drop -> new ReactorDropEntry(drop.getItemid(), drop.getChance(), drop.getQuestid()))
                    .collect(Collectors.toList());
            drops.put(reactorId, ret);
        }
        return ret;
    }

    public void clearDrops() {
        drops.clear();
    }

    public void touch(Client c, Reactor reactor) {
        touching(c, reactor, true);
    }

    public void untouch(Client c, Reactor reactor) {
        touching(c, reactor, false);
    }

    private void touching(Client c, Reactor reactor, boolean touching) {
        final String functionName = touching ? "touch" : "untouch";
        try {
            Invocable iv = initializeInvocable(c, reactor);
            if (iv == null) {
                return;
            }

            iv.invokeFunction(functionName);
        } catch (final ScriptException | NoSuchMethodException | NullPointerException e) {
            log.error("Error during {} script for reactor: {}", functionName, reactor.getId(), e);
        }
    }

    private Invocable initializeInvocable(Client c, Reactor reactor) {
        ScriptEngine engine = getInvocableScriptEngine("reactor/" + reactor.getId() + ".js", c);
        if (engine == null) {
            return null;
        }

        Invocable iv = (Invocable) engine;
        ReactorActionManager rm = new ReactorActionManager(c, reactor, iv);
        engine.put("rm", rm);

        return iv;
    }
}
