package org.gms.service;

import com.mybatisflex.core.query.QueryWrapper;
import lombok.AllArgsConstructor;
import org.gms.dao.entity.HwidaccountsDO;
import org.gms.dao.mapper.HwidaccountsMapper;
import org.gms.net.server.coordinator.session.Hwid;
import org.gms.net.server.coordinator.session.HwidRelevance;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static com.mybatisflex.core.query.QueryMethods.now;
import static org.gms.dao.entity.table.HwidaccountsDOTableDef.HWIDACCOUNTS_D_O;

@Service
@AllArgsConstructor
public class SessionService {

    private final HwidaccountsMapper hwidaccountsMapper;

    public void deleteExpiredHwidAccounts() {
        hwidaccountsMapper.deleteByQuery(QueryWrapper.create().where(HWIDACCOUNTS_D_O.EXPIRESAT.lt(now())));
    }

    public List<Hwid> getHwidsForAccount(int accountId) {
        List<HwidaccountsDO> list = hwidaccountsMapper.selectListByQuery(QueryWrapper.create()
                .select(HWIDACCOUNTS_D_O.HWID)
                .where(HWIDACCOUNTS_D_O.ACCOUNTID.eq(accountId)));
        List<Hwid> hwids = new ArrayList<>();
        for (HwidaccountsDO data : list) {
            hwids.add(new Hwid(data.getHwid()));
        }
        return hwids;
    }

    public void registerAccountAccess(int accountId, Hwid hwid, Instant expiry) {
        if (hwid == null) {
            throw new IllegalArgumentException("Hwid must not be null");
        }
        HwidaccountsDO doo = new HwidaccountsDO();
        doo.setAccountid(accountId);
        doo.setHwid(hwid.hwid());
        doo.setRelevance(1);
        doo.setExpiresat(Timestamp.from(expiry));
        hwidaccountsMapper.insert(doo);
    }

    public List<HwidRelevance> getHwidRelevance(int accountId) {
        List<HwidaccountsDO> list = hwidaccountsMapper.selectListByQuery(QueryWrapper.create()
                .where(HWIDACCOUNTS_D_O.ACCOUNTID.eq(accountId)));
        List<HwidRelevance> hwidRelevances = new ArrayList<>();
        for (HwidaccountsDO data : list) {
            hwidRelevances.add(new HwidRelevance(data.getHwid(), data.getRelevance()));
        }
        return hwidRelevances;
    }

    public void updateAccountAccess(Hwid hwid, int accountId, Instant expiry, int loginRelevance) {
        HwidaccountsDO doo = new HwidaccountsDO();
        doo.setRelevance(loginRelevance);
        doo.setExpiresat(Timestamp.from(expiry));
        hwidaccountsMapper.updateByQuery(doo, QueryWrapper.create()
                .where(HWIDACCOUNTS_D_O.ACCOUNTID.eq(accountId))
                .and(HWIDACCOUNTS_D_O.HWID.like(hwid.hwid())));
    }
}
