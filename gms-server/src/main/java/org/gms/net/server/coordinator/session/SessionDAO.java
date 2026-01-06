package org.gms.net.server.coordinator.session;

import org.gms.manager.ServerManager;
import org.gms.service.SessionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;

public class SessionDAO {
    private static final Logger log = LoggerFactory.getLogger(SessionDAO.class);
    private static final SessionService sessionService = ServerManager.getApplicationContext().getBean(SessionService.class);

    public static void deleteExpiredHwidAccounts() {
        sessionService.deleteExpiredHwidAccounts();
    }

    public static List<Hwid> getHwidsForAccount(int accountId) {
        return sessionService.getHwidsForAccount(accountId);
    }

    public static void registerAccountAccess(int accountId, Hwid hwid, Instant expiry) {
        sessionService.registerAccountAccess(accountId, hwid, expiry);
    }

    public static List<HwidRelevance> getHwidRelevance(int accountId) {
        return sessionService.getHwidRelevance(accountId);
    }

    public static void updateAccountAccess(Hwid hwid, int accountId, Instant expiry, int loginRelevance) {
        sessionService.updateAccountAccess(hwid, accountId, expiry, loginRelevance);
    }
}
