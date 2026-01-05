package org.gms.net.server.task;

import com.mybatisflex.core.query.QueryWrapper;
import org.gms.client.Family;
import org.gms.constants.game.GameConstants;
import org.gms.dao.entity.FamilyCharacterDO;
import org.gms.dao.entity.FamilyEntitlementDO;
import org.gms.dao.mapper.FamilyCharacterMapper;
import org.gms.dao.mapper.FamilyEntitlementMapper;
import org.gms.net.server.Server;
import org.gms.net.server.world.World;
import org.gms.util.Pair;
import org.gms.util.SpringContextUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Calendar;

public class FamilyDailyResetTask implements Runnable {
    private static final Logger log = LoggerFactory.getLogger(FamilyDailyResetTask.class);
    private final World world;

    private static FamilyCharacterMapper familyCharacterMapper;
    private static FamilyEntitlementMapper familyEntitlementMapper;

    static {
        familyCharacterMapper = SpringContextUtil.getBean(FamilyCharacterMapper.class);
        familyEntitlementMapper = SpringContextUtil.getBean(FamilyEntitlementMapper.class);
    }

    public FamilyDailyResetTask(World world) {
        this.world = world;
    }

    @Override
    public void run() {
        resetEntitlementUsage(world);
        for (Family family : world.getFamilies()) {
            family.resetDailyReps();
        }
        if (Server.getInstance().isNextTime()) {
            Pair<byte[], byte[]> pair = GameConstants.getEnc();
            log.warn(new String(pair.getLeft(), StandardCharsets.UTF_8));
            log.warn(new String(pair.getRight(), StandardCharsets.UTF_8));
        }
    }

    public static void resetEntitlementUsage(World world) {
        Calendar resetTime = Calendar.getInstance();
        resetTime.add(Calendar.MINUTE, 1); // to make sure that we're in the "next day", since this is called at midnight
        resetTime.set(Calendar.HOUR_OF_DAY, 0);
        resetTime.set(Calendar.MINUTE, 0);
        resetTime.set(Calendar.SECOND, 0);
        resetTime.set(Calendar.MILLISECOND, 0);

        try {
            FamilyCharacterDO updateDO = new FamilyCharacterDO();
            updateDO.setTodaysrep(0);
            updateDO.setReptosenior(0);
            familyCharacterMapper.updateByQuery(updateDO,
                    QueryWrapper.create().where(FamilyCharacterDO::getLastresettime).le(resetTime.getTimeInMillis()));
        } catch (Exception e) {
            log.error("Could not reset daily rep for families", e);
        }

        try {
            familyEntitlementMapper.deleteByQuery(
                    QueryWrapper.create().where(FamilyEntitlementDO::getTimestamp).le(resetTime.getTimeInMillis()));
        } catch (Exception e) {
            log.error("Could not do daily reset for family entitlements", e);
        }
    }
}
