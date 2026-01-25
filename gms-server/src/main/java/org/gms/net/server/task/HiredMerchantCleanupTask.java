package org.gms.net.server.task;

import org.gms.config.GameConfig;
import org.gms.manager.ServerManager;
import org.gms.service.HiredMerchantService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HiredMerchantCleanupTask implements Runnable {
    private static final Logger log = LoggerFactory.getLogger(HiredMerchantCleanupTask.class);
    private final HiredMerchantService hiredMerchantService;

    public HiredMerchantCleanupTask() {
        this.hiredMerchantService = ServerManager.getApplicationContext().getBean(HiredMerchantService.class);
    }

    @Override
    public void run() {
        int days = GameConfig.getServerInt("hired_merchant_keep_days", 30);
        if (days <= 0) return;
        
        log.info("开始清理雇佣商店数据 (保留天数: {} 天)...", days);
        try {
            hiredMerchantService.cleanupOldRecords(days);
            log.info("雇佣商店数据清理完成。");
        } catch (Exception e) {
            log.error("雇佣商店数据清理过程中发生错误", e);
        }
    }
}
