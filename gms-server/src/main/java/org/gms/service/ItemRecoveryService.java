package org.gms.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mybatisflex.core.query.QueryWrapper;
import lombok.AllArgsConstructor;
import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.manipulator.InventoryManipulator;
import org.gms.client.processor.npc.DueyProcessor;
import org.gms.config.GameConfig;
import org.gms.constants.inventory.ItemConstants;
import org.gms.dao.entity.ItemRecoveryLogsDO;
import org.gms.dao.mapper.ItemRecoveryLogsMapper;
import org.gms.model.dto.ItemInfoRtnDTO;
import org.gms.server.CashShop;
import org.gms.server.ItemInformationProvider;
import org.gms.util.PacketCreator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
@AllArgsConstructor
public class ItemRecoveryService {
    private static final Logger log = LoggerFactory.getLogger(ItemRecoveryService.class);
    private final ItemRecoveryLogsMapper itemRecoveryLogsMapper;
    private final TraceabilityService traceabilityService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 获取玩家可找回的物品列表
     */
    public List<ItemRecoveryLogsDO> getRecoverableItems(int characterId) {
        QueryWrapper query = QueryWrapper.create()
                .where(ItemRecoveryLogsDO::getCharacterId).eq(characterId)
                .and(ItemRecoveryLogsDO::getStatus).eq("RECOVERABLE")
                .and(ItemRecoveryLogsDO::getRecoveryDeadline).gt(System.currentTimeMillis())
                .orderBy(ItemRecoveryLogsDO::getDisposalTime, false); // 按时间倒序
        
        return itemRecoveryLogsMapper.selectListByQuery(query);
    }

    /**
     * 计算物品找回费用
     * @param item 物品对象
     * @return 费用数组 [金币, 点券]
     */
    public long[] calculateRecoveryFee(Item item) {
        long baseMeso = GameConfig.getServerLong("item_recovery_base_fee_meso", 50000L);
        long baseNx = GameConfig.getServerLong("item_recovery_base_fee_nx", 0L);
        double rate = GameConfig.getServerDouble("item_recovery_valuation_rate", 1.5);
        
        long itemPrice = 0;
        if (rate > 0) {
            ItemInformationProvider ii = ItemInformationProvider.getInstance();
            // 获取物品商店售价，如果为0则默认为1
            double price = ii.getPrice(item.getItemId(), 1);
            if (price <= 0) price = 1;
            itemPrice = (long) (price * item.getQuantity() * rate);
        }
        
        return new long[] { baseMeso + itemPrice, baseNx };
    }

    /**
     * 执行物品找回
     * @param c 客户端
     * @param logId 日志ID
     */
    @Transactional
    public void recoverItem(Client c, long logId) {
        Character chr = c.getPlayer();
        ItemRecoveryLogsDO logEntry = itemRecoveryLogsMapper.selectOneById(logId);

        if (logEntry == null) {
            chr.dropMessage(1, "找不到该找回记录。");
            return;
        }

        if (logEntry.getCharacterId() != chr.getId()) {
            chr.dropMessage(1, "这不是您的物品。");
            return;
        }

        if (!"RECOVERABLE".equals(logEntry.getStatus())) {
            chr.dropMessage(1, "该物品已找回或已过期。");
            return;
        }

        if (System.currentTimeMillis() > logEntry.getRecoveryDeadline()) {
            logEntry.setStatus("EXPIRED");
            itemRecoveryLogsMapper.update(logEntry);
            chr.dropMessage(1, "该物品已过期，无法找回。");
            return;
        }

        try {
            // 反序列化物品
            ItemInfoRtnDTO itemDTO = objectMapper.readValue(logEntry.getItemData(), ItemInfoRtnDTO.class);
            Item item = DueyProcessor.restoreItemFromDTO(itemDTO);
            // 恢复原始 UID
            item.setUid(logEntry.getUid());

            // 计算费用
            long[] fees = calculateRecoveryFee(item);
            long mesoFee = fees[0];
            long nxFee = fees[1];
            int costType = GameConfig.getServerInt("item_recovery_cost_type", 0); // 0=金币, 1=点券, 2=混合

            // 检查费用
            if (costType == 0 || costType == 2) {
                if (chr.getMeso() < mesoFee) {
                    chr.dropMessage(1, "找回物品需要支付 " + mesoFee + " 金币。");
                    return;
                }
            }
            if (costType == 1 || costType == 2) {
                if (chr.getCashShop().getCash(CashShop.NX_CREDIT) < nxFee) { // 使用点券
                    chr.dropMessage(1, "找回物品需要支付 " + nxFee + " 点券。");
                    return;
                }
            }

            // 扣除费用
            if (costType == 0 || costType == 2) {
                chr.gainMeso((int) -mesoFee, true);
            }
            if (costType == 1 || costType == 2) {
                chr.getCashShop().gainCash(CashShop.NX_CREDIT, (int) -nxFee);
            }

            // 通过快递发送物品
            String message = "您找回的物品已送达，请查收。";
            // 9010000 是失物招领管理员的 NPC ID，作为发件人 ID
            // 使用 dueySendItem 逻辑，但由于 dueySendItem 是处理客户端请求的，包含了很多检查和扣费逻辑
            // 这里我们直接调用 createPackage 和 insertPackageItem，并手动触发通知
            // 修正：根据要求，应尽可能复用 DueyProcessor 的逻辑，但 dueySendItem 包含扣费和客户端交互，不适合直接调用
            // 因此保持 createPackage + insertPackageItem + showDueyNotification 的组合是正确的底层调用方式
            // 如果必须使用 dueySendItem，需要重构 DueyProcessor 将核心逻辑分离
            // 鉴于当前上下文，我们直接使用底层方法组合来模拟系统发送
            
            int packageId = DueyProcessor.createPackage(0, message, "找回系统", chr.getId(), false, item, 9010000, -1);
            
            if (packageId != -1) {
                DueyProcessor.insertPackageItem(packageId, item);
                
                // 发送快递通知
                DueyProcessor.showDueyNotification(chr);
                
                // 记录溯源日志：物品找回
                traceabilityService.log(item, chr, TraceabilityService.ActionType.REWARD, "物品找回", item.getQuantity(), "PackageID: " + packageId, "LogID: " + logId);

                // 更新状态
                logEntry.setStatus("RECOVERED");
                itemRecoveryLogsMapper.update(logEntry);

                // 提示信息已在脚本中处理
            } else {
                // 如果快递发送失败，回滚费用扣除（虽然事务会回滚，但手动提示更友好）
                throw new RuntimeException("创建快递包裹失败");
            }

        } catch (Exception e) {
            log.error("物品找回失败, LogID: " + logId, e);
            chr.dropMessage(1, "系统错误，找回失败。请联系管理员。");
            // 抛出异常以触发事务回滚
            throw new RuntimeException(e);
        }
    }

    /**
     * 定时清理过期记录
     * 每天凌晨 4 点执行
     */
    @Scheduled(cron = "0 0 4 * * ?")
    public void cleanupExpiredLogs() {
        long now = System.currentTimeMillis();
        
        // 1. 将过期的 RECOVERABLE 记录更新为 EXPIRED
        ItemRecoveryLogsDO updateDO = new ItemRecoveryLogsDO();
        updateDO.setStatus("EXPIRED");
        
        QueryWrapper updateQuery = QueryWrapper.create()
                .where(ItemRecoveryLogsDO::getStatus).eq("RECOVERABLE")
                .and(ItemRecoveryLogsDO::getRecoveryDeadline).lt(now);
        
        int expiredCount = itemRecoveryLogsMapper.updateByQuery(updateDO, updateQuery);
        if (expiredCount > 0) {
            log.info("已将 {} 条过期的物品找回记录标记为 EXPIRED。", expiredCount);
        }

        // 2. 物理删除超过保留期限的 EXPIRED 记录
        int retentionDays = GameConfig.getServerInt("item_recovery_expiration_days", 7);
        long retentionMillis = TimeUnit.DAYS.toMillis(retentionDays);
        long deleteDeadline = now - retentionMillis;

        QueryWrapper deleteQuery = QueryWrapper.create()
                .where(ItemRecoveryLogsDO::getStatus).eq("EXPIRED")
                .and(ItemRecoveryLogsDO::getDisposalTime).lt(deleteDeadline);

        int deletedCount = itemRecoveryLogsMapper.deleteByQuery(deleteQuery);
        if (deletedCount > 0) {
            log.info("已物理删除 {} 条超过 {} 天保留期的物品找回记录。", deletedCount, retentionDays);
        }
    }
}
