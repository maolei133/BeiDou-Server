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
import org.gms.server.ItemInformationProvider;
import org.gms.util.PacketCreator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@AllArgsConstructor
public class ItemRecoveryService {
    private static final Logger log = LoggerFactory.getLogger(ItemRecoveryService.class);
    private final ItemRecoveryLogsMapper itemRecoveryLogsMapper;
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

        // 检查费用
        int fee = GameConfig.getServerInt("item_recovery_fee", 10000);
        if (chr.getMeso() < fee) {
            chr.dropMessage(1, "找回物品需要支付 " + fee + " 金币的手续费。");
            return;
        }

        try {
            // 反序列化物品
            ItemInfoRtnDTO itemDTO = objectMapper.readValue(logEntry.getItemData(), ItemInfoRtnDTO.class);
            Item item = DueyProcessor.restoreItemFromDTO(itemDTO);
            // 恢复原始 UID
            item.setUid(logEntry.getUid());

            // 检查背包空间
            if (!InventoryManipulator.checkSpace(c, item.getItemId(), item.getQuantity(), item.getOwner())) {
                chr.dropMessage(1, "背包空间不足，请整理后再试。");
                return;
            }

            // 扣除费用
            chr.gainMeso(-fee, true);

            // 发放物品
            InventoryManipulator.addFromDrop(c, item, true);

            // 更新状态
            logEntry.setStatus("RECOVERED");
            itemRecoveryLogsMapper.update(logEntry);

            chr.dropMessage(1, "物品找回成功！");

        } catch (Exception e) {
            log.error("物品找回失败, LogID: " + logId, e);
            chr.dropMessage(1, "系统错误，找回失败。");
        }
    }

    /**
     * 定时清理过期记录
     * 每天凌晨 4 点执行
     */
    @Scheduled(cron = "0 0 4 * * ?")
    public void cleanupExpiredLogs() {
        long now = System.currentTimeMillis();
        
        // 将过期的 RECOVERABLE 记录更新为 EXPIRED
        ItemRecoveryLogsDO updateDO = new ItemRecoveryLogsDO();
        updateDO.setStatus("EXPIRED");
        
        QueryWrapper updateQuery = QueryWrapper.create()
                .where(ItemRecoveryLogsDO::getStatus).eq("RECOVERABLE")
                .and(ItemRecoveryLogsDO::getRecoveryDeadline).lt(now);
        
        int count = itemRecoveryLogsMapper.updateByQuery(updateDO, updateQuery);
        if (count > 0) {
            log.info("已清理 {} 条过期的物品找回记录。", count);
        }
    }
}
