package org.gms.controller;

import lombok.RequiredArgsConstructor;
import org.gms.dao.entity.HiredMerchantItemsDO;
import org.gms.dao.entity.HiredMerchantTransactionsDO;
import org.gms.dao.entity.HiredMerchantsDO;
import org.gms.service.HiredMerchantService;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.util.List;

@RestController
@RequestMapping("/api/merchant")
@RequiredArgsConstructor
public class HiredMerchantController {

    private final HiredMerchantService hiredMerchantService;

    @GetMapping("/list")
    public List<HiredMerchantsDO> getAllActiveMerchants() {
        return hiredMerchantService.getAllActiveMerchants();
    }

    @GetMapping("/{id}/items")
    public List<HiredMerchantItemsDO> getMerchantItems(@PathVariable int id) {
        return hiredMerchantService.getMerchantItems(id);
    }

    @PostMapping("/{id}/restore")
    public String restoreMerchant(@PathVariable int id) {
        try {
            hiredMerchantService.restoreMerchantItems(id);
            return "商店物品恢复成功。";
        } catch (Exception e) {
            return "恢复商店物品时出错: " + e.getMessage();
        }
    }
    
    @PostMapping("/restore-backup")
    public String restoreFromBackup(@RequestParam String filePath) {
        try {
            File backupFile = new File(filePath);
            if (!backupFile.exists()) {
                return "备份文件不存在: " + filePath;
            }
            hiredMerchantService.restoreFromBackup(backupFile);
            return "从备份恢复成功。";
        } catch (Exception e) {
            return "从备份恢复时出错: " + e.getMessage();
        }
    }
    
    @PostMapping("/cleanup")
    public String cleanupOldRecords(@RequestParam(defaultValue = "30") int days) {
        try {
            hiredMerchantService.cleanupOldRecords(days);
            return "清理完成。";
        } catch (Exception e) {
            return "清理过程中出错: " + e.getMessage();
        }
    }
}
