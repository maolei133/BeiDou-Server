package org.gms.controller;

import lombok.RequiredArgsConstructor;
import org.gms.dao.entity.HiredMerchantItemsDO;
import org.gms.dao.entity.HiredMerchantTransactionsDO;
import org.gms.dao.entity.HiredMerchantsDO;
import org.gms.model.dto.ResultBody;
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
    public ResultBody<List<HiredMerchantsDO>> getAllActiveMerchants() {
        return ResultBody.success(hiredMerchantService.getAllActiveMerchants());
    }

    @GetMapping("/{id}/items")
    public ResultBody<List<HiredMerchantItemsDO>> getMerchantItems(@PathVariable int id) {
        return ResultBody.success(hiredMerchantService.getMerchantItems(id));
    }

    @PostMapping("/{id}/restore")
    public ResultBody<String> restoreMerchant(@PathVariable int id) {
        try {
            hiredMerchantService.restoreMerchantItems(id);
            return ResultBody.success("商店物品恢复成功。");
        } catch (Exception e) {
            return ResultBody.error("恢复商店物品时出错: " + e.getMessage());
        }
    }
    
    @PostMapping("/restore-backup")
    public ResultBody<String> restoreFromBackup(@RequestParam String filePath) {
        try {
            File backupFile = new File(filePath);
            if (!backupFile.exists()) {
                return ResultBody.error("备份文件不存在: " + filePath);
            }
            hiredMerchantService.restoreFromBackup(backupFile);
            return ResultBody.success("从备份恢复成功。");
        } catch (Exception e) {
            return ResultBody.error("从备份恢复时出错: " + e.getMessage());
        }
    }
    
    @PostMapping("/cleanup")
    public ResultBody<String> cleanupOldRecords(@RequestParam(defaultValue = "30") int days) {
        try {
            hiredMerchantService.cleanupOldRecords(days);
            return ResultBody.success("清理完成。");
        } catch (Exception e) {
            return ResultBody.error("清理过程中出错: " + e.getMessage());
        }
    }
}
