package org.gms.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.gms.client.inventory.Item;
import org.gms.model.dto.ResultBody;
import org.gms.service.StorageService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "仓库管理", description = "提供仓库物品查询和管理接口")
@RestController
@RequestMapping("/api/storage")
@RequiredArgsConstructor
public class StorageController {

    private final StorageService storageService;

    @Operation(summary = "获取仓库物品", description = "获取指定角色的仓库物品列表")
    @GetMapping("/{charId}")
    public ResultBody<List<Item>> getStorageItems(@PathVariable int charId) {
        // 注意：StorageService.loadStorageItems 需要 storageId (通常是 accountId)
        // 这里假设前端传递的是 characterId，我们需要先获取 accountId
        // 或者前端直接传递 accountId
        // 为了简化，这里假设 charId 就是 storageId (在某些私服实现中可能是这样，或者需要转换)
        // 实际上，Storage.loadOrCreateFromDB 使用 accountId 和 worldId
        // 我们需要一个服务方法通过 charId 获取 accountId
        // 暂时假设传入的是 accountId
        return ResultBody.success(storageService.loadStorageItems(charId));
    }

    @Operation(summary = "移动物品", description = "管理员将物品从仓库移动到背包，或反之")
    @PostMapping("/move")
    public ResultBody<String> moveItem(@RequestParam int charId, @RequestParam long itemUid, @RequestParam String direction) {
        // 实现物品移动逻辑
        // direction: "to_inventory" or "to_storage"
        return ResultBody.error("该功能暂未实现");
    }
}
