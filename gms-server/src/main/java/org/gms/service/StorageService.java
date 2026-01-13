package org.gms.service;

import lombok.AllArgsConstructor;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.dao.entity.StoragesDO;
import org.gms.dao.mapper.StoragesMapper;
import org.gms.util.Pair;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@AllArgsConstructor
public class StorageService {
    private final StoragesMapper storagesMapper;
    private final ItemFactoryService itemFactoryService;

    @Transactional
    public void saveStorage(StoragesDO storageDO, List<Pair<Item, InventoryType>> items, int storageId) {
        storagesMapper.update(storageDO);
        // 仓库物品的 accountid 字段实际上存储的是 storageid，这是历史遗留设计
        // ItemFactory.STORAGE 的 isAccount 为 true，所以这里传入 storageId 作为 accountId
        itemFactoryService.saveItems(2, true, items, storageId);
    }
}
