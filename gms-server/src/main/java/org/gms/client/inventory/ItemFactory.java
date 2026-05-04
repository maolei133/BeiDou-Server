/*
 This file is part of the OdinMS Maple Story Server
 Copyright (C) 2008 Patrick Huy <patrick.huy@frz.cc>
 Matthias Butz <matze@odinms.de>
 Jan Christian Meyer <vimes@odinms.de>

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License version 3
 as published by the Free Software Foundation. You may not use, modify
 or distribute this program under any other version of the
 GNU Affero General Public License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.gms.client.inventory;

import org.gms.manager.ServerManager;
import org.gms.service.ItemFactoryService;
import org.gms.util.Pair;

import java.util.List;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @author Flav
 */
public enum ItemFactory {

    INVENTORY(1, false),
    STORAGE(2, true),
    CASH_EXPLORER(3, true),
    CASH_CYGNUS(4, true),
    CASH_ARAN(5, true),
    MERCHANT(6, false),
    CASH_OVERALL(7, true),
    MARRIAGE_GIFTS(8, false),
    DUEY(9, false);
    private final int value;
    private final boolean account;

    private static final int lockCount = 400;
    private static final Lock[] locks = new Lock[lockCount];
    private static ItemFactoryService itemFactoryService;

    static {
        for (int i = 0; i < lockCount; i++) {
            locks[i] = new ReentrantLock(true);
        }
    }

    private static ItemFactoryService getItemFactoryService() {
        if (itemFactoryService == null) {
            itemFactoryService = ServerManager.getApplicationContext().getBean(ItemFactoryService.class);
        }
        return itemFactoryService;
    }

    ItemFactory(int value, boolean account) {
        this.value = value;
        this.account = account;
    }

    public int getValue() {
        return value;
    }

    public boolean isAccount() {
        return account;
    }

    public List<Pair<Item, InventoryType>> loadItems(int id, boolean login) {
        if (value != 6) {
            return getItemFactoryService().loadItems(value, account, id, login);
        } else {
            return getItemFactoryService().loadItemsMerchant(value, id, login);
        }
    }

    public void saveItems(List<Pair<Item, InventoryType>> items, int id) {
        saveItems(items, null, id, null);
    }
    
    public void saveItems(List<Pair<Item, InventoryType>> items, int id, Set<InventoryType> targetTypes) {
        saveItems(items, null, id, targetTypes);
    }

    public void saveItems(List<Pair<Item, InventoryType>> items, List<Short> bundlesList, int id) {
        saveItems(items, bundlesList, id, null);
    }

    public void saveItems(List<Pair<Item, InventoryType>> items, List<Short> bundlesList, int id, Set<InventoryType> targetTypes) {
        Lock lock = locks[id % lockCount];
        lock.lock();
        try {
            if (value != 6) {
                getItemFactoryService().saveItems(value, account, items, id, targetTypes);
            } else {
                getItemFactoryService().saveItemsMerchant(value, items, bundlesList, id);
            }
        } finally {
            lock.unlock();
        }
    }

    public static List<Pair<Item, Integer>> loadEquippedItems(int id, boolean isAccount, boolean login) {
        return getItemFactoryService().loadEquippedItems(id, isAccount, login);
    }
}
