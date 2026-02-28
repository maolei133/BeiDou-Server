/**
 * 脚本名称：物品找回系统NPC
 * 功能：允许玩家找回近期出售给NPC或丢弃的物品
 * 作者：BeiDou Server
 */

const GameConfig = Java.type('org.gms.config.GameConfig');
const ItemRecoveryService = Java.type('org.gms.manager.ServerManager').getApplicationContext().getBean(Java.type('org.gms.service.ItemRecoveryService'));
const ItemInformationProvider = Java.type('org.gms.server.ItemInformationProvider').getInstance();
const DueyProcessor = Java.type('org.gms.client.processor.npc.DueyProcessor');
const ItemInfoRtnDTO = Java.type('org.gms.model.dto.ItemInfoRtnDTO');
const ObjectMapper = Java.type('com.fasterxml.jackson.databind.ObjectMapper');
const SimpleDateFormat = Java.type('java.text.SimpleDateFormat');
const Date = Java.type('java.util.Date');
const ItemConstants = Java.type('org.gms.constants.inventory.ItemConstants');
const InventoryType = Java.type('org.gms.client.inventory.InventoryType');

var status = -1;
var selection = -1;
var recoverableItems = [];
var currentCategoryItems = [];
var selectedLog = null;
var selectedItem = null;
var selectedFee = null;

function start() {
    levelMain();
}

function level() {
    cm.dispose();
}

function levelMain() {
    cm.sendNextSelectLevel("showRecoveryMenu", "您好，我是失物招领管理员。\r\n如果您不小心卖错或丢弃了重要的物品，我或许可以帮您找回。\r\n\r\n#b#L0#我想找回物品#l\r\n#L1#了解找回规则#l");
}

function levelshowRecoveryMenu(selection) {
    if (selection == 0) {
        // 动态生成分类
        recoverableItems = ItemRecoveryService.getRecoverableItems(cm.getPlayer().getId());
        
        if (recoverableItems.isEmpty()) {
            cm.sendOkLevel("Main", "您目前没有可找回的物品。");
            return;
        }

        var categories = new java.util.ArrayList();
        for (var i = 0; i < recoverableItems.size(); i++) {
            var log = recoverableItems.get(i);
            var type = ItemConstants.getInventoryType(log.getItemId());
            if (!categories.contains(type)) {
                categories.add(type);
            }
        }

        var text = "请选择要找回的物品类型：\r\n\r\n";
        if (categories.contains(InventoryType.EQUIP)) text += "#b#L1#装备#l\r\n";
        if (categories.contains(InventoryType.USE)) text += "#L2#消耗#l\r\n";
        if (categories.contains(InventoryType.SETUP)) text += "#L3#设置#l\r\n";
        if (categories.contains(InventoryType.ETC)) text += "#L4#其它#l\r\n";
        if (categories.contains(InventoryType.CASH)) text += "#L5#现金#l";
        
        cm.sendNextSelectLevel("selectCategory", text);
    } else if (selection == 1) {
        var ruleText = "#e#b[物品找回规则]#k#n\r\n\r\n";
        ruleText += "1. 只能找回#r最近" + GameConfig.getServerInt("item_recovery_hours", 24) + "小时内#k出售给商店或丢弃的物品。\r\n";
        ruleText += "2. 找回物品需要支付一定的手续费（金币或点券）。\r\n";
        ruleText += "3. 手续费 = 基础费用 + 物品评估价值 * 倍率。\r\n";
        ruleText += "4. 普通垃圾物品（如怪物掉落的杂物、普通药水）无法找回。\r\n";
        ruleText += "5. 请确保背包有足够的空间接收找回的物品。";
        
        cm.sendOkLevel("Main", ruleText);
    }
}

function levelselectCategory(selection) {
    var targetType;
    switch(selection) {
        case 1: targetType = InventoryType.EQUIP; break;
        case 2: targetType = InventoryType.USE; break;
        case 3: targetType = InventoryType.SETUP; break;
        case 4: targetType = InventoryType.ETC; break;
        case 5: targetType = InventoryType.CASH; break;
        default: cm.dispose(); return;
    }

    // recoverableItems 已经在 levelshowRecoveryMenu 中获取了，无需再次获取
    currentCategoryItems = [];
    var objectMapper = new ObjectMapper();
    var sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm");

    var sb = "请选择您要找回的物品：\r\n\r\n";
    var hasItem = false;

    for (var i = 0; i < recoverableItems.size(); i++) {
        var log = recoverableItems.get(i);
        var itemId = log.getItemId();
        
        // 过滤类型
        if (ItemConstants.getInventoryType(itemId) != targetType) {
            continue;
        }

        // 尝试解析物品以获取更多信息（如果需要）
        var item = null;
        try {
            var itemDTO = objectMapper.readValue(log.getItemData(), ItemInfoRtnDTO.class);
            item = DueyProcessor.restoreItemFromDTO(itemDTO);
        } catch (e) {
            continue;
        }

        currentCategoryItems.push({log: log, item: item});
        hasItem = true;
        
        var itemIco = `#i${itemId}:#`;
        var itemName = ItemInformationProvider.getName(itemId);
        var time = sdf.format(new Date(log.getDisposalTime()));
        var reason = log.getDisposalType() == "SELL" ? "出售" : "丢弃";
        
        sb += `#L${currentCategoryItems.length - 1}# ${itemIco} #b${itemName}#k\r\n`;
        sb += `   丢失时间：${time} (${reason})#l\r\n`;
    }

    if (!hasItem) {
        cm.sendOkLevel("Main", "该分类下没有可找回的物品。");
    } else {
        cm.sendNextSelectLevel("showItemDetail", sb);
    }
}

function levelshowItemDetail(selection) {
    if (selection < 0 || selection >= currentCategoryItems.length) {
        cm.dispose();
        return;
    }

    var data = currentCategoryItems[selection];
    selectedLog = data.log;
    selectedItem = data.item;
    
    var sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm");
    var time = sdf.format(new Date(selectedLog.getDisposalTime()));
    var reason = selectedLog.getDisposalType() == "SELL" ? "出售" : "丢弃";
    var itemId = selectedItem.getItemId();
    var itemName = ItemInformationProvider.getName(itemId);

    // 计算费用
    var fees = ItemRecoveryService.calculateRecoveryFee(selectedItem);
    selectedFee = fees;
    
    var feeStr = "";
    var costType = GameConfig.getServerInt("item_recovery_cost_type", 0);
    
    // 详细费用计算展示
    var baseMeso = GameConfig.getServerLong("item_recovery_base_fee_meso", 50000);
    var baseNx = GameConfig.getServerLong("item_recovery_base_fee_nx", 0);
    var rate = GameConfig.getServerDouble("item_recovery_valuation_rate", 1.5);
    
    var itemPrice = fees[0] - baseMeso; // 估算出的物品价值部分费用
    
    if (costType == 0 || costType == 2) {
        feeStr += fees[0] + " 金币";
        if (itemPrice > 0) {
            feeStr += " (基础:" + baseMeso + " + 估值:" + itemPrice + ")";
        }
        feeStr += " ";
    }
    if (costType == 1 || costType == 2) {
        feeStr += fees[1] + " 点券";
        if (baseNx > 0) {
             feeStr += " (基础:" + baseNx + ")";
        }
    }

    var detail = `#e#b[物品详细信息]#k#n\r\n\r\n`;
    detail += `#i${itemId}:# #r${itemName}#k\r\n`;
    detail += `丢失时间：${time}\r\n`;
    detail += `丢失原因：${reason}\r\n`;
    detail += `找回费用：#r${feeStr}#k\r\n`;
    detail += `------------------------------\r\n`;

    // 显示装备详细属性
    if (ItemConstants.getInventoryType(itemId) == InventoryType.EQUIP) {
        var equip = selectedItem; 
        
        // 定义属性映射：显示名称 -> 方法名
        var statMap = {
            "等级": "getItemLevel",
            "经验": "getItemExp",
            "力量": "getStr",
            "敏捷": "getDex",
            "智力": "getInt",
            "运气": "getLuk",
            "HP": "getHp",
            "MP": "getMp",
            "攻击力": "getWatk",
            "魔法力": "getMatk",
            "物理防御": "getWdef",
            "魔法防御": "getMdef",
            "命中率": "getAcc",
            "回避率": "getAvoid",
            "手技": "getHands",
            "移动速度": "getSpeed",
            "跳跃力": "getJump",
            "升级次数": "getLevel",
            "可升级次数": "getUpgradeSlots",
            "金锤子已强化次数": "getVicious"
        };

        for (var name in statMap) {
            var method = statMap[name];
            // 动态调用方法
            var value = equip[method](); 
            if (value > 0) {
                detail += name + "：" + value + "\r\n";
            }
        }
    } else {
        detail += `数量：${selectedItem.getQuantity()}\r\n`;
    }

    detail += `\r\n#e是否确认找回该物品？#n`;
    
    cm.sendYesNoLevel("selectCategory", "confirmRecovery", detail);
}

function levelconfirmRecovery(selection) {
    // 再次检查费用（虽然服务端会检查，但前端也做个预判更好，或者直接调用服务端）
    // 这里直接调用服务端逻辑
    try {
        ItemRecoveryService.recoverItem(cm.getClient(), selectedLog.getId());
        
        // 构造成功提示信息
        var itemId = selectedItem.getItemId();
        var itemName = ItemInformationProvider.getName(itemId);
        var costType = GameConfig.getServerInt("item_recovery_cost_type", 0);
        var feeMsg = "";
        if (costType == 0 || costType == 2) feeMsg += selectedFee[0] + " 金币 ";
        if (costType == 1 || costType == 2) feeMsg += selectedFee[1] + " 点券";

        var msg = `成功找回 #i${itemId}:# #b${itemName}#k x${selectedItem.getQuantity() || 1}，花费：#r${feeMsg}#k。物品已发送至快递。`;
        cm.getPlayer().dropMessage(6, `[找回系统] 成功找回  ${itemName}  x${selectedItem.getQuantity() || 1}，花费：${feeMsg}。物品已发送至快递。`);
        
        cm.sendOkLevel("Main", msg);
        
    } catch (e) {
        cm.sendOkLevel("Main", "找回失败，请检查费用或背包空间。");
    }
}
