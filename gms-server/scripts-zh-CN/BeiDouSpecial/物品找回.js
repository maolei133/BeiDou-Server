/**
 * 脚本名称：物品找回系统NPC
 * 功能：允许玩家找回近期出售给NPC或丢弃的物品
 * 作者：BeiDou Server
 */

const GameConfig = Java.type('org.gms.config.GameConfig');
const ItemRecoveryService = Java.type('org.gms.manager.ServerManager').getApplicationContext().getBean(Java.type('org.gms.service.ItemRecoveryService'));
const ItemInformationProvider = Java.type('org.gms.server.ItemInformationProvider').getInstance();
const DueyProcessor = Java.type('org.gms.client.processor.npc.DueyProcessor');
const SimpleDateFormat = Java.type('java.text.SimpleDateFormat');
const Date = Java.type('java.util.Date');
const ItemConstants = Java.type('org.gms.constants.inventory.ItemConstants');
const InventoryType = Java.type('org.gms.client.inventory.InventoryType');
const ItemConverter = Java.type('org.gms.util.ItemConverter');
// **新增**: 导入Java的JSON处理库和目标DTO类
const JSON_JAVA = Java.type('com.alibaba.fastjson2.JSON');
const ItemInfoRtnDTO = Java.type('org.gms.model.dto.ItemInfoRtnDTO');


var status = -1;
var selection = -1;
var recoverableItems = []; // 将存储 ItemRecoveryLogsDO 列表
var currentCategoryItems = []; // 将存储过滤后的 ItemRecoveryLogsDO
var selectedRecoveryLog = null; // 存储选中的 ItemRecoveryLogsDO
var selectedItemData = null; // 存储从log中获取的物品JSON数据(JS对象)
var selectedFee = null;

function start() {
    if (!GameConfig.getServerBoolean("item_recovery_enabled", true)) {
        cm.sendOk("物品找回系统当前未开启。");
        cm.dispose();
        return;
    }
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
        recoverableItems = ItemRecoveryService.getRecoverableItems(cm.getPlayer().getId());
        
        if (recoverableItems.isEmpty()) {
            cm.sendOkLevel("Main", "您目前没有可找回的物品。");
            return;
        }

        var categories = new java.util.ArrayList();
        for (var i = 0; i < recoverableItems.size(); i++) {
            var logEntry = recoverableItems.get(i);
            var type = ItemConstants.getInventoryType(logEntry.getItemId());
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
        ruleText += "5. 找回的物品将通过快递发送给您。";
        
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

    currentCategoryItems = [];
    var sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm");
    var sb = "请选择您要找回的物品：\r\n\r\n";
    var hasItem = false;

    for (var i = 0; i < recoverableItems.size(); i++) {
        var logEntry = recoverableItems.get(i);
        var itemId = logEntry.getItemId();
        
        if (ItemConstants.getInventoryType(itemId) != targetType) {
            continue;
        }

        currentCategoryItems.push(logEntry);
        hasItem = true;
        
        var itemData = JSON.parse(logEntry.getItemData());
        var itemIco = `#i${itemId}:#`;
        var itemName = ItemInformationProvider.getName(itemId);
        var time = sdf.format(new Date(logEntry.getDisposalTime()));
        var reason = logEntry.getDisposalType() == "SELL" ? "出售" : "丢弃";
        
        sb += `#L${currentCategoryItems.length - 1}# ${itemIco} #b${itemName}#k × #r${itemData.qty || 1}#k\r\n`;
        sb += `   丢失时间：${time}  [${reason}]#l\r\n`;
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

    selectedRecoveryLog = currentCategoryItems[selection];
    var jsonString = selectedRecoveryLog.getItemData();
    
    // 用于界面显示
    selectedItemData = JSON.parse(jsonString);
    
    var itemId = selectedRecoveryLog.getItemId();
    var itemName = ItemInformationProvider.getName(itemId);
    var quantity = selectedItemData.qty || 1;

    // **核心修正**: 
    // 1. 获取原始JSON字符串。
    // 2. 使用Java的JSON库将其直接反序列化为ItemInfoRtnDTO.class类型的Java对象。
    var itemDtoForJava = JSON_JAVA.parseObject(jsonString, ItemInfoRtnDTO.class);
    
    // 3. 将类型正确的Java DTO对象传递给ItemConverter。
    var itemForFeeCalc = ItemConverter.restoreItemFromDTO(itemId, itemDtoForJava);

    var fees = ItemRecoveryService.calculateRecoveryFee(itemForFeeCalc);
    selectedFee = fees;
    
    var sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm");
    var time = sdf.format(new Date(selectedRecoveryLog.getDisposalTime()));
    var reason = selectedRecoveryLog.getDisposalType() == "SELL" ? "出售" : "丢弃";
    
    var feeStr = "";
    var costType = GameConfig.getServerInt("item_recovery_cost_type", 0);
    
    if (costType == 0 || costType == 2) feeStr += fees[0] + " 金币 ";
    if (costType == 1 || costType == 2) feeStr += ` && ${fees[1]} 点券`;

    var detail = `#e#b[物品详细信息]#k#n\r\n\r\n`;
    detail += `#i${itemId}:# #r${itemName}#k\r\n`;
    detail += `丢失时间：${time}\r\n`;
    detail += `丢失原因：${reason}\r\n`;
    detail += `找回费用：#r${feeStr}#k\r\n`;
    detail += `------------------------------\r\n`;

    if (ItemConstants.getInventoryType(itemId) == InventoryType.EQUIP) {
        var equipData = selectedItemData; 
        
        var statMap = {
            "成长等级": "il", "成长经验": "exp", "力量": "s", "敏捷": "d", "智力": "i",
            "运气": "l", "HP": "h", "MP": "m", "攻击力": "wa", "魔法力": "ma",
            "物理防御": "wd", "魔法防御": "md", "命中率": "ac", "回避率": "av",
            "手技": "hd", "移动速度": "sp", "跳跃力": "jp", "已强化次数": "lv",
            "可升级次数": "us", "金锤子已用": "vc"
        };

        for (var name in statMap) {
            var key = statMap[name];
            var value = equipData[key];
            if (value > 0) {
                detail += name + "：" + value + "\r\n";
            }
        }
    } else {
        detail += `数量：${quantity}\r\n`;
    }

    detail += `\r\n#e是否确认找回该物品？#n`;
    
    cm.sendYesNoLevel("selectCategory", "confirmRecovery", detail);
}

function levelconfirmRecovery(selection) {
    var logId = selectedRecoveryLog.getId();
    
    try {
        ItemRecoveryService.recoverItem(cm.getClient(), logId);
        
        var itemId = selectedRecoveryLog.getItemId();
        var itemName = ItemInformationProvider.getName(itemId);
        var costType = GameConfig.getServerInt("item_recovery_cost_type", 0);
        var feeMsg = "";
        if (costType == 0 || costType == 2) feeMsg += selectedFee[0] + " 金币 ";
        if (costType == 1 || costType == 2) feeMsg += selectedFee[1] + " 点券";

        var msg = `成功找回 #i${itemId}:# #b${itemName}#k x${selectedItemData.qty || 1}，花费：#r${feeMsg}#k。物品已发送至快递。`;
        cm.getPlayer().dropMessage(6, `[找回系统] 成功找回  ${itemName}  x${selectedItemData.qty || 1}，花费：${feeMsg}。物品已发送至快递。`);
        
        cm.sendOkLevel("Main", msg);
        
    } catch (e) {
        cm.sendOkLevel("Main", "找回失败，请检查费用或背包空间。");
    }
}
