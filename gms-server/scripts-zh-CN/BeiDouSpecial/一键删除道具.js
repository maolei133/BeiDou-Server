/*
 * 脚本名称：一键删除道具
 * 功能：提供单个或批量删除背包道具的功能，增加安全确认和锁定道具保护。
 * 作者：BeiDou Server (修改 by @Magical-H 使唤的AI)
 */

var status;
var text;
var column = ["装备", "消耗", "设置", "其他", "商城"];
var sel; // 存储选择的背包栏 (1-5)
var itemPos; // 存储要操作的道具位置

// --- 批量删除配置 ---
var selectionState = {}; // 存储批量删除中道具的勾选状态 {position: boolean}
const CHECK_SYMBOL = "#fUI/Basic.img/CheckBox/1#"; // 已勾选的符号 (U057)
const UNCHECK_SYMBOL = "#fUI/Basic.img/CheckBox/0#"; // 未勾选的符号 (U056)
const LOCKED_SYMBOL = "#fUI/UIWindow.img/ItemProtector/Icon/0#"; // 锁定图标 (U155)
const CONFIRM_DELETE_OPTION = 998;
const CANCEL_DELETE_OPTION = 999;


// 导入Java类
const ItemConstants = Java.type('org.gms.constants.inventory.ItemConstants');

function start() {
    levelStart();
}

// 对话开始
function levelStart() {
    text = "#e#r欢迎使用道具删除功能#n#k\r\n\r\n请选择您要操作的背包栏：\r\n";
    for (let i = 1; i <= 5; i++) {
        text += `#L${i}#删除 #b${column[i - 1]}#k 栏的道具#l\r\n`;
    }
    cm.sendNextSelectLevel("ChooseInventory", text);
}

// 选择了背包栏
function levelChooseInventory(choose) {
    sel = choose;
    cm.sendSelectLevel("ChooseType", `您想如何删除 #b${column[sel - 1]}#k 栏的道具？\r\n#L1#单个删除指定道具#l\r\n#L2#批量删除(可勾选)#l\r\n`);
}

// -------------------- 单个删除逻辑 --------------------

// 选择了删除方式1：单个删除
function levelChooseType1() {
    text = "请选择您要删除的道具：\r\n\r\n";
    let inventory = cm.getInventory(sel);
    let items = inventory.list().toArray();
    let hasVal = false;

    for (const item of items) {
        if (item) {
            hasVal = true;
            let locked = (item.getFlag() & ItemConstants.LOCK) !== 0;
            text += `#L${item.getPosition()}##i${item.getItemId()}# #t${item.getItemId()}# × ${item.getQuantity()} ${locked ? LOCKED_SYMBOL : ""}#l\r\n`;
        }
    }

    if (!hasVal) {
        cm.sendOkLevel("Start", "您选择的背包栏下没有任何道具！");
        return;
    }
    cm.sendNextSelectLevel("ConfirmRemoveSingle", text);
}

// 单个删除：显示确认信息
function levelConfirmRemoveSingle(choose) {
    itemPos = choose;
    let inventory = cm.getInventory(sel);
    let item = inventory.getItem(itemPos);

    if (!item) {
        cm.sendOkLevel("ChooseType1", "找不到该物品，可能已被移动。");
        return;
    }

    if ((item.getFlag() & ItemConstants.LOCK) !== 0) {
        cm.sendOkLevel("ChooseType1", `该物品已被锁定 ${LOCKED_SYMBOL}，无法删除。`);
        return;
    }

    let confirmText = `#e#r请确认删除以下物品：#n#k\r\n\r\n`;
    confirmText += `#i${item.getItemId()}# #t${item.getItemId()}# × ${item.getQuantity()}\r\n\r\n`;

    if (sel === 1) { // 装备栏
        let equip = item;
        confirmText += "------------------------------\r\n";
        
        const stats = [
            { label: "力量", getter: "getStr" },
            { label: "敏捷", getter: "getDex" },
            { label: "智力", getter: "getInt" },
            { label: "运气", getter: "getLuk" },
            { label: "HP", getter: "getHp" },
            { label: "MP", getter: "getMp" },
            { label: "攻击力", getter: "getWatk" },
            { label: "魔法力", getter: "getMatk" },
            { label: "物理防御", getter: "getWdef" },
            { label: "魔法防御", getter: "getMdef" },
            { label: "命中值", getter: "getAcc" },
            { label: "回避值", getter: "getAvoid" },
            { label: "手技", getter: "getHands" },
            { label: "移动速度", getter: "getSpeed" },
            { label: "跳跃力", getter: "getJump" }
        ];

        for (const stat of stats) {
            const value = equip[stat.getter]();
            if (value > 0) {
                confirmText += `${stat.label}: +${value}\r\n`;
            }
        }

        confirmText += `可升级次数: ${equip.getUpgradeSlots()}\r\n`;
        confirmText += `已强化次数: ${equip.getLevel()}\r\n`;
    }

    confirmText += "\r\n#b此操作不可逆，是否确定删除？#k";
    cm.sendYesNoLevel("ChooseType1", "DoRemoveSingle", confirmText);
}

// 单个删除：执行操作
function levelDoRemoveSingle() {
    let item = cm.getInventory(sel).getItem(itemPos);
    if (!item) {
        cm.sendOkLevel("ChooseType1", "删除失败，找不到该物品。");
        return;
    }
    if ((item.getFlag() & ItemConstants.LOCK) !== 0) {
        cm.sendOkLevel("ChooseType1", `该物品已被锁定 ${LOCKED_SYMBOL}，无法删除。`);
        return;
    }
    cm.removeAllByInventorySlot(sel, itemPos);
    cm.sendOkLevel("ChooseType1", "删除成功！");
}


// -------------------- 批量删除逻辑 --------------------

// 选择了删除方式2：批量删除
function levelChooseType2() {
    selectionState = {}; // 重置勾选状态
    let inventory = cm.getInventory(sel);
    let items = inventory.list().toArray();
    let hasVal = false;

    for (const item of items) {
        if (item && (item.getFlag() & ItemConstants.LOCK) === 0) {
            hasVal = true;
            selectionState[item.getPosition()] = true; // 默认全部勾选
        }
    }

    if (!hasVal) {
        cm.sendOkLevel("Start", "该背包没有可供批量删除的（未锁定）道具。");
        return;
    }
    levelShowBulkDeleteList();
}

// 批量删除：显示可勾选的道具列表
function levelShowBulkDeleteList() {
    let text = `#e#L${CONFIRM_DELETE_OPTION}#[#b确定删除#k]#l    #L${CANCEL_DELETE_OPTION}#[#r取消操作#k]#l#n\r\n\r\n`;
    text += "\r\n".padStart(25,"——");
    text += `点击下方道具切换勾选状态：\r\n`;
    text += `${CHECK_SYMBOL} = 删除, ${UNCHECK_SYMBOL} = 保留, ${LOCKED_SYMBOL} = 锁定\r\n\r\n`;

    let inventory = cm.getInventory(sel);
    let items = inventory.list().toArray();

    for (const item of items) {
        if (item) {
            let pos = item.getPosition();
            let isLocked = (item.getFlag() & ItemConstants.LOCK) !== 0;

            if (isLocked) {
                text += `\r\n   \t${LOCKED_SYMBOL} #i${item.getItemId()}# #t${item.getItemId()}# × ${item.getQuantity()}\r\n`;
            } else {
                let symbol = selectionState[pos] ? CHECK_SYMBOL : UNCHECK_SYMBOL;
                text += `#L${pos}#${symbol} #i${item.getItemId()}# #t${item.getItemId()}# × ${item.getQuantity()}#l\r\n`;
            }
        }
    }
    text += "\r\n".padEnd(25,"——");
    text += "\r\n#e#L" + CONFIRM_DELETE_OPTION + "#[#b确定删除#k]#l    #L" + CANCEL_DELETE_OPTION + "#[#r取消操作#k]#l#n\r\n\r\n";
    cm.sendNextSelectLevel("ProcessBulkDelete", text);
}

// 批量删除：处理玩家在列表中的选择
function levelProcessBulkDelete(selection) {
    if (selection === CONFIRM_DELETE_OPTION) {
        let hasCheckedItem = false;
        for (let pos in selectionState) {
            if (selectionState[pos]) {
                hasCheckedItem = true;
                break;
            }
        }
        if (!hasCheckedItem) {
            cm.sendOkLevel("ShowBulkDeleteList", "您没有勾选任何需要删除的道具。");
            return;
        }
        let confirmText = `此操作将删除所有已勾选 (${CHECK_SYMBOL}) 的道具，且 #r#e不可逆#n#k！\r\n\r\n如果您确定要继续，请输入“#b我确认清空#k”进行最终确认。`;
        cm.getInputTextLevel("DoClear", confirmText);

    } else if (selection === CANCEL_DELETE_OPTION) {
        cm.sendOkLevel("Start", "操作已取消。");

    } else { // 玩家点击了某个道具，切换其勾选状态
        if (selectionState.hasOwnProperty(selection)) {
            selectionState[selection] = !selectionState[selection];
        }
        levelShowBulkDeleteList(); // 刷新列表
    }
}

// 批量删除：执行最终操作
function levelDoClear(inputText) {
    if (inputText !== "我确认清空") {
        cm.sendOkLevel("Start", "输入错误，操作已取消。");
        return;
    }

    let deletedCount = 0;
    // 删除勾选的物品
    for (let pos in selectionState) {
        if (selectionState[pos]) {
            cm.removeAllByInventorySlot(sel, parseInt(pos));
            deletedCount++;
        }
    }

    cm.dropMessage(5, "批量删除了 " + deletedCount + " 个道具。")
    let resultText = `批量删除操作完成！\r\n\r\n成功删除 #b${deletedCount}#k 个道具。\r\n`;
    cm.sendOkLevel("Start", resultText);
}
