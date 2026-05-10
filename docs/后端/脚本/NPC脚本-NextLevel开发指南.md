# NPC 脚本 - NextLevel 实战开发指南

## 1. 概述

本指南旨在通过一系列实用的代码范本，向您展示如何使用 **NextLevel** 模式来编写常见的 NPC 功能。

**重要提示：在本项目中，所有 NPC 脚本【必须】使用 NextLevel 模式进行开发。**

---

## 2. 基础结构

所有 NPC 脚本都共享一个基础结构：

```javascript
/**
 * 脚本入口函数，所有逻辑从这里开始。
 */
function start() {
    // 通常在这里调用主逻辑函数
    levelMain(); 
}

/**
 * 脚本结束函数，用于处理对话中断或最终的清理。
 * 在 NextLevel 模式中，通常只包含 cm.dispose()。
 */
function level() {
    cm.dispose();
}

/**
 * 主逻辑函数，对话的起点。
 */
function levelMain() {
    // ... 你的第一个对话框 ...
}

// ... 其他 level<MethodName> 函数 ...
```

---

## 3. 实战范本

### 范本1：简单的对话流程

展示了 `sendYesNoLevel` 和 `sendOkLevel` 的基本用法。

```javascript
function levelMain() {
    cm.sendYesNoLevel("End", "Step2", "你好，冒险家！想听我讲个故事吗？");
}

function levelStep2() {
    cm.sendOkLevel("End", "从前有座山，山里有座庙...");
}

function levelEnd() {
    cm.sendOk("好吧，那下次再聊！");
    cm.dispose();
}
```

### 范本2：多功能 NPC (使用 `sendNextSelectLevel`)

这是最常用的模式，用于创建带有多个选项的 NPC。

```javascript
function levelMain() {
    let text = "你好，" + cm.getPlayer().getName() + "！有什么可以帮你的吗？\r\n";
    text += "#L0#我想去万神殿#l\r\n";
    text += "#L1#我想打开仓库#l\r\n";
    text += "#L2#我想购买一些药水#l\r\n";
    text += "#L3#查看我的个人信息#l";
    
    // 所有选项都会跳转到 levelProcessSelection 函数
    cm.sendNextSelectLevel("ProcessSelection", text);
}

/**
 * 统一处理玩家的选择
 * @param {number} selection - 玩家选择的 #L 标签的 value
 */
function levelProcessSelection(selection) {
    switch (selection) {
        case 0: // 传送
            cm.sendOk("好的，我马上送你过去。");
            cm.warp(400000000, 0);
            cm.dispose();
            break;
        case 1: // 打开仓库
            cm.sendStorage(); // 这是终端操作，会自动 dispose
            break;
        case 2: // 打开商店
            cm.openShop(9010000); // 这是终端操作，会自动 dispose
            break;
        case 3: // 显示信息
            const player = cm.getPlayer();
            const info = `名字: ${player.getName()}\r\n等级: ${player.getLevel()}\r\n职业: ${player.getJob().name()}`;
            cm.sendOkLevel("End", info);
            break;
        default:
            cm.dispose();
            break;
    }
}

function levelEnd() {
    cm.sendOk("感谢你的使用！");
    cm.dispose();
}
```

### 范本3：用户输入 (购买物品)

展示了如何获取用户输入的数字，并进行逻辑处理。

```javascript
const APPLE_ID = 2000000;
const APPLE_PRICE = 10;

function levelMain() {
    cm.getInputNumberLevel("BuyApples", `一个苹果售价 ${APPLE_PRICE} 金币，你要买多少个？`, 1, 1, 100);
}

function levelBuyApples(quantity) {
    if (quantity <= 0) {
        cm.sendOkLevel("Main", "购买数量必须大于0。");
        return;
    }
    
    const totalCost = quantity * APPLE_PRICE;
    
    if (cm.getMeso() < totalCost) {
        cm.sendOkLevel("Main", "你的金币不足！需要 " + totalCost + " 金币。");
        return;
    }
    
    if (!cm.canHold(APPLE_ID, quantity)) {
        cm.sendOkLevel("Main", "你的背包空间不足。");
        return;
    }
    
    cm.gainMeso(-totalCost);
    cm.gainItem(APPLE_ID, quantity);
    cm.sendOkLevel("End", `你成功购买了 ${quantity} 个苹果！`);
}

function levelEnd() {
    cm.dispose();
}
```

### 范本4：与事件脚本交互 (启动副本)

展示了 NPC 如何作为副本入口。

```javascript
const EVENT_NAME = "MyPartyQuest"; // 对应 event/MyPartyQuest.js

function levelMain() {
    cm.sendYesNoLevel("End", "CheckConditions", "准备好开始组队任务了吗？");
}

function levelCheckConditions() {
    // 检查1：是否为队长
    if (!cm.isLeader()) {
        cm.sendOk("请让你的队长来和我说话。");
        cm.dispose();
        return;
    }
    
    // 检查2：队伍人数
    const party = cm.getParty();
    if (party == null || party.getMembers().size() < 2) {
        cm.sendOk("你需要一个至少2人的队伍才能开始。");
        cm.dispose();
        return;
    }
    
    // 获取事件管理器
    const em = cm.getEventManager(EVENT_NAME);
    if (em == null) {
        cm.sendOk("当前任务正在维护中，请稍后再试。");
        cm.dispose();
        return;
    }
    
    // 启动事件实例
    // em.startInstance(party, map) 会自动调用 MyPartyQuest.js 中的 setup() 函数
    const started = em.startInstance(party, cm.getMap());
    
    if (!started) {
        cm.sendOk("当前频道任务繁忙，或你的队伍成员不满足条件，请稍后再试。");
    }
    
    // 无论成功与否，NPC 的对话都结束了
    cm.dispose();
}

function levelEnd() {
    cm.sendOk("准备好了再来找我吧。");
    cm.dispose();
}
```

---

## 4. 完整 API 参考

本指南专注于实战范本。关于 `cm` 对象所有可用方法的完整列表和详细说明，请查阅权威的 API 参考手册：

**[▶️ NextLevel 脚本 - 完整 API 参考手册](./NextLevel脚本开发指南.md)**
