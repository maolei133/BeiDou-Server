# 任务脚本 - NextLevel 开发指南

## 1. 概述

本指南旨在介绍如何使用 **NextLevel** 语法模式来开发任务脚本 (`quest`)。通过利用 NextLevel 模式，您可以将传统上分离的任务开始 (`start`) 和结束 (`end`) 对话流程，统一到一套更清晰、更易于维护的函数路由中。

### 1.1. 核心优势

- **统一对话流程**: 无需在 `start` 和 `end` 函数中分别管理对话状态 (`status`)。
- **代码清晰**: 每个对话步骤都是一个独立的函数，逻辑一目了然。
- **易于维护**: 修改或增加对话步骤只需增删函数，无需改动复杂的 `if-else` 状态判断。
- **复用 `cm` API**: 可以直接使用所有 `NPCConversationManager` 提供的对话框 API。

### 1.2. 关键原理

任务脚本的交互对象 `qm` (`QuestActionManager`) 是 `NPCConversationManager` 的子类。这意味着 `qm` 对象继承了所有 `cm` 对象的方法，因此可以直接调用 `qm.sendNextLevel(...)`、`qm.getInputNumberLevel(...)` 等所有 NextLevel API。

---

## 2. 脚本结构与入口函数

任务脚本的文件名必须遵循 `[任务ID].js` 的格式，并存放在 `scripts/quest/` 目录下。

脚本包含两个固定的入口函数：

- **`start(mode, type, selection)`**: 当玩家**开始**或**进行中**点击任务时调用。
- **`end(mode, type, selection)`**: 当玩家**完成**任务条件后，点击任务时调用。

**参数说明**:
- `mode`: 任务状态 (`0`=未开始, `1`=进行中, `2`=已完成)。
- `type`: 对话类型 (`0`=点击, `1`=选择)。
- `selection`: 玩家的选择（通常用于 `type=1` 的情况）。

---

## 3. 开发范本

### 3.1. 简单任务示例

这是一个简单的任务，开始时给玩家一个道具，结束时收回并给予奖励。

```javascript
// scripts/quest/12345.js

// 任务相关的常量
const REQUIRED_ITEM = 4000000; // 需要的道具
const REWARD_MESO = 10000;     // 奖励金币

/**
 * 任务开始/进行中
 */
function start(mode, type, selection) {
    // mode: 0=未开始, 1=进行中
    if (mode === 0) { // 首次接受任务
        levelStartQuest();
    } else if (mode === 1) { // 任务进行中
        qm.sendOk("你还没找回我需要的道具呢，快去吧！");
        qm.dispose();
    } else { // 任务已完成 (mode === 2)
        qm.dispose(); // 理论上不会进入这里
    }
}

/**
 * 任务完成
 */
function end(mode, type, selection) {
    // mode: 1=进行中(已满足完成条件), 2=已完成
    if (mode === 1) { // 满足条件，准备完成任务
        levelCompleteQuest();
    } else if (mode === 2) { // 任务已经完成
        qm.sendOk("你已经完成过这个任务了。");
        qm.dispose();
    } else {
        qm.dispose();
    }
}

// =================================================
//          NextLevel 对话流程函数
// =================================================

/**
 * 开始任务的主流程
 */
function levelStartQuest() {
    qm.sendYesNoLevel("End", "AcceptQuest", "你好！我需要你帮我找一个#t" + REQUIRED_ITEM + "#，你能帮我吗？");
}

/**
 * 玩家接受任务
 */
function levelAcceptQuest() {
    // 强制开始任务
    qm.forceStartQuest(); 
    // 给予玩家任务道具（如果需要）
    // qm.gainItem(REQUIRED_ITEM, 1);
    qm.sendOkLevel("End", "太好了！找到后请再来找我。");
}

/**
 * 完成任务的主流程
 */
function levelCompleteQuest() {
    // 检查玩家是否真的有任务道具
    if (!qm.haveItem(REQUIRED_ITEM, 1)) {
        qm.sendOk("嗯？你好像还没有#t" + REQUIRED_ITEM + "#。");
        qm.dispose();
        return;
    }
    qm.sendYesNoLevel("End", "ConfirmComplete", "你真的找到了！要现在交给我吗？");
}

/**
 * 玩家确认完成任务
 */
function levelConfirmComplete() {
    // 收回任务道具
    qm.gainItem(REQUIRED_ITEM, -1);
    // 给予奖励
    qm.gainMeso(REWARD_MESO);
    qm.gainExp(500);
    // 强制完成任务
    qm.forceCompleteQuest();
    qm.sendOkLevel("End", "非常感谢！这是一点小小的谢礼。");
}

/**
 * 玩家选择 "否" 或关闭对话框
 */
function levelEnd() {
    qm.sendOk("如果你改变主意了，可以再来找我。");
    qm.dispose();
}

/**
 * 脚本结束时必须调用的函数
 * 在 NextLevel 模式中，通常在 levelEnd 或最终的对话步骤中调用
 */
function level() {
    qm.dispose();
}
```

### 3.2. 带选项奖励的任务示例

在这个示例中，玩家完成任务后可以选择不同的奖励。

```javascript
// ... start() 和 end() 函数同上 ...

/**
 * 完成任务的主流程
 */
function levelCompleteQuest() {
    var text = "感谢你的帮助！为了表示感谢，请从下面选择一个你喜欢的奖励：\r\n";
    text += "#L0#10个红色药水#l\r\n";
    text += "#L1#10个蓝色药水#l\r\n";
    text += "#L2#5000金币#l";
    // 使用 sendNextSelectLevel 将选择结果统一交给 levelProcessReward 处理
    qm.sendNextSelectLevel("ProcessReward", text);
}

/**
 * 处理玩家的奖励选择
 * @param {number} selection - 玩家选择的 #L 标签值
 */
function levelProcessReward(selection) {
    if (selection === 0) {
        qm.gainItem(2000000, 10);
        qm.sendOk("你获得了10个红色药水。");
    } else if (selection === 1) {
        qm.gainItem(2000001, 10);
        qm.sendOk("你获得了10个蓝色药水。");
    } else if (selection === 2) {
        qm.gainMeso(5000);
        qm.sendOk("你获得了5000金币。");
    }
    
    // 给予通用奖励并完成任务
    qm.gainExp(1000);
    qm.forceCompleteQuest();
    qm.dispose();
}

// ... 其他函数 ...
```
### 4.1 任务专用 API
| 方法签名 | 返回值 | 说明 |
| :--- | :--- | :--- |
| `qm.forceStartQuest([questId])` | `boolean` | 强制开始一个任务。 |
| `qm.forceCompleteQuest([questId])` | `boolean` | 强制完成一个任务。 |
| `qm.getQuest()` | `int` | 获取当前任务的 ID。 |

### 4.2 通用 API 参考

由于 `qm` 对象继承自 `cm`，它拥有所有 NPC 脚本的通用 API。关于所有可用方法的完整列表和详细说明，请查阅权威的 API 参考手册：

**[▶️ NextLevel 脚本 - 完整 API 参考手册](./NextLevel脚本开发指南.md)**
