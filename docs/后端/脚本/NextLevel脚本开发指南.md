# NextLevel 脚本 - 完整开发指南 (v2.2)

## 1. 概述

本指南是为 NPC 和任务脚本开发者准备的**一站式参考手册**。它首先会介绍 **NextLevel** 脚本模式的原理、优势以及与传统模式的对比，然后提供一份 `cm` (`NPCConversationManager`) 和 `qm` (`QuestActionManager`) 对象的**完整 API 列表**作为速查手册。

---

## 2. NextLevel 模式：核心概念与优势

### 2.1 什么是 NextLevel？

NextLevel 是一种基于**方法路由**的脚本编写模式，旨在替代传统的 `status` 状态机模式。在传统模式中，开发者需要手动维护一个 `status` 变量，并通过大量的 `if-else` 或 `switch` 语句来控制对话流程，这使得代码难以阅读和维护。

NextLevel 模式通过将每个对话步骤封装成一个独立的函数，并使用特定的 API 来“路由”到下一个函数，从而解决了这个问题。

- **入口函数**：`start()`，所有脚本的起点。
- **路由规则**：通过 `cm.xxxLevel("NextMethodName", ...)` 指定用户操作后要执行的下一个函数名。
- **函数命名**：所有被路由的函数，其名称**必须**以 `level` 开头。例如，`cm.sendNextLevel("Step2", ...)` 将会调用 `function levelStep2() {}`。
- **结束对话**: 在对话流程的终点，**必须**调用 `cm.dispose()` 来结束会话并释放资源。

### 2.2 为什么必须使用 NextLevel？

1.  **告别 `status`**：无需手动管理和递增 `status` 变量，代码更简洁。
2.  **流程可视化**：通过查看 `...Level` 方法的参数和被调用的函数名，可以清晰地追踪对话的流转路径。
3.  **逻辑隔离**：每个对话步骤都是一个独立的函数，职责单一，易于复用、测试和修改。
4.  **状态安全**：框架层自动管理上下文，有效减少因 `status` 状态错乱导致的脚本卡死或逻辑错误问题。

---

## 3. NextLevel 对话流程 API

这类 API 是 NextLevel 模式的核心，专门用于构建对话框和控制脚本流程。

### 3.1 新旧API对照参考

| 传统 API (status模式) | NextLevel API | 说明 |
| :--- | :--- | :--- |
| `cm.sendNext(text)` | `cm.sendNextLevel("Method", text, [spk])` | 显示“下一步”按钮，点击后跳转到 `levelMethod()` |
| `cm.sendPrev(text)` | `cm.sendLastLevel("Method", text, [spk])` | 显示“上一步”按钮，点击后跳转到 `levelMethod()` |
| `cm.sendNextPrev(text)` | `cm.sendLastNextLevel("LastM", "NextM", text, [spk])` | 显示“上一步”和“下一步”按钮 |
| `cm.sendOk(text)` | `cm.sendOkLevel("Method", text, [spk])` | 显示“确定”按钮，点击后跳转到 `levelMethod()` |
| `cm.sendYesNo(text)` | `cm.sendYesNoLevel("NoM", "YesM", text, [spk])` | 显示“是/否”按钮，分别跳转到不同方法 |
| `cm.sendAcceptDecline(text)` | `cm.sendAcceptDeclineLevel("DeclineM", "AcceptM", text, [spk])` | 显示“接受/拒绝”按钮 |
| `cm.sendSimple(text)` | `cm.sendNextSelectLevel("Method", text, [spk])` | **(推荐)** 选项菜单，选择后统一跳转到 `levelMethod(selection)` |
| `cm.sendSimple(text)` | `cm.sendSelectLevel("Prefix", text, [spk])` | 选项菜单，根据 `Prefix + selection` 自动路由到不同方法 |
| `cm.sendGetNumber(...)` | `cm.getInputNumberLevel("Method", ...)` | 获取数字输入，输入后跳转到 `levelMethod(input)` |
| `cm.sendGetText(...)` | `cm.getInputTextLevel("Method", ...)` | 获取文本输入，输入后跳转到 `levelMethod(text)` |

*`[spk]` 代表可选的 `speaker` 参数。*

### 3.2 对话流程 API 详解

| 方法签名 | 说明 |
| :--- | :--- |
| `cm.sendNextLevel(next, text, [spk])` | 显示“下一步”按钮，点击后调用 `level<next>()`。 |
| `cm.sendLastLevel(last, text, [spk])` | 显示“上一步”按钮，点击后调用 `level<last>()`。 |
| `cm.sendLastNextLevel(last, next, text, [spk])` | 同时显示“上一步”和“下一步”按钮。 |
| `cm.sendOkLevel(next, text, [spk])` | 显示“确定”按钮，点击后调用 `level<next>()`。 |
| `cm.sendYesNoLevel(no, yes, text, [spk])` | 显示“是/否”按钮，分别调用 `level<no>()` 和 `level<yes>()`。 |
| `cm.sendAcceptDeclineLevel(decline, accept, text, [spk])` | 显示“接受/拒绝”按钮。 |
| `cm.sendNextSelectLevel(next, text, [spk])` | **(推荐)** 显示选项列表，选择后统一调用 `level<next>(selection)`。 |
| `cm.sendSelectLevel(prefix, text, [spk])` | 显示选项列表，选择 `#L<N>#` 后调用 `level<prefix><N>()`。 |
| `cm.getInputTextLevel(next, text, [def, spk])` | 获取文本输入，输入后调用 `level<next>(text)`。 |
| `cm.getInputNumberLevel(next, text, def, min, max, [spk])` | 获取数字输入，输入后调用 `level<next>(number)`。 |

---

## 4. 通用 API 完整参考

除了对话流程 API，`cm` 和 `qm` 对象还提供了大量通用的方法来执行游戏逻辑。

### 4.1 玩家 (Player)

| 方法签名 | 返回值 | 说明 |
| :--- | :--- | :--- |
| `cm.getPlayer()` / `cm.getChar()` | `Character` | 获取当前玩家的角色对象。 |
| `cm.getName()` | `String` | 获取玩家的名字。 |
| `cm.getGender()` | `int` | 获取玩家的性别 (0=男, 1=女)。 |
| `cm.getLevel()` | `int` | 获取玩家的等级。 |
| `cm.getJob()` | `Job` | 获取玩家的职业对象。 |
| `cm.getJobId()` | `int` | 获取玩家的职业ID。 |
| `cm.getJobName(id)` | `String` | 根据职业 ID 获取职业名称。 |
| `cm.changeJob(jobId)` | `void` | 改变玩家的职业。 |
| `cm.getMeso()` | `int` | 获取玩家的金币数量。 |
| `cm.gainMeso(amount)` | `void` | 给予或扣除玩家的金币。 |
| `cm.getExp()` | `long` | 获取玩家的经验值。 |
| `cm.gainExp(amount)` | `void` | 给予玩家经验值。 |
| `cm.gainFame(delta)` | `void` | 增加或减少玩家的人气。 |
| `cm.resetStats()` | `void` | 重置玩家的能力值 (用于能力值重置卷轴)。 |
| `cm.setHair(hairId)` | `void` | 设置玩家的发型。 |
| `cm.setFace(faceId)` | `void` | 设置玩家的脸型。 |
| `cm.setSkin(skinId)` | `void` | 设置玩家的肤色。 |
| `cm.getOnlineTime()` | `int` | 获取当前账户角色的在线时间（分钟）。 |

### 4.2 物品 (Item)

| 方法签名 | 返回值 | 说明 |
| :--- | :--- | :--- |
| `cm.haveItem(itemId, [quantity, checkEquipped])` | `boolean` | 检查玩家是否拥有指定数量的道具。 |
| `cm.canHold(itemId, [quantity])` | `boolean` | 检查玩家背包是否能容纳指定数量的道具。 |
| `cm.gainItem(id, quantity, [random, show, expires, ...])` | `Item` | 给予或扣除玩家的道具。`quantity` 为负数时扣除。 |
| `cm.gainEquip(equip)` | `void` | 给予玩家一个已实例化的装备对象。 |
| `cm.itemQuantity(itemId)` | `int` | 获取玩家背包中指定道具的数量。 |
| `cm.getItemEffect(itemId)` | `StatEffect` | 获取消耗品的效果对象。 |
| `cm.itemExists(itemId)` | `boolean` | 检查指定 ID 的物品是否存在于游戏中。 |
| `cm.removeAll(itemId)` | `void` | 移除玩家身上所有指定ID的物品（包括背包和已装备）。 |
| `cm.removeAllByInventory(invType)` | `void` | 清空指定类型的背包。 |
| `cm.getInventory(type)` | `Inventory` | 获取指定类型的背包实例。 |

### 4.3 地图与传送 (Map & Warp)

| 方法签名 | 返回值 | 说明 |
| :--- | :--- | :--- |
| `cm.getMap()` | `MapleMap` | 获取玩家当前所在的地图对象。 |
| `cm.getMapId()` | `int` | 获取当前地图的 ID。 |
| `cm.warp(mapId, [portal])` | `void` | 将玩家传送到指定地图的指定传送点 (ID 或名称)。 |
| `cm.warpParty(mapId, ...)` | `void` | 传送整个队伍。有多个重载方法。 |
| `cm.warpMap(mapId)` | `void` | 传送当前地图的所有人。 |
| `cm.resetMap(mapId)` | `void` | 重置指定地图的所有反应堆和怪物。 |
| `cm.mapMessage(type, message)` | `void` | 向当前地图的所有玩家广播一条消息。 |
| `cm.playEffect(effectPath)` | `void` | 在玩家身上播放一个效果动画。 |
| `cm.playSound(soundPath)` | `void` | 为玩家播放一个声音。 |
| `cm.showEffect(effectPath)` | `void` | 在当前地图播放一个环境效果。 |
| `cm.mapClock(seconds)` | `void` | 在当前地图显示一个倒计时时钟。 |
| `cm.spawnMonster(id, qty, x, y)` | `void` | 在指定坐标召唤怪物。 |
| `cm.spawnNpc(npcId, x, y)` | `void` | 在指定坐标召唤NPC。 |

### 4.4 任务 (Quest)

| 方法签名 | 返回值 | 说明 |
| :--- | :--- | :--- |
| `cm.isQuestStarted(questId)` | `boolean` | 检查任务是否已开始 (等同于 `isQuestActive`)。 |
| `cm.isQuestCompleted(questId)` | `boolean` | 检查任务是否已完成。 |
| `cm.getQuestStatus(questId)` | `int` | 获取任务的状态 (0=未开始, 1=进行中, 2=已完成)。 |
| `cm.startQuest(questId, [npcId])` | `boolean` | 开始一个任务。 |
| `cm.completeQuest(questId, [npcId])` | `boolean` | 完成一个任务。 |
| `cm.forceStartQuest(questId, [npcId])` | `boolean` | 强制开始一个任务。 |
| `cm.forceCompleteQuest(questId, [npcId])` | `boolean` | 强制完成一个任务。 |
| `cm.getQuestProgress(id, [infoNumber])` | `String` | 获取任务进度字符串。 |
| `cm.setQuestProgress(id, [infoNumber], progress)` | `void` | 设置任务进度。 |

### 4.5 技能 (Skill)

| 方法签名 | 返回值 | 说明 |
| :--- | :--- | :--- |
| `cm.getSkillLevel(skillId)` | `int` | 获取玩家的技能等级。 |
| `cm.teachSkill(skillId, level, [masterlevel, expiration])` | `void` | 教予玩家技能。 |
| `cm.maxMastery()` | `void` | 将所有技能的熟练度提升到最大。 |
| `cm.getAvailableMasteryBooks()` | `Object[]` | 获取当前玩家可用的能力手册列表。 |
| `cm.getAvailableSkillBooks()` | `Object[]` | 获取当前玩家可用的技能书列表。 |

### 4.6 队伍 (Party) & 远征队 (Expedition)

| 方法签名 | 返回值 | 说明 |
| :--- | :--- | :--- |
| `cm.getParty()` | `Party` | 获取玩家所在的队伍对象。 |
| `cm.isLeader()` | `boolean` | 检查玩家是否为队长。 |
| `cm.partyMembersInMap()` | `int` | 获取当前地图内，与玩家同队伍的成员数量。 |
| `cm.createExpedition(type, ...)` | `int` | 创建一个远征队。 |
| `cm.getExpedition(type)` | `Expedition` | 获取指定类型的远征队。 |

### 4.7 公会 (Guild) & 联盟 (Alliance)

| 方法签名 | 返回值 | 说明 |
| :--- | :--- | :--- |
| `cm.getGuild()` | `Guild` | 获取玩家所在的公会对象。 |
| `cm.isGuildLeader()` | `boolean` | 检查玩家是否为公会会长。 |
| `cm.displayGuildRanks()` | `void` | 显示公会排名。 |
| `cm.guildMessage(type, message)` | `void` | 向公会成员广播消息。 |
| `cm.createAlliance(name)` | `Alliance` | 创建一个联盟。 |
| `cm.upgradeAlliance()` | `void` | 升级联盟（增加容量）。 |
| `cm.disbandAlliance(allianceId)` | `void` | 解散联盟。 |

### 4.8 UI 与交互

| 方法签名 | 返回值 | 说明 |
| :--- | :--- | :--- |
| `cm.openShop(shopId)` | `void` | 为玩家打开一个商店。这是一个**终端操作**。 |
| `cm.sendStorage()` | `void` | 为玩家打开仓库。这是一个**终端操作**。 |
| `cm.openNpc(npcId)` | `void` | 强制与一个 NPC 开始对话。 |
| `cm.openNpc(npcId, script)` | `void` | 强制与一个 NPC 开始对话，并指定运行的脚本。 |
| `cm.sendDimensionalMirror(text)` | `void` | 打开次元之镜。 |
| `cm.sendStyle(text, styles)` | `void` | **(传统API)** 显示美发/美瞳选择对话框。`styles` 是一个包含皮肤或发型 ID 的整数数组。**注意**：这是一个传统API，不会自动路由，需谨慎使用。 |
| `cm.playerMessage(type, message)` | `void` | 向玩家发送指定类型的提示消息。 |
| `cm.dispose()` | `void` | **【重要】** 结束脚本会话，释放资源。 |

### 4.9 扩展值 (Extend Value)

用于在数据库中为角色或账号持久化存储自定义数据。

| 方法签名 | 返回值 | 说明 |
| :--- | :--- | :--- |
| `cm.getCharacterExtendValue(name, [isDaily])` | `String` | 获取角色扩展值（可指定是否为每日/每周）。 |
| `cm.getAccountExtendValue(name, [isDaily])` | `String` | 获取账号扩展值（可指定是否为每日/每周）。 |
| `cm.saveOrUpdateCharacterExtendValue(name, value, [isDaily])` | `void` | 保存或更新角色扩展值。 |
| `cm.saveOrUpdateAccountExtendValue(name, value, [isDaily])` | `void` | 保存或更新账号扩展值。 |

### 4.10 其他

| 方法签名 | 返回值 | 说明 |
| :--- | :--- | :--- |
| `cm.getEventManager(eventName)` | `EventManager` | 获取指定名称的事件管理器，用于启动副本等。 |
| `cm.getNpc()` | `int` | 获取当前 NPC 的 ID。 |
| `cm.getClient()` | `Client` | 获取客户端对象。 |
| `cm.getCurrentTime()` | `long` | 获取服务器当前时间戳。 |
| `cm.doGachapon()` | `void` | 执行一次扭蛋机操作。 |
| `cm.hasMerchant()` | `boolean` | 检查玩家是否有雇佣商人。 |
| `cm.showFredrick()` | `void` | 显示弗兰德里[9030000]（雇佣商人管理员）的物品取回界面。 |
