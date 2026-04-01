# NextLevel 脚本开发指南 (v2.2)

NextLevel 是一种基于方法路由的 NPC 脚本编写模式，旨在替代传统的 `status` 状态机模式。它通过方法名直接映射对话流程，使代码结构更清晰、逻辑更易维护。

**所有 NextLevel 相关的 API 均定义在 `NPCConversationManager.java` 类中。**
如果本指南未覆盖您需要的功能，或您想深入了解其实现原理，建议直接查阅该文件：
[点击跳转到 NPCConversationManager.java](../src/main/java/org/gms/scripting/npc/NPCConversationManager.java)

---

## 1. 核心概念

在 NextLevel 模式中，每个对话步骤都对应脚本中的一个函数（Function）。
- **入口函数**：`start()`，通常在此函数中调用第一个业务逻辑函数。
- **路由规则**：通过 `cm.xxxLevel("NextMethodName", ...)` 指定用户操作后要执行的下一个函数名。
- **函数命名**：所有被路由的函数，其名称必须以 `level` 开头。例如，`cm.sendNextLevel("Step2", ...)` 将会调用 `function levelStep2() {}`。

---

## 2. 新旧API对照参考

对于熟悉传统 `status` 模式的开发者，下表可以帮助您快速找到对应的 NextLevel 方法。

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

* `[spk]` 代表可选的 `speaker` 参数。

---

## 3. API 详细参考与示例

### 3.1 基础对话框 (Basic Dialogs)

| 方法签名 | 说明 |
| :--- | :--- |
| `cm.sendNextLevel(nextLevel, text, [speaker])` | 显示“下一步”按钮。点击后调用 `level<nextLevel>()`。 |
| `cm.sendLastLevel(lastLevel, text, [speaker])` | 显示“上一步”按钮。点击后调用 `level<lastLevel>()`。 |
| `cm.sendLastNextLevel(lastLevel, nextLevel, text, [speaker])` | 同时显示“上一步”和“下一步”按钮。 |
| `cm.sendOkLevel(nextLevel, text, [speaker])` | 显示“确定”按钮。点击后调用 `level<nextLevel>()`。 |
| `cm.sendYesNoLevel(noLevel, yesLevel, text, [speaker])` | 显示“是/否”按钮。点击“是”调用 `level<yesLevel>()`，点击“否”调用 `level<noLevel>()`。 |
| `cm.sendAcceptDeclineLevel(declineLevel, acceptLevel, text, [speaker])` | 显示“接受/拒绝”按钮。点击“接受”调用 `level<acceptLevel>()`，点击“拒绝”调用 `level<declineLevel>()`。 |

**示例：**
```javascript
function start() {
    levelMain(); 
}

function level() { // 用于结束或异常处理
    cm.dispose();
}

function levelMain() {
    cm.sendYesNoLevel("End", "Step2", "你好，要进入下一步吗？");
}

function levelStep2() {
    cm.sendOkLevel("End", "欢迎来到第二步，点击确定结束。");
}

function levelEnd() {
    cm.sendOk("对话结束。");
    cm.dispose();
}
```

### 3.2 选项选择 (Selections)

#### 方式一：统一处理 (推荐)
使用 `sendNextSelectLevel`，所有选项都由同一个方法处理，通过 `selection` 参数区分。

| 方法签名 | 说明 |
| :--- | :--- |
| `cm.sendNextSelectLevel(nextLevel, text, [speaker])` | 显示选项列表。无论玩家选择哪个选项，都会调用 `level<nextLevel>(selection)`，其中 `selection` 是玩家选择的 `L` 标签值。 |

**示例：**
```javascript
function levelMenu() {
    var text = "请选择一个功能：\r\n";
    text += "#L0#查看天气#l\r\n";
    text += "#L1#购买商品#l";
    // 选择后统一跳转到 levelProcessMenu(selection)
    cm.sendNextSelectLevel("ProcessMenu", text);
}

function levelProcessMenu(selection) {
    if (selection == 0) {
        cm.sendOkLevel("End", "今天天气晴朗！");
    } else if (selection == 1) {
        cm.sendOkLevel("End", "商品已售罄。");
    }
}
```

#### 方式二：分发处理
使用 `sendSelectLevel`，根据 `Prefix + selection` 自动路由到不同方法。

| 方法签名 | 说明 |
| :--- | :--- |
| `cm.sendSelectLevel(prefix, text, [speaker])` | 显示选项列表。如果玩家选择 `L` 标签值为 `N` 的选项，则会调用 `level<prefix><N>()`。 |

**示例：**
```javascript
function levelJobs() {
    var text = "请选择你的职业：\r\n#L0#战士#l\r\n#L1#法师#l";
    // Prefix 为 "Confirm"，选择 0 跳转到 levelConfirm0，选择 1 跳转到 levelConfirm1
    cm.sendSelectLevel("Confirm", text);
}

function levelConfirm0() {
    cm.sendOkLevel("End", "你选择了战士。");
}

function levelConfirm1() {
    cm.sendOkLevel("End", "你选择了法师。");
}
```

### 3.3 用户输入 (User Input)

| 方法签名 | 说明 |
| :--- | :--- |
| `cm.getInputTextLevel(nextLevel, text)` | 获取文本输入。玩家输入后，点击“确定”将调用 `level<nextLevel>(inputText)`。 |
| `cm.getInputNumberLevel(nextLevel, text, default, min, max)` | 获取数字输入。玩家输入后，点击“确定”将调用 `level<nextLevel>(inputNumber)`。 |
| `cm.getPnpcInputTextLevel(...)` / `cm.getPnpcInputNumberLevel(...)` | 带有 `speaker` 参数的版本。 |

**示例：获取文本**
```javascript
function levelAskName() {
    cm.getInputTextLevel("ShowName", "请输入你的名字：");
}

function levelShowName(name) {
    if (name === "") {
        cm.sendOkLevel("AskName", "名字不能为空，请重新输入。");
        return;
    }
    cm.sendOkLevel("End", "你好，" + name + "！");
}
```

**示例：获取数字**
```javascript
function levelAskQuantity() {
    cm.getInputNumberLevel("ConfirmQuantity", "请输入购买数量：", 1, 1, 100);
}

function levelConfirmQuantity(quantity) {
    cm.sendOkLevel("End", "你购买了 " + quantity + " 个。");
}
```

---

## 4. 优势

1.  **无需维护 `status` 变量**：代码更简洁，告别繁琐的 `status` 判断。
2.  **流程可视化**：通过方法名即可清晰地看出对话的流转路径。
3.  **模块化**：每个对话步骤都是独立的函数，易于复用、测试和修改。
4.  **状态安全**：框架层自动管理上下文，有效减少因状态错乱导致的脚本卡死问题。
