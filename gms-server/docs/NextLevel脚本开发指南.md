# NextLevel 脚本开发指南

NextLevel 是一种基于方法路由的 NPC 脚本编写模式，旨在替代传统的 `status` 状态机模式。它通过方法名直接映射对话流程，使代码结构更清晰、逻辑更易维护。

## 1. 核心概念

在 NextLevel 模式中，每个对话步骤对应脚本中的一个函数（Function）。
- **入口函数**：`start()` 或 `action()`，通常在 `start()` 中调用第一个业务逻辑函数。
- **路由规则**：通过 `cm.sendXxxLevel("NextMethodName", ...)` 指定下一步要执行的函数名。
- **函数命名**：通常以 `level` 开头，例如 `levelMain`, `levelSelectJob`。

## 2. 常用 API 对照表

| 传统 API (status模式) | NextLevel API | 说明 |
| :--- | :--- | :--- |
| `cm.sendNext(text)` | `cm.sendNextLevel("MethodName", text)` | 显示“下一步”按钮，点击后跳转到 `levelMethodName` |
| `cm.sendPrev(text)` | `cm.sendLastLevel("MethodName", text)` | 显示“上一步”按钮，点击后跳转到 `levelMethodName` |
| `cm.sendNextPrev(text)` | `cm.sendLastNextLevel("LastMethod", "NextMethod", text)` | 显示“上一步”和“下一步”按钮 |
| `cm.sendOk(text)` | `cm.sendOkLevel("MethodName", text)` | 显示“确定”按钮，点击后跳转到 `levelMethodName` |
| `cm.sendYesNo(text)` | `cm.sendYesNoLevel("NoMethod", "YesMethod", text)` | 显示“是/否”按钮，分别跳转到不同方法 |
| `cm.sendAcceptDecline(text)` | `cm.sendAcceptDeclineLevel("DeclineMethod", "AcceptMethod", text)` | 显示“接受/拒绝”按钮 |
| `cm.sendSimple(text)` | `cm.sendNextSelectLevel("MethodName", text)` | 显示选项菜单，选择后跳转到 `levelMethodName(selection)` |
| `cm.sendSimple(text)` | `cm.sendSelectLevel("Prefix", text)` | 显示选项菜单，选择后跳转到 `levelPrefix + selection` |
| `cm.sendGetNumber(...)` | `cm.getInputNumberLevel("MethodName", ...)` | 获取数字输入，输入后跳转到 `levelMethodName(input)` |
| `cm.sendGetText(...)` | `cm.getInputTextLevel("MethodName", ...)` | 获取文本输入，输入后跳转到 `levelMethodName(text)` |

## 3. 编写规范与示例

### 3.1 基础结构

```javascript
// 必须包含 start 方法
function start() {
    levelMain(); // 跳转到主逻辑
}

// 必须包含 level 方法，用于处理异常或结束
function level() {
    cm.dispose();
}

// 业务逻辑方法 1
function levelMain() {
    cm.sendNextLevel("Step2", "你好，这是第一步。点击下一步继续。");
}

// 业务逻辑方法 2 (对应 levelMain 中的 "Step2")
// 注意：方法名必须是 "level" + 传入的名称
function levelStep2() {
    cm.sendOkLevel("End", "这是第二步。点击确定结束对话。");
}

// 结束方法
function levelEnd() {
    cm.dispose();
}
```

### 3.2 处理选项菜单 (Selection)

**方式一：统一处理 (推荐)**
使用 `sendNextSelectLevel`，所有选项都由同一个方法处理，通过 `selection` 参数区分。

```javascript
function levelMenu() {
    var text = "请选择一个功能：\r\n";
    text += "#L0#功能A#l\r\n";
    text += "#L1#功能B#l";
    // 选择后跳转到 levelProcessMenu(selection)
    cm.sendNextSelectLevel("ProcessMenu", text);
}

function levelProcessMenu(selection) {
    if (selection == 0) {
        cm.sendOkLevel("End", "你选择了功能A");
    } else if (selection == 1) {
        cm.sendOkLevel("End", "你选择了功能B");
    }
}
```

**方式二：分发处理**
使用 `sendSelectLevel`，根据 `Prefix + selection` 自动路由到不同方法。

```javascript
function levelMenu() {
    var text = "请选择：\r\n#L0#去处理A#l\r\n#L1#去处理B#l";
    // Prefix 为 "Action"，选择 0 跳转到 levelAction0，选择 1 跳转到 levelAction1
    cm.sendSelectLevel("Action", text);
}

function levelAction0() {
    cm.sendOkLevel("End", "处理 A");
}

function levelAction1() {
    cm.sendOkLevel("End", "处理 B");
}
```

### 3.3 处理输入 (Input)

```javascript
function levelAskNumber() {
    // 跳转到 levelCheckNumber(input)
    cm.getInputNumberLevel("CheckNumber", "请输入一个数字：", 1, 1, 100);
}

function levelCheckNumber(input) {
    cm.sendOkLevel("End", "你输入的数字是：" + input);
}
```

## 4. 优势

1.  **无需维护 `status` 变量**：不再需要 `status++` 或 `if (status == 1) ...` 的繁琐判断。
2.  **流程可视化**：通过方法名即可看出对话的流转方向（如 `levelMain` -> `levelStep2`）。
3.  **模块化**：每个对话步骤都是独立的函数，易于复用和修改。
4.  **状态安全**：框架层自动管理上下文，减少了因状态错乱导致的脚本卡死问题。

## 5. 注意事项

*   所有跳转的目标方法名，在定义时必须加上 `level` 前缀。例如 `cm.sendNextLevel("Test", ...)` 对应 `function levelTest() {}`。
*   `cm.dispose()` 仍然是结束对话的必要操作。
*   如果脚本中同时存在 `action` 函数和 NextLevel 调用，可能会导致冲突，建议新脚本完全采用 NextLevel 写法。
