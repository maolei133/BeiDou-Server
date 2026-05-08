# OpcodeManager 动态封包注册指南 (JS版)

## 1. 功能概述

`OpcodeManager` 是一个强大的动态封包（操作码）管理系统，它允许开发者通过 JavaScript 脚本来完全控制服务器的接收（Recv）和发送（Send）操作码。

该系统彻底将操作码定义从硬编码的 Java 文件中解放出来，带来了以下核心优势：

- **高度解耦**：操作码的定义集中在 `OpcodeManager.js` 脚本中，与服务器的 Java 业务逻辑分离。
- **极致灵活性**：无论是**覆盖**一个现有的操作码，还是**新增**一个 Java 代码中完全不存在的全新操作码，都可以轻松完成。
- **热更新支持**：修改操作码后，无需重启服务器。通过 GM 命令（如 `!reloadopcodes`）或Web后台即可让改动立即生效，极大提升了开发和调试效率。
- **版本兼容性**：当需要兼容不同版本的客户端时，只需修改 `OpcodeManager.js` 脚本，即可快速切换或调整操作码，无需改动和重新编译任何 Java 代码。

## 2. 核心概念

### 2.1 核心文件

- **`scripts-zh-CN/packet/OpcodeManager.js`**: 这是你的主战场。所有操作码的定义、覆盖、新增都在此脚本中完成。

### 2.2 注入的 `manager` 实例

系统在执行 `OpcodeManager.js` 时，会自动向其全局作用域中注入一个名为 `manager` 的 Java 实例。该实例是 `org.gms.net.OpcodeManager` 的对象，你可以通过调用它的方法来注册操作码。

### 2.3 “JS 优先”原则

服务器的操作码加载遵循以下流程：
1.  **加载默认值**：服务器启动时，首先将 Java 枚举类（`RecvOpcode.java`, `SendOpcode.java`）中定义的硬编码值加载到内存中。
2.  **执行 JS 脚本**：紧接着，执行 `OpcodeManager.js` 脚本。
3.  **覆盖与新增**：
    - 如果脚本中定义的操作码在内存中**已存在**，其值将被**覆盖**。
    - 如果脚本中定义的操作码在内存中**不存在**，它将被作为一条**新记录添加**。
4.  **应用**：在此之后，服务器的所有部分（包括 Java 和其他 JS 脚本）都将使用这套内存中最新的、被 JS 更新过的操作码。

---

## 3. 快速上手：三种核心操作

### 3.1 操作一：覆盖一个已有的操作码

当客户端版本更新，导致某个操作码的值发生变化时，使用此方法。

- **场景**：`LOGIN_PASSWORD` 的值从 `0x01` 变成了 `0x02`。
- **步骤**：
    1.  在 `OpcodeManager.js` 脚本顶部，使用 `Java.type()` 导入 `RecvOpcode` 枚举，以获得 IDE 的自动补全支持并保证名称正确。
    2.  使用 `manager.putRecv()` 方法，传入枚举项的 `.name()` 和新的十六进制值。

```javascript
// 1. 导入 Java 枚举
var RecvOpcode = Java.type('org.gms.net.opcodes.RecvOpcode');

// 2. 使用 .name() 方法覆盖值
manager.putRecv(RecvOpcode.LOGIN_PASSWORD.name(), 0x02); // 将值从 0x01 覆盖为 0x02
```
> **最佳实践**: 覆盖已有操作码时，强烈建议使用 `RecvOpcode.LOGIN_PASSWORD.name()` 的形式，而不是 `"LOGIN_PASSWORD"`。这能让你的 IDE 在编码时就发现拼写错误，而不是等到运行时才报错。

### 3.2 操作二：新增一个全新的操作码

当你开发了自定义功能，需要一个在 Java 代码中从未定义过的新操作码时，使用此方法。

- **场景**：你开发了一个自定义的聊天表情系统，需要一个新的接收操作码 `CUSTOM_EMOTICON`，值为 `0x7FFE`。
- **步骤**：直接使用字符串作为操作码的名称，调用 `manager.putRecv()`。

```javascript
// 直接使用字符串作为新操作码的名称
manager.putRecv("CUSTOM_EMOTICON", 0x7FFE);
log.info("已注册新的自定义接收操作码: CUSTOM_EMOTICON");
```
> **注意**: 因为这个操作码在 Java 的 `RecvOpcode` 枚举中不存在，所以你**只能**使用字符串 `"CUSTOM_EMOTICON"`，而不能写 `RecvOpcode.CUSTOM_EMOTICON`。

### 3.3 操作三：在其他脚本中使用这些操作码

无论是被覆盖的、还是新增的操作码，都应该通过 `OpcodeManager` 来获取其值，以确保获取到的是最新的、最准确的值。

- **场景**：你需要为新增的 `CUSTOM_EMOTICON` 操作码注册一个数据包处理器。
- **步骤**（在 `scripts-zh-CN/packet/PacketProcessor.js` 中）：
    1.  导入 `OpcodeManager` 类。
    2.  通过 `OpcodeManager.getInstance().getRecvOpcode()` 方法，使用**字符串名称**获取操作码的整数值。
    3.  将获取到的值用于注册处理器。

```javascript
// file: scripts-zh-CN/packet/PacketProcessor.js

// 1. 导入 OpcodeManager
var OpcodeManager = Java.type('org.gms.net.OpcodeManager');

// 2. 获取操作码的值
var customEmoticonOpcode = OpcodeManager.getInstance().getRecvOpcode("CUSTOM_EMOTICON");

// 3. 使用获取到的值进行注册 (务必检查非空)
if (customEmoticonOpcode !== null) {
    processor.registerScriptedHandler(customEmoticonOpcode, "packet/custom/CUSTOM_EMOTICON.js");
    log.info("已为自定义操作码 CUSTOM_EMOTICON 注册处理器。");
}
```

---

## 4. 热重载

本系统完全支持热重载。当你修改并保存 `OpcodeManager.js` 文件后：
-   **方式一 (游戏内)**: 使用拥有权限的 GM 账号，在聊天框输入命令 `!reloadopcodes`。
-   **方式二 (Web后台)**: 访问Web管理后台，在 **仪表盘 -> 工作台** 找到 **数据重载** 卡片，点击 **“重载操作码”** 按钮。

服务器会动态执行完整的重载流程，你的修改会立即生效。

## 5. 相关文件清单

### 5.1. 功能独有文件

-   [`gms-server/src/main/java/org/gms/net/OpcodeManager.java`](../../../../java/org/gms/net/OpcodeManager.java): **（调度中心）** 负责从 `OpcodeManager.js` 中加载并注册动态的操作码。
-   [`gms-server/src/main/java/org/gms/net/opcodes/Opcode.java`](../../../../java/org/gms/net/opcodes/Opcode.java): **（操作码接口）**
-   [`gms-server/src/main/java/org/gms/net/opcodes/SendOpcode.java`](../../../../java/org/gms/net/opcodes/SendOpcode.java): **（发送操作码）**
-   [`gms-server/src/main/java/org/gms/net/opcodes/RecvOpcode.java`](../../../../java/org/gms/net/opcodes/RecvOpcode.java): **（接收操作码）**
-   [`gms-server/src/main/java/org/gms/client/command/commands/gm3/ReloadOpcodesCommand.java`](../../../../java/org/gms/client/command/commands/gm3/ReloadOpcodesCommand.java): **（GM指令）** 用于在游戏中通过指令重载操作码。
-   [`gms-server/scripts-zh-CN/packet/OpcodeManager.js`](../../../../scripts-zh-CN/packet/OpcodeManager.js): **（开发者脚本）** 开发者在此文件中定义需要动态修改的操作码。

### 5.2. 交叉关联文件

-   [`gms-server/src/main/java/org/gms/scripting/AbstractScriptManager.java`](../../../../java/org/gms/scripting/AbstractScriptManager.java): **（脚本引擎核心）** 提供通用的脚本引擎创建和执行能力。
-   [`gms-server/src/main/java/org/gms/service/CommandService.java`](../../../../java/org/gms/service/CommandService.java): **（重载服务）** 提供了所有脚本化功能的重载业务逻辑。
-   [`gms-server/src/main/java/org/gms/controller/CommandController.java`](../../../../java/org/gms/controller/CommandController.java): **（重载API）** 提供了所有脚本化功能重载的Web API接口。
-   [`gms-server/src/main/java/org/gms/net/PacketProcessor.java`](../../../../java/org/gms/net/PacketProcessor.java): **（封包处理器）** 在 `OpcodeManager.js` 重载后，需要调用其 `reloadScripts()` 方法以使用最新的操作码重新注册处理器。
