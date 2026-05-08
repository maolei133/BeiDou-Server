# PacketProcessor 封包注册与开发指南 (JS版)

## 1. 功能概述

本系统允许开发者使用 JavaScript (GraalVM JS) 编写独立的脚本来处理客户端发送的数据包（封包），从而替代传统的在 Java 中硬编码处理逻辑的方式。

这种方法带来了以下核心优势：

- **高度解耦**：每个封包的处理逻辑都位于其独立的 `.js` 文件中，互不干扰。
- **快速开发**：无需重新编译 Java 代码，通过 GM 命令或Web后台即可实现**热更新**，立即生效。
- **职责单一**：`PacketProcessor.js` 负责路由，具体脚本负责业务逻辑。
- **错误隔离**：单个脚本的语法或逻辑错误不会影响到其他封包处理器的正常运行。
- **明确性与自包含**：每个脚本都明确导入自己所需的 Java 类，可读性强，易于维护。

## 2. 核心概念

### 2.1 注入的上下文实例

对于每一个执行的脚本，系统会自动向其全局作用域中注入以下实例：

| 变量名   | Java 实例                               | 用途说明                                           |
| -------- | --------------------------------------- | -------------------------------------------------- |
| `log`    | `org.slf4j.Logger`                      | SLF4J 日志记录器，请使用 `log.info()`, `log.warn()` 等。 |
| `client` | `org.gms.client.Client`                 | 代表当前客户端连接的实例。                         |
| `packet` | `org.gms.net.packet.InPacket`           | 接收到的数据包实例，用于读取数据。                 |
| `PacketCreator` | `org.gms.agent.ScriptableJavaClassProxy` | 被代理的 `PacketCreator` 对象，可直接调用其所有方法（包括JS中新增的）。 |

### 2.2 手动导入 Java 类

除了以上自动注入的实例外，**所有**需要用到的 Java 类都**必须**在脚本的开头使用 `Java.type()` 手动导入。

```javascript
// 语法: var <JS变量名> = Java.type('<Java类的完整包路径>');

// 示例:
var Server = Java.type('org.gms.net.server.Server');
var GameConfig = Java.type('org.gms.config.GameConfig');
var SpringContextUtil = Java.type('org.gms.util.SpringContextUtil');
var AccountsMapper = Java.type('org.gms.dao.mapper.AccountsMapper');
```

## 3. 快速上手：三步处理一个新封包

假设我们需要为一个新的操作码 `RecvOpcode.SOME_NEW_ACTION` 编写处理逻辑。

### 第一步：在路由中心注册脚本路径

打开 `scripts-zh-CN/packet/PacketProcessor.js` 文件。

在文件末尾添加一行新的路由规则，将操作码指向你将要创建的脚本文件：

```javascript
// ... 其他路由 ...

// 为 SOME_NEW_ACTION 操作码注册一个新的处理器脚本
processor.registerScriptedHandler(RecvOpcode.SOME_NEW_ACTION, "packet/player/SOME_NEW_ACTION.js");
log.info("已将 SOME_NEW_ACTION 路由到 'packet/player/SOME_NEW_ACTION.js'");
```

### 第二步：创建并编写逻辑脚本

根据你在上一步中定义的路径，创建新的 JS 文件。例如，创建 `scripts-zh-CN/packet/player/SOME_NEW_ACTION.js`。

在该文件中，首先导入你需要的 Java 类，然后编写业务逻辑。

```javascript
/**
 * 处理 SOME_NEW_ACTION 数据包的脚本。
 *
 * @global log, client, packet, PacketCreator (由Java自动注入)
 */

// 1. 导入需要的 Java 类
var GameConfig = Java.type('org.gms.config.GameConfig');

log.info("开始处理 SOME_NEW_ACTION 数据包...");

// 2. 业务逻辑
var someValue = packet.readInt();
var someString = packet.readString();
var someConfig = GameConfig.getServerStr("some_config_key");

log.info("读取到数据: value={}, string='{}', config='{}'", someValue, someString, someConfig);

// 3. 直接使用注入的 PacketCreator 对象发送回包
client.sendPacket(PacketCreator.serverNotice(1, "服务器已收到您的 SOME_NEW_ACTION 请求！"));

log.info("SOME_NEW_ACTION 数据包处理完毕。");
```

### 第三步：热更新并测试

1.  **保存** 你修改的所有 `.js` 文件。
2.  进入游戏，使用拥有权限的 GM 账号，在聊天框输入命令 `!reloadpackets`。
3.  或者，访问Web管理后台，在 **仪表盘 -> 工作台** 找到 **数据重载** 卡片，点击 **“重载处理器”** 按钮。
4.  观察服务器后台日志，确认脚本被重新加载。
5.  触发客户端发送 `SOME_NEW_ACTION` 封包的操作，观察日志和游戏内效果是否与你的脚本逻辑一致。

---

## 4. 风险与责任

> [!WARNING]
> **权力越大，责任越大！**
>
> 通过 `Java.type()` 和 `SpringContextUtil.getBean()`，脚本可以获得访问服务器几乎所有资源的能力，包括直接操作数据库。在编写脚本时，你必须清楚自己调用的每一个方法可能带来的后果。
>
> - **谨慎操作**：对于任何修改或删除数据的操作，请再三确认逻辑的正确性。
> - **避免滥用**：不要在脚本中执行长时间运行或高资源消耗的任务，这可能会阻塞服务器的主线程。
> - **责任自负**：脚本的编写者对由其脚本引起的任何数据损坏、服务器崩溃或其他意外问题负全部责任。

---

## 5. 相关文件清单

### 5.1. 功能独有文件

-   [`gms-server/src/main/java/org/gms/net/PacketProcessor.java`](../../../../java/org/gms/net/PacketProcessor.java): **（调度中心）** 负责加载和调度 `PacketProcessor.js`，并将收到的封包分发给JS处理。
-   [`gms-server/src/main/java/org/gms/net/ScriptedPacketHandler.java`](../../../../java/org/gms/net/ScriptedPacketHandler.java): **（处理器实现）** 一个具体的封包处理器，它的 `handlePacket` 方法会调用 `AbstractScriptManager` 来执行JS脚本。
-   [`gms-server/src/main/java/org/gms/client/command/commands/gm3/ReloadPacketsCommand.java`](../../../../java/org/gms/client/command/commands/gm3/ReloadPacketsCommand.java): **（GM指令）** 用于在游戏中通过指令重载所有Packet脚本。
-   [`gms-server/scripts-zh-CN/packet/PacketProcessor.js`](../../../../scripts-zh-CN/packet/PacketProcessor.js): **（开发者脚本）** 开发者在此文件中注册要由JS处理的包头和对应的处理函数。

### 5.2. 交叉关联文件

-   [`gms-server/src/main/java/org/gms/scripting/AbstractScriptManager.java`](../../../../java/org/gms/scripting/AbstractScriptManager.java): **（脚本引擎核心）** 提供通用的脚本引擎创建和执行能力，并负责向JS注入代理对象。
-   [`gms-server/src/main/java/org/gms/service/CommandService.java`](../../../../java/org/gms/service/CommandService.java): **（重载服务）** 提供了所有脚本化功能的重载业务逻辑。
-   [`gms-server/src/main/java/org/gms/controller/CommandController.java`](../../../../java/org/gms/controller/CommandController.java): **（重载API）** 提供了所有脚本化功能重载的Web API接口。
-   [`gms-server/src/main/java/org/gms/net/opcodes/RecvOpcode.java`](../../../../java/org/gms/net/opcodes/RecvOpcode.java): **（接收操作码）** 在 `PacketProcessor.js` 中用于注册处理器。
-   [`gms-server/src/main/java/org/gms/util/PacketCreator.java`](../../../../java/org/gms/util/PacketCreator.java): **（封包创建）** 在处理器脚本中用于构建和发送响应封包。
