# PacketCreator 脚本化开发指南 (最终版)

## 1. 功能概述

本服务端实现了一套非侵入式的脚本化机制，允许开发者使用 JavaScript 文件来覆盖或扩展 `org.gms.util.PacketCreator` 类，而**无需修改任何 `PacketCreator.java` 的源代码**。

这套机制的目标是：

- **JS优先**：当调用一个 `PacketCreator` 的方法时，系统会优先检查并执行位于 `scripts-zh-CN/packet/PacketCreator.js` 中的同名JS函数。
- **Java保底**：如果JS文件中没有对应的函数，或者JS函数执行失败，系统会自动回退，执行`PacketCreator.java`中原始的Java方法，保证服务的稳定性。
- **完全透明**：对于Java代码调用者来说，调用方式与以往完全相同（`PacketCreator.getXXX()`），无需关心底层的实现是Java还是JS。
- **无缝新增**：支持在 `PacketCreator.js` 中定义全新的、Java中不存在的方法，并在其他JS脚本中以 `PacketCreator.newMethod()` 的方式**直接调用**，享受与原生静态方法完全一致的开发体验。
- **动态重载**：支持通过Web管理后台热更新 `PacketCreator.js` 脚本，无需重启服务器即可让修改生效，极大提升了封包相关逻辑的开发和调试效率。

## 2. 技术内幕

本功能的核心是 **Java字节码增强**、**自定义类加载器** 和 **GraalVM多语言代理** 的精妙结合。

- **`ByteBuddyClassLoader`**: 我们创建了一个自定义的类加载器。当Spring Boot应用启动时，我们通过引导程序（`ServerApplication.main`）将主线程的上下文类加载器替换为它。
- **`ByteBuddy`**: 在 `ByteBuddyClassLoader` 加载 `org.gms.util.PacketCreator` 类时，它会使用强大的 `ByteBuddy` 库动态地修改该类的字节码，拦截所有已存在的方法。
- **`PacketCreatorInterceptor`**: 字节码增强的过程，就是将所有符合条件（`public static Packet`类型）的方法调用，全部拦截并重定向到 `PacketCreatorInterceptor.intercept()` 方法。
- **`ScriptableJavaClassProxy` (关键)**: 这是一个GraalVM代理，是实现无缝API的“魔法”所在。在执行任何JS脚本之前，我们会将 `PacketCreator.class` 包装成这个代理对象，并以“PacketCreator”为名注入到JS引擎中。当JS代码访问 `PacketCreator` 时，实际上访问的是这个代理。
- **`PacketCreatorManager`**: 所有的调用最终都会被分发到 `PacketCreatorManager`。它持有JS脚本引擎，负责执行JS函数，并在必要时调用Java后备方法。

**调用流程小结:**
- **调用现有方法 (如 `getLoginFailed`)**: JS代码 `PacketCreator.getLoginFailed()` -> `ScriptableJavaClassProxy` 发现Java中有此方法 -> 返回Java方法引用 -> 调用触发ByteBuddy拦截 -> `PacketCreatorInterceptor` -> `PacketCreatorManager.dispatch()` -> 执行JS或Java。
- **调用新增方法 (如 `getLoginFailednew`)**: JS代码 `PacketCreator.getLoginFailednew()` -> `ScriptableJavaClassProxy` 发现Java中没有，但在JS脚本中有 -> 返回一个可执行代理 -> 调用该代理 -> `PacketCreatorManager.invoke()` -> 执行JS。

## 3. 开发者实践指南

### 3.1. 覆盖Java现有方法

要在JS中覆盖一个`PacketCreator`的**已有**方法，你只需要在以下文件中添加一个同名函数即可。

- **脚本文件位置**: `gms-server/scripts-zh-CN/packet/PacketCreator.js`

```javascript
// file: scripts-zh-CN/packet/PacketCreator.js

// 导入需要的 Java 类
var OutPacket = Java.type('org.gms.net.packet.OutPacket');
var SendOpcode = Java.type('org.gms.net.opcodes.SendOpcode');

/**
 * 覆盖 Java 中的 PacketCreator.getLoginFailed(int reason) 方法。
 */
function getLoginFailed(reason) {
    log.info("正在通过 JS 脚本创建 getLoginFailed 封包, 原因: {}", reason);
    var p = OutPacket.create(SendOpcode.LOGIN_STATUS);
    p.writeByte(reason);
    p.writeByte(0);
    p.writeInt(0);
    return p;
}
```

### 3.2. 新增JS独有方法并调用

你可以在 `PacketCreator.js` 中定义一个Java中完全不存在的新方法，然后在**任何其他JS脚本**中直接调用它，语法与调用普通Java静态方法完全相同。

#### 步骤1: 在 `PacketCreator.js` 中定义新函数

```javascript
// file: scripts-zh-CN/packet/PacketCreator.js

/**
 * 一个在 Java 中不存在的、全新的封包创建函数。
 */
function getLoginFailednew(reason) {
    log.info("正在执行一个Java中不存在的全新JS封包函数 getLoginFailednew, 原因: {}", reason);
    var p = OutPacket.create(SendOpcode.LOGIN_STATUS);
    p.writeByte(reason);
    p.writeByte(1); // 与原版不同的标识，用于测试
    p.writeInt(0);
    return p;
}
```

#### 步骤2: 在其他JS脚本中直接调用

在任何其他JS脚本（如 `LOGIN_PASSWORD.js`）中，你可以像调用原生Java静态方法一样直接调用它。

```javascript
// file: scripts-zh-CN/packet/login/LOGIN_PASSWORD.js

// PacketCreator 已由引擎自动注入，无需手动导入。

// ... 在你的处理逻辑中 ...

// 直接调用，就像它是Java的静态方法一样！
var packetToSend = PacketCreator.getLoginFailednew(loginok);

if (packetToSend) {
    client.sendPacket(packetToSend);
}
```
**这就是最终的、最优雅的调用方式。**

### 3.3. 【重要】避免报错的核心要点

#### **规则1：正确调用 `OutPacket.create()`**

`OutPacket.create()` 方法的参数是一个 `SendOpcode` **枚举对象**。

- **正确做法 ✅**
  ```javascript
  // 直接传递枚举对象
  var p = OutPacket.create(SendOpcode.LOGIN_STATUS);
  ```

- **错误做法 ❌**
  ```javascript
  // 错误：传递了枚举的整数值，会导致类型转换异常
  var p = OutPacket.create(SendOpcode.LOGIN_STATUS.getValue()); 
  ```

#### **规则2：确保JS函数签名与Java一致（当覆盖时）**

如果要覆盖一个Java方法，JS函数的名称和参数个数应与Java静态方法保持一致。

- **Java 方法**: `public static Packet getCharList(Client c, int serverId, int status)`
- **对应JS函数**: `function getCharList(c, serverId, status) { ... }`

## 4. 动态重载

为了方便调试，你可以在修改 `PacketCreator.js` 文件后，无需重启服务器，直接通过Web管理后台使其生效。

1.  登录Web管理后台。
2.  进入 **仪表盘 -> 工作台**。
3.  找到 **数据重载** 卡片。
4.  点击 **“重载封包脚本”** 按钮。

系统会重新加载 `packet/PacketCreator.js` 文件。之后的所有相关封包创建请求，都将执行新的脚本逻辑。

## 5. 相关文件清单

### 5.1. 功能独有文件

-   [`gms-server/src/main/java/org/gms/util/PacketCreator.java`](../../../../java/org/gms/util/PacketCreator.java): 被动态增强的封包创建外观类。**源码保持干净，不应被手动修改**。
-   [`gms-server/src/main/java/org/gms/util/PacketCreatorManager.java`](../../../../java/org/gms/util/PacketCreatorManager.java): 负责加载和调度 `PacketCreator.js` 中的函数。
-   [`gms-server/src/main/java/org/gms/agent/ByteBuddyClassLoader.java`](../../../../java/org/gms/agent/ByteBuddyClassLoader.java): 在加载时对`PacketCreator`进行字节码增强。
-   [`gms-server/src/main/java/org/gms/agent/PacketCreatorInterceptor.java`](../../../../java/org/gms/agent/PacketCreatorInterceptor.java): 拦截`PacketCreator`的**现有**方法调用。
-   [`gms-server/src/main/java/org/gms/agent/InvokeMethodInterceptor.java`](../../../../java/org/gms/agent/InvokeMethodInterceptor.java): 为`PacketCreator`动态添加`invoke`方法。
-   [`gms-server/src/main/java/org/gms/agent/ScriptableJavaClassProxy.java`](../../../../java/org/gms/agent/ScriptableJavaClassProxy.java): 实现JS中无缝调用Java新增和现有方法的“魔法”所在。
-   [`gms-server/scripts-zh-CN/packet/PacketCreator.js`](../../../../scripts-zh-CN/packet/PacketCreator.js): 开发者在此文件中编写覆盖或新增的封包函数。

### 5.2. 交叉关联文件

-   [`gms-server/src/main/java/org/gms/ServerApplication.java`](../../../../java/org/gms/ServerApplication.java): **（系统入口）** 引导程序，负责启动自定义ClassLoader。
-   [`gms-server/src/main/java/org/gms/scripting/AbstractScriptManager.java`](../../../../java/org/gms/scripting/AbstractScriptManager.java): **（脚本引擎核心）** 提供通用的脚本引擎创建和执行能力，并负责向JS注入代理对象。
-   [`gms-server/src/main/java/org/gms/service/CommandService.java`](../../../../java/org/gms/service/CommandService.java): **（重载服务）** 提供了所有脚本化功能的重载业务逻辑。
-   [`gms-server/src/main/java/org/gms/controller/CommandController.java`](../../../../java/org/gms/controller/CommandController.java): **（重载API）** 提供了所有脚本化功能重载的Web API接口。
