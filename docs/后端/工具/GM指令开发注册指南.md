# GM 指令开发与注册指南

## 1. 功能概述

本服务端的 GM 指令系统采用经典的命令模式设计，具有良好的结构和高度的可扩展性。开发者可以通过创建独立的 Java 类来封装每一个指令的逻辑，然后通过简单的配置将其注册到系统中。

本指南将详细介绍如何从零开始创建一个全新的 GM 指令。

## 2. 核心概念与文件

- **`org.gms.client.command.Command`**: 这是一个抽象类，所有具体的指令都必须继承它。它定义了指令的基本结构。
- **`org.gms.client.command.CommandsExecutor`**: 指令的执行中心。它负责解析玩家输入的文本，查找并执行对应的指令。
- **`org.gms.client.command.commands`**: 这是一个包（package），所有具体的指令类都存放在此包的子包中，通常按 GM 等级（`gm0`, `gm1`...）进行分类。

## 3. 快速上手：三步创建一个新指令

假设我们需要创建一个新的 GM 指令 `!helloworld`，它的功能是在游戏聊天框中对玩家说“Hello, World!”。

### 第一步：创建指令类

1.  **选择位置**：根据你希望的 GM 等级，在 `org.gms.client.command.commands` 下选择一个合适的子包。例如，我们为 `gm0`（0级GM）创建一个新指令，就在 `gm0` 包下创建一个新的 Java 类。
2.  **命名规范**：通常，类名应与指令功能相关，并以 `Command` 结尾。我们创建 `HelloWorldCommand.java`。
3.  **编写代码**：

```java
package org.gms.client.command.commands.gm0;

import org.gms.client.Client;
import org.gms.client.command.Command;

/**
 * 一个简单的 "Hello World" 指令，用于演示。
 */
public class HelloWorldCommand extends Command {

    public HelloWorldCommand() {
        // 1. 设置指令的描述，会显示在 !help 中
        description = "一个简单的演示指令";
    }

    @Override
    public void execute(Client client, String[] params) {
        // 2. 实现指令的核心逻辑
        client.getPlayer().dropMessage(1, "Hello, World! 你成功执行了新指令。");
    }
}
```

**代码解析**:
- **继承 `Command`**: 必须继承 `Command` 抽象类。
- **构造函数**: 在构造函数中，你可以设置 `description` 属性。
- **`execute` 方法**: 这是指令的核心。
    - `client`: 代表当前执行指令的客户端连接，你可以通过 `client.getPlayer()` 获取玩家对象。
    - `params`: 一个字符串数组，包含了指令触发词之后的所有参数。例如，输入 `!say hello world`，则 `params` 数组为 `["hello", "world"]`。

### 第二步：注册指令

本服务端采用更先进的基于注解的自动注册机制，无需手动修改 `CommandsExecutor.java`。

1.  **添加注解**：在你刚刚创建的 `HelloWorldCommand` 类的上方，添加 `@CommandComponent` 注解。
2.  **配置注解**：
    - `syntax`: 定义触发此指令的命令词（一个或多个）。
    - `rank`: 定义执行此指令所需的最低 GM 等级。

修改后的 `HelloWorldCommand.java` 如下：

```java
package org.gms.client.command.commands.gm0;

import org.gms.client.Client;
import org.gms.client.command.Command;
import org.gms.service.annotion.CommandComponent; // 导入注解

/**
 * 一个简单的 "Hello World" 指令，用于演示。
 */
@CommandComponent(syntax = {"helloworld", "hw"}, rank = 0) // 添加注解并配置
public class HelloWorldCommand extends Command {

    public HelloWorldCommand() {
        description = "一个简单的演示指令";
    }

    @Override
    public void execute(Client client, String[] params) {
        client.getPlayer().dropMessage(1, "Hello, World! 你成功执行了新指令。");
    }
}
```
通过 `@CommandComponent` 注解，我们定义了 `!helloworld` 和 `!hw` 两个命令都可以触发这个指令，并且只需要 0 级 GM 权限。

### 第三步：编译并测试

1.  **重新编译**：修改或添加 Java 文件后，你需要重新编译你的项目。
2.  **重启服务器**：重启游戏服务器以加载新的类。
3.  **进入游戏测试**：使用一个 0 级或更高等级的 GM 账号，在聊天框中输入 `!helloworld` 或 `!hw`，你应该会收到 "Hello, World! ..." 的消息。

---

## 4. 进阶技巧

### 4.1 处理参数

`execute` 方法的 `params` 数组是你与用户交互的关键。

```java
// 假设指令是 !spawn 10000 5 (生成5个蜗牛)
@Override
public void execute(Client client, String[] params) {
    if (params.length < 2) {
        client.getPlayer().dropMessage(5, "格式错误! 请使用: !spawn <怪物ID> <数量>");
        return;
    }
    try {
        int monsterId = Integer.parseInt(params[0]);
        int quantity = Integer.parseInt(params[1]);
        
        // ... 生成怪物的逻辑 ...

    } catch (NumberFormatException e) {
        client.getPlayer().dropMessage(5, "参数必须是数字!");
    }
}
```

### 4.2 使用 `joinStringFrom`

如果你需要将从某个位置开始的所有参数合并成一个完整的字符串（例如 `!notice` 指令），可以使用 `Command` 类提供的 `joinStringFrom` 辅助方法。

```java
// 假设指令是 !notice 欢迎来到 北斗冒险岛
@Override
public void execute(Client client, String[] params) {
    // 从第0个参数开始，合并所有参数为一个字符串
    String message = joinStringFrom(params, 0); 
    // message 的值将是 "欢迎来到 北斗冒险岛"
    
    // ... 发送全服公告的逻辑 ...
}
```

通过遵循以上步骤，你可以轻松地为服务器添加任何你想要的新功能。
