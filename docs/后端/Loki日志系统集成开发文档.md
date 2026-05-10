# Loki 日志系统集成开发文档 (v4.3)

> **开发规范**：所有代码的 Javadoc、注释以及开发过程中的回答、交流均必须使用**中文**。

## 1. 概述

本项目采用 **Loki + Promtail + 自定义前端** 的全新日志解决方案，彻底替代传统的文本日志查看方式。
本架构遵循 **"人机分离"** 原则：
*   **人 (控制台)**: 仅输出最精简的文本日志，供开发调试。
*   **机 (Loki)**: 输出严格结构化的 JSON 日志，供系统采集、存储和分析。

### 1.1 核心优势
*   **纯净架构**: 彻底摒弃旧时代的文本解析，全链路采用 JSON 结构化数据。
*   **极致性能**: Loki 不索引全文，写入吞吐量极高；支持 Snappy/Gzip 压缩，查询速度快，磁盘占用低。
*   **深度集成**: 前端管理页面直接嵌入游戏服务端，零依赖、全自动。
*   **完全可控**: 支持细粒度的模块开关、日志级别控制及自定义仪表盘。
*   **后端驱动国际化**: 全界面支持中英文切换，模块和动作名称的国际化由后端处理，前端无需配置。

## 2. 架构设计

```mermaid
graph LR
    GameServer[Game Server] -->|AuditLogger (FastJson2)| AuditFile[audit.json (Pure JSON)]
    GameServer -->|Log4j2 (PatternLayout)| Console[Console (Text)]
    AuditFile -->|Promtail| Loki[Loki Server]
    GMS-UI[GMS Admin UI] -->|HTTP API| GameServer
    GameServer -->|Loki API| Loki
```

1.  **生成端 (Game Server)**:
    *   **Audit Log**: `logs/audit/audit.json`。**严格 JSON 格式**，由 `AuditLogger` 使用 `FastJson2` 手动序列化，并通过 Log4j2 `PatternLayout` (%m%n) 输出，避免了 Log4j2 的额外包装。
    *   **Console**: 仅输出人类可读的简略信息，不被 Promtail 采集。
2.  **采集端 (Promtail)**: 监听 `audit.json`，直接提取顶层 JSON 字段，无需二次解析。
3.  **存储端 (Loki)**: 负责日志的存储、索引和压缩。
4.  **展示端 (GMS-UI)**: 提供日志查询、仪表盘展示及系统配置。

## 3. 日志规范与分类策略

### 3.1 模块与动作枚举 (Enum)
为了保证数据的一致性和可统计性，所有日志必须使用预定义的枚举。所有枚举都包含 `getI18nVal()` 方法，用于直接从后端获取国际化文本。

**LogModule (模块)**:
*   `SYSTEM`: 系统级事件 (启动/关闭)
*   `LOGIN`: 登录/账号相关
*   `CHARACTER`: 角色成长 (升级/转职)
*   `ITEM`: 物品/背包变动
*   `SHOP`: NPC 商店交易
*   `TRADE`: 玩家间交易
*   `CASH_SHOP`: 商城消费
*   `FIELD`: 地图/打怪
*   `SCRIPT`: 脚本/副本
*   `EVENT`: 活动相关
*   `AUTOBAN`: 反作弊系统
*   `PLUGIN`: 内置辅助插件

**LogAction (动作)**:
*   `LOGIN_SUCCESS`, `LOGIN_FAIL`, `LOGOUT`
*   `LEVEL_UP`, `DIE`, `REVIVE`
*   `ITEM_GAIN`, `ITEM_LOST`, `ITEM_USE`
*   `SHOP_BUY`, `SHOP_SELL`
*   `TRADE_START`, `TRADE_COMPLETE`
*   `CHEAT_DETECTED`, `CHEAT_WARNING`, `CHEAT_BAN`
*   `PLUGIN_USE`, `PLUGIN_START`, `PLUGIN_STOP`
*   `STORAGE_IN`, `STORAGE_OUT`
*   (更多动作请参考 `org.gms.server.logging.LogAction` 源码)

### 3.2 字段缩写规范 (Schema)
所有日志字段均采用扁平化设计，禁止嵌套 JSON 字符串。为了节省存储空间，一级字段采用缩写。

**基础字段**:

| 字段名 (Key) | 说明 | 示例 |
| :--- | :--- | :--- |
| `ts` | 时间戳 (毫秒) | `1678888888000` |
| `mod` | 业务模块 | `SHOP` (枚举名) |
| `act` | 具体行为 | `SHOP_BUY` (枚举名) |
| `actsou` | 行为来源 (物品溯源专用) | `PLAYER_DROP` |
| `cat` | 分类 (可选) | `PLUGIN_OPERATION` |

**客户端字段**:

| 字段名 (Key) | 说明 | 示例 |
| :--- | :--- | :--- |
| `ip` | IP地址 | `127.0.0.1` |
| `hwid` | 硬件ID | `...` |
| `macs` | MAC地址 | `["00-00-00-00-00-00"]` |

**角色信息字段**:

| 字段名 (Key) | 说明 | 示例 |
| :--- | :--- | :--- |
| `aid` | 账号ID | `1` |
| `acc` | 账号名 | `admin` |
| `cid` | 角色ID | `12345` |
| `chr` | 角色名 | `Hero` |
| `lvl` | 角色等级 | `250` |
| `job` | 职业ID | `112` |
| `jobName` | 职业名称 | `英雄` |
| `map` | 地图ID | `100000000` |
| `mapName` | 地图名称 | `射手村` |

**业务字段**:

| 字段名 (Key) | 说明 | 示例 |
| :--- | :--- | :--- |
| `msg` | 详细描述 | `购买物品` |
| `itm` | 物品ID | `4001126` |
| `cnt` | 数量 | `1` |
| `err` | 错误信息 | `NullPointerException...` |
| `mob` | 怪物ID | `100100` |
| `mobName` | 怪物名称 | `蜗牛` |

## 4. Java 接入指南

### 4.1 核心原则
*   **使用枚举**: 必须使用 `LogModule` 和 `LogAction` 枚举，禁止使用魔法字符串。
*   **直接传递对象**: 必须使用 `MapMessage` 对象传递数据，由 `AuditLogger` 负责序列化。
*   **国际化**: 日志消息的国际化文本通过枚举的 `getI18nVal()` 方法在后端直接生成。

### 4.2 代码示例
在任何业务代码中，只需调用 `AuditLogger` 即可。

```java
import org.apache.logging.log4j.message.MapMessage;
import org.gms.server.logging.AuditLogger;
import org.gms.server.logging.LogModule;
import org.gms.server.logging.LogAction;

// 示例：记录商店购买日志
MapMessage data = new MapMessage()
    .with("itm", item.getItemId())
    .with("cnt", quantity)
    .with("cost", price);

// AuditLogger 会自动注入 acc, chr, jobName, mapName 等上下文信息
// 日志的模块和动作将使用其国际化文本
AuditLogger.info(LogModule.SHOP, LogAction.SHOP_BUY, data);
```

**底层实现 (AuditLogger.java)**:
```java
// 1. 自动注册模块
moduleConfig.putIfAbsent(module.name(), true);
// 2. 注入上下文 (AuditContext)
// 3. 使用 FastJson2 序列化为 JSON 字符串
// 4. 写入日志 (PatternLayout %m%n)
log.info(JSON.toJSONString(logMap)); 
```

## 5. 前端功能实现

### 5.1 自定义仪表盘 (Custom Dashboard)
*   **功能**: 允许管理员自由创建监控图表，并保存布局。
*   **技术实现**:
    *   **组件化**: 核心图表逻辑封装在 `LogChart.vue` 中，使用 **Vue-ECharts** 渲染，支持响应式和自动重绘。
    *   **持久化**: 布局配置保存于 `LogSystem/Windows/config/dashboard-layout.json`。
    *   **交互**: 
        *   支持添加、删除图表。
        *   支持 **拖拽排序** (SortableJS)。
        *   支持 **双击标题重命名**。
        *   支持 **点击图表重新配置**。
        *   支持 **拖拽调整图表宽度和高度**。
        *   **网格对齐**: 拖拽和调整大小时显示 16px 间距的网格辅助线，图表尺寸自动对齐网格，确保布局整齐。
    *   **可视化配置**: 提供图形化查询构建器 (Query Builder)，无需手动编写 LogQL。
        *   支持 **Top N (排行)** 查询。
        *   支持 **Sum/Avg/Max/Min** 聚合及数值字段选择。
        *   支持 **自动填充** 过滤条件，下拉列表显示国际化名称。
        *   **日志源选择**: 支持选择 `Audit Log`, `Server Log`, `Error Log`, `Chat Log`, `Packet Log`。
        *   **时间范围选择**: 支持选择 `1h`, `6h`, `12h`, `24h`, `7d`, `30d` 等时间范围。
        *   **查询测试与字段解析**: 允许测试生成的 LogQL 语句，并自动解析返回结果中的字段，动态添加到“分组维度”和“数值字段”选项中，极大提升配置灵活性。
    *   **图表类型**: 支持 **Line (折线图)**, **Bar (柱状图)**, **Pie (饼图)**, **Scatter (散点图)**, **Area (面积图)**, **Radar (雷达图)**, **Funnel (漏斗图)**, **Gauge (仪表盘)**, **Heatmap (热力图)**, **Candlestick (K线图)**。
*   **查询规范**: 必须使用 LogQL 的 Range Query (范围查询)，例如：
    *   `sum by (act) (count_over_time({mod="SHOP"}[1m]))` (统计每分钟商店各动作次数)
*   **智能时间轴**: 图表 X 轴会根据数据的时间跨度自动调整显示格式：
    *   跨度 < 1 天：显示 `HH:mm` (时:分)
    *   跨度 < 30 天：显示 `MM-dd HH:mm` (月-日 时:分)
    *   跨度 >= 30 天：显示 `yyyy-MM-dd` (年-月-日)

### 5.2 业务配置 (Business Config)
*   **功能**: 集中管理日志系统的业务行为，包含模块开关和日志级别。
*   **模块开关 (Module Toggle)**:
    *   细粒度控制每个业务模块 (如 `SHOP`, `LOGIN`) 的日志记录。
    *   支持实时生效，无需重启服务端。
    *   自动识别新注册的模块，并从后端获取其国际化名称。
*   **日志级别 (Log Level)**:
    *   查看并修改 Log4j2 中所有 Logger 的当前级别 (DEBUG/INFO/WARN/ERROR)。
    *   支持针对特定包或类 (Logger Name) 进行单独设置。

### 5.3 高级配置 (Advanced Config)
*   **功能**: 提供可视化的表单界面，用于修改 Loki 和 Promtail 的核心配置，替代易出错的 YAML 文本编辑。
*   **Loki 配置表单**:
    *   **Server**: HTTP/GRPC 端口配置，认证开关。
    *   **Retention**: 日志保留策略 (Retention Period)、压缩设置 (Compaction)。
    *   **Limits**: 查询限制配置 (Max Entries)。
    *   **Storage**: 文件存储路径配置 (Chunks/Rules Directory)。
*   **Promtail 配置表单**:
    *   **Server**: HTTP/GRPC 端口配置。
    *   **Clients**: Loki 推送地址配置。
    *   **Scrape Configs**: 动态管理采集任务 (Job)，支持配置日志路径和 Pipeline Stages (JSON 编辑)。
    *   **Positions**: 偏移量文件路径配置。
*   **运维操作**:
    *   **保存与重启**: 配置保存后，系统会自动提示并执行服务重启操作，确保配置生效。
    *   **配置回显**: 自动读取当前 YAML 配置并解析为表单数据。

### 5.4 日志查询 (Log Query)
*   **功能**: 基于 LogQL 的多维度日志检索。
*   **优化**: 
    *   前端移除了所有旧格式兼容代码，直接解析后端返回的标准 JSON 对象。
    *   支持从 Log4j2 的嵌套 `message` 结构中自动提取 `mod`/`act` 字段。
    *   **国际化**: 模块和动作名称由后端直接提供国际化文本，前端仅负责展示。
    *   **字段扩展**: 支持显示账号、职业、地图、IP、MAC、HWID 等详细信息。
    *   **自动填充**: 支持账号、角色、IP、MAC、HWID 的下拉自动填充搜索。
    *   **分页**: 支持前端分页展示。
    *   **缓存**: 前端会对模块、动作、行为类型、行为来源列表进行缓存，用于在表格中快速将原始值转为显示文本。

## 6. 管理接口 (REST API)

| 路径 | 方法 | 描述 |
| :--- | :--- | :--- |
| `/log/process/status` | GET | 获取 Loki/Promtail 进程状态 (基于 runtime.ini) |
| `/log/process/start` | POST | 启动日志系统 (单例保护) |
| `/log/process/stop` | POST | 停止日志系统 (自动清理僵尸进程) |
| `/log/process/restart` | POST | 重启日志系统 (先停止后启动) |
| `/log/process/reset` | POST | 重置日志系统 (停止 -> 删除 positions -> 启动) |
| `/log/config/all-options` | GET | **(推荐)** 一次性获取所有查询选项列表 (模块, 动作, 行为类型, 行为来源)。 |
| `/log/config/modules` | GET | 获取所有日志模块列表，返回 `[{ "label": "系统", "value": "SYSTEM" }]` 格式。 |
| `/log/config/actions` | GET | 获取所有日志动作列表，返回 `[{ "label": "服务器启动", "value": "SERVER_START" }]` 格式。 |
| `/log/config/module-switches` | GET/POST | 获取/设置模块日志开关。 |
| `/log/config/levels` | GET/POST | 获取/设置 Logger 级别 |
| `/log/query/range` | GET | 查询日志 (返回解析后的 JSON 对象) |
| `/log/query/stats` | GET | 获取日志统计数据 (用于仪表盘) |
| `/log/config/yaml/{fileName}` | GET/POST | 读/写 YAML 配置文件 (Loki/Promtail) |
| `/log/files/{fileName}` | GET/POST | 读/写文本文件 (支持 dashboard-layout.json) |
| `/log/search/account` | GET | 搜索账号 (ID/名称) |
| `/log/search/character` | GET | 搜索角色 (ID/名称) |
| `/log/search/ip` | GET | 搜索 IP |
| `/log/search/mac` | GET | 搜索 MAC |
| `/log/search/hwid` | GET | 搜索 HWID |
| `/v1/traceability/action-types` | GET | 获取物品溯源的行为类型列表。 |
| `/v1/traceability/action-source-types` | GET | 获取物品溯源的行为来源列表。 |

## 7. 部署与运维

### 7.1 自动化脚本 (`start-logging.bat`)
*   **启动即焚**: 脚本采用“启动即焚”模式，完成服务启动或检测到服务已运行后，会自动倒计时 3 秒并关闭窗口，保持桌面整洁。
*   **同步部署**: 主启动脚本 (`start-server.bat`) 使用 `call` 同步调用日志脚本，确保日志系统完全就绪（包括首次下载组件）后才启动游戏服务端，避免日志丢失。
*   **统一配置**: 使用 `config/runtime.ini` 集中管理 Loki、Promtail 的 PID 及上次运行路径 (`LastPath`)。
*   **一步到位**: 利用 PowerShell 管道技术，在启动进程的同时直接将 PID 写入配置文件，避免了临时文件的创建和读取，提高了脚本的健壮性。
*   **自动修复**: 启动时若检测到状态不一致（如 PID 文件存在但进程丢失），会自动清理残留并重启。
*   **防卡死**: 遇到错误（如配置文件缺失）时，脚本会提示并倒计时 5 秒后自动退出。

### 7.2 国际化支持
*   **后端驱动**: `LogModule` 和 `LogAction` 枚举类现在包含 `getI18nVal()` 方法，直接从后端的 `.properties` 文件加载国际化文本。
*   **前端简化**: 前端不再需要维护模块和动作的语言包，直接从 `/log/config/*` 等接口获取显示文本。
*   **语言包**: 后端语言包位于 `src/main/resources/i18n/log_*.properties`。
