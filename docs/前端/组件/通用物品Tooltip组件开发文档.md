# 通用物品 Tooltip 组件开发文档

## 1. 项目背景与目标

本项目旨在为 `gms-ui` 前端开发一套高度还原冒险岛（MapleStory）游戏内风格的物品展示组件（Tooltip）。该组件将用于在网页端展示装备、消耗品、设置道具等各类物品的详细信息，包括属性、描述、潜能、有效期等，提供与游戏内一致的视觉体验。

## 2. 功能需求

### 2.1 基础 UI 规范
*   **尺寸**: 固定宽度 `300px`，高度根据内容自适应。
*   **背景**: 深色半透明背景 (`rgba(0, 0, 0, 0.85)`)，圆角边框。
*   **字体**: 白色为主，特殊字段使用游戏内特定颜色（如橙色 `#FF9900`）。
*   **国际化**: 所有显示文字信息均需支持国际化（中英文）。

### 2.2 详细布局规范 (Updated)
根据最新需求，Tooltip 内容布局顺序如下：

1.  **拥有者 (Owner)**
    *   位置：名称上方居中。
    *   样式：橙色文字。
    *   条件：若 `owner` 字段存在则显示。

2.  **物品名称 (Name)**
    *   位置：居左显示。
    *   强化等级：若 `level > 0`，在名称右侧显示 `(+level)`。
    *   **物品ID (Item ID)**:
        *   位置：名称下方。
        *   格式：`ID: {itemId}`。

3.  **Flag 标识 (Flags)**
    *   位置：名称下方居中。
    *   内容：`flag` 字段对应的文字内容，多个 flag 用逗号分隔。
    *   样式：橙色文字。

4.  **有效期/封印时间 (Expiration)**
    *   位置：Flag 下方。
    *   内容：
        *   若为封印状态：显示 "封印至 yyyy-mm-dd hh:mm:ss" (Lock until ...)。
        *   若为普通有效期：显示 "使用期限到 yyyy-mm-dd hh:mm:ss" (Time Available ...)。
    *   条件：若有时间限制则显示。

5.  **装备要求 (Requirements)**
    *   布局：标签文字居右，属性文字居左，并排显示。
    *   内容列表：
        *   要求等级 (Req Level)
        *   要求力量 (Req STR)
        *   要求敏捷 (Req DEX)
        *   要求智力 (Req INT)
        *   要求运气 (Req LUK)
        *   要求人气 (Req Fame)
        *   道具等级 (Item Level): `itemLevel` 字段值
        *   道具经验 (Item Exp)
    *   **职业要求**:
        *   位置：要求属性下方，横排显示。
        *   内容：新手 战士 魔法师 弓箭手 飞侠 海盗。
        *   样式：可用职业为白色，禁用职业为红色。

6.  **装备属性 (Attributes)**
    *   布局：标签文字居右，属性文字居左，并排显示。
    *   内容列表：
        *   分类 (Category)
        *   力量 (STR)
        *   敏捷 (DEX)
        *   智力 (INT)
        *   运气 (LUK)
        *   HP
        *   MP
        *   攻击力 (Weapon Attack)
        *   魔法力 (Magic Attack)
        *   防御力 (Weapon Def)
        *   魔法防御力 (Magic Def)
        *   命中率 (Accuracy)
        *   回避率 (Avoidability)
        *   手技 (Hands)
        *   移动速度 (Speed)
        *   跳跃力 (Jump)
        *   **防滑/防寒 (Spikes/Cold)**:
            *   位置：可升级次数上方。
            *   内容：添加防滑 (Add Spikes) / 添加防寒 (Add Cold Protection)。
            *   条件：若 `flag` 包含对应标识。
        *   可升级次数 (Upgrade Slots)
        *   金锤子次数 (Hammer Slots)

7.  **描述 (Description)**
    *   位置：属性下方。
    *   条件：若有描述则显示。

8.  **宿命剪刀 (Karma Scissors)**
    *   位置：最下方。
    *   内容："使用宿命剪刀，可以使物品交易1次" (Use Karma Scissors to enable trade once)。
    *   条件：若 `flag` 包含宿命剪刀标识。

## 3. 组件设计

### 3.1 组件拆分
为了处理装备与普通道具截然不同的展示结构，将组件拆分为两个：

| 组件名 | 用途 | 适用类型 |
| :--- | :--- | :--- |
| `EquipTooltip.vue` | 展示装备详细属性 | Equip (ID < 2000000) |
| `ItemTooltip.vue` | 展示普通物品描述 | Use, Setup, Etc, Cash (ID >= 2000000) |

### 3.2 数据结构 (Props)
组件接收统一的 `item` 对象作为 prop。为了保证向后兼容性和灵活性，`EquipTooltip.vue` 内部实现了一个 `normalizedItem` 计算属性，用于适配两种不同风格的 JSON 字段名。

**组件内部使用的标准字段名 (全称):**
```typescript
interface NormalizedItemInfo {
  itemId: number;
  name?: string;
  desc?: string;     // 描述
  quantity?: number;
  owner?: string;    // 拥有者
  expiration?: number; // 过期/封印时间戳
  flag?: number;     // 位掩码
  
  // 装备要求
  reqLevel?: number;
  reqJob?: number;
  reqStr?: number;
  reqDex?: number;
  reqInt?: number;
  reqLuk?: number;
  reqPop?: number; // Fame

  // 装备属性
  str?: number;
  dex?: number;
  intel?: number; // Changed from int_ to intel
  luk?: number;
  hp?: number;
  mp?: number;
  watk?: number;     // 物理攻击
  matk?: number;     // 魔法攻击
  wdef?: number;     // 物理防御
  mdef?: number;     // 魔法防御
  acc?: number;      // 命中
  avoid?: number;    // 回避
  speed?: number;
  jump?: number;
  hands?: number;
  upgradeSlots?: number; // 剩余升级次数
  vicious?: number;      // 金锤子次数 (Hammer Slots)
  level?: number;    // 强化等级 (+N)
  itemLevel?: number; // 成长等级
  itemExp?: number;   // 道具经验 (假设字段名)
}
```

**兼容的传入字段 (新旧两种):**
组件可以接收包含以下任意一种或混合字段名的 `item` 对象：
1.  **旧版 (全称)**: `itemId`, `quantity`, `name`, `owner`, `expiration`, `str`, `dex`, `int`, `luk`, `hp`, `mp`, `watk`, `matk`, `wdef`, `mdef`, `acc`, `avoid`, `hands`, `speed`, `jump`, `upgradeSlots`, `level`, `itemLevel`, `flag`, `vicious`
2.  **新版 (缩写)**: `id`, `qty`, `nm`, `own`, `exp`, `s`, `d`, `i` (或 `int_`), `l`, `h`, `m`, `wa`, `ma`, `wd`, `md`, `ac`, `av`, `hd`, `sp`, `jp`, `us`, `lv`, `il`, `f`, `vc`

`normalizedItem` 计算属性会通过 `raw.id || raw.itemId` 这样的逻辑，优先使用缩写字段，如果不存在则使用全称字段，最终输出一个标准化的对象供模板使用。

## 4. 功能对照表 (Mapping)

### 4.1 装备属性映射

| 前端显示标签 (Key) | 对应字段 | 备注 |
| :--- | :--- | :--- |
| **REQ LEV** | `reqLevel` | |
| **REQ STR** | `reqStr` | |
| **REQ DEX** | `reqDex` | |
| **REQ INT** | `reqInt` | |
| **REQ LUK** | `reqLuk` | |
| **REQ FAME** | `reqPop` | |
| **Item Level** | `itemLevel` | |
| **Item Exp** | `itemExp` | |
| **Category** | (Calculated) | 根据 ItemID 推断 |
| **STR** | `str` | |
| **DEX** | `dex` | |
| **INT** | `int` | |
| **LUK** | `luk` | |
| **MaxHP** | `hp` | |
| **MaxMP** | `mp` | |
| **WEAPON ATTACK** | `watk` | |
| **MAGIC ATTACK** | `matk` | |
| **WEAPON DEF** | `wdef` | |
| **MAGIC DEF** | `mdef` | |
| **ACCURACY** | `acc` | |
| **AVOIDABILITY** | `avoid` | |
| **Hands** | `hands` | |
| **SPEED** | `speed` | |
| **JUMP** | `jump` | |
| **Add Spikes** | `SPIKES` (Flag) | 防滑 |
| **Add Cold Protection** | `COLD` (Flag) | 防寒 |
| **NUMBER OF UPGRADES AVAILABLE** | `upgradeSlots` | |
| **Hammer Slots** | `vicious` | 金锤子次数 |

### 4.2 Flag 标识映射

| 显示文本 | Flag 位 | 值 (Hex) |
| :--- | :--- | :--- |
| **Lock until** | `LOCK` | `0x01` |
| (图标/特效) | `SPIKES` | `0x02` |
| (图标/特效) | `COLD` | `0x04` |
| **Untradeable** | `UNTRADEABLE` | `0x08` |
| **Tradable once with Karma Scissors** | `KARMA` | `0x10` |
| **Account Sharing** | `ACCOUNT_SHARING` | `0x100` |

## 5. 开发计划与进度

### 阶段一：基础组件实现 (已完成)
- [x] 创建 `src/utils/mapleStoryItem.ts` 工具类 (Flag定义, 分类判断, 富文本解析)。
- [x] 创建 `EquipTooltip.vue` 组件框架。
- [x] 创建 `ItemTooltip.vue` 组件框架。
- [x] 实现基础属性渲染与隐藏逻辑。
- [x] 实现 CSS 样式复刻。

### 阶段二：逻辑完善 (已完成)
- [x] 完善 `getEquipCategory` 逻辑，覆盖所有装备类型。
- [x] 实现 `level` (强化) 与 `itemLevel` (成长) 的区分显示。
- [x] 实现基于 Flag 的时间显示逻辑 (Lock vs Expire)。
- [ ] **待验证**: 在实际页面 (`ItemSelector` 或 `Duey`) 中集成测试，验证样式兼容性。

### 阶段三：后端接口对接 (已完成)
- [x] **需求**: 后端 `ItemInfoRtnDTO` 缺失 `reqLevel` (穿戴等级) 等静态属性。
- [x] **后端实现**: 
    - 扩展 `EquipmentInfoRtnDTO`，增加 `reqLevel`, `reqJob`, `reqStr`, `reqDex`, `reqInt`, `reqLuk`, `reqPop` 字段。
    - 更新 `CommonService.getEquipmentInfoByItemId`，调用 `ItemInformationProvider.getEquipStats` 填充上述字段。
- [x] **前端对接**: 更新 `EquipTooltip.vue`，优先使用 props 中的 `reqLevel`，移除或保留异步获取作为兜底。

### 阶段四：集成与优化 (进行中)
- [x] **集成**: 在 `Duey/list/index.vue` 中引入 `EquipTooltip` 和 `ItemTooltip`。
- [x] **交互**: 使用 `<a-popover>` 实现鼠标移入显示 Tooltip。
- [x] **性能**: 使用 `keep-alive` 和异步组件加载，优化 Tooltip 渲染性能。

### 阶段五：新版布局与国际化 (已完成)
- [x] **布局调整**: 根据最新文档调整 `EquipTooltip.vue` 的 DOM 结构和 CSS。
- [x] **国际化**: 提取所有硬编码文本到 `gms-ui/src/components/ToolTip/locale` (zh-CN, en-US)，实现语言切换。
- [x] **新增字段**: 对接 `reqStr`, `reqDex` 等新增属性的显示。
- [x] **职业要求**: 实现职业要求的红白颜色判断逻辑。

### 阶段六：细节优化 (进行中)
- [x] **ID显示**: 在名称下方增加显示物品ID。
- [x] **图标缩放**: 将物品图标缩放比例调整为 1.5 倍。
- [x] **防滑/防寒**: 在可升级次数上方添加防滑、防寒标记显示。

### 阶段七：兼容性改造 (已完成)
- [x] **需求**: 适配后端返回的、字段名经过缩写的新版 JSON 结构。
- [x] **实现**:
    - 在 `EquipTooltip.vue` 中增加 `normalizedItem` 计算属性。
    - 该属性作为适配器，将传入的、可能包含缩写字段 (`id`, `qty`, `nm`, `s`, `d` 等) 的 `item` prop，转换为模板内部使用的、包含全称字段 (`itemId`, `quantity`, `name`, `str`, `dex` 等) 的标准化对象。
    - 更新模板，使其所有数据绑定均指向 `normalizedItem`，从而实现对新旧两种数据结构的无缝兼容。

### 阶段八：性能与响应优化 (已完成)
- [x] **需求**: 解决在列表中快速移动鼠标时，Tooltip 组件因重复创建导致大量并发请求的问题，并提升组件加载的响应速度。
- [x] **实现**:
    1.  **引入 Promise 缓存机制**:
        *   在 `EquipTooltip.vue` 和 `ItemTooltip.vue` 的模块级别（`<script lang="ts">` 块）创建了 `Map` 对象作为缓存 (`equipInfoPromiseCache`, `itemInfoPromiseCache`)。
        *   该缓存 **存储的是网络请求的 Promise 实例，而不是请求结果**。
        *   当组件需要获取数据时，会先根据 `itemId` 检查缓存。如果缓存中存在对应的 Promise，则直接 `await` 这个 Promise；如果不存在，则发起新的网络请求，并将返回的 Promise 存入缓存。
        *   **核心优势**: 此机制从根本上解决了并发请求和竞态条件。即使多个组件实例同时请求同一个 `itemId`，也只有第一个实例会触发网络请求，后续所有实例都会共享并等待同一个请求的完成。
    2.  **优化数据获取逻辑 (立即显示，后台补充)**:
        *   组件在创建时，会 **立即使用并显示 `props` 中传入的所有数据**。这确保了最快的初始响应速度。
        *   之后，组件会检查 `props` 中的数据是否完整。只有当缺少某些字段（如 `reqLevel` 或 `desc`）时，才会触发异步的 `fetch` 函数。
        *   `fetch` 函数会利用上述的 Promise 缓存机制来获取缺失的数据，并更新到视图上。
    3.  **精简 `watch` 侦听器**:
        *   将 `watch` 的侦听目标从整个 `item` 对象 (`{ deep: true }`) 优化为只侦听 `itemId`。这确保了只有在 `itemId` 真正改变时才触发数据获取逻辑，避免了不必要的性能开销。

## 6. 目录结构说明

```
src/
├── components/
│   └── ToolTip/
│       ├── EquipTooltip.vue    # 装备展示组件
│       └── ItemTooltip.vue     # 道具展示组件
│       └── locale/             # 国际化文件
│           ├── zh-CN.ts
│           └── en-US.ts
├── utils/
│   └── mapleStoryItem.ts       # 物品相关工具函数 (Flag, Category, Parser)
└── api/
    └── information.ts          # 信息查询接口
```

## 7. 注意事项
1.  **图片资源**: 图标依赖 `maplestory.io` API，需确保网络连通性。
2.  **多语言**: 必须使用 `vue-i18n` 进行文本管理，禁止硬编码中文。
3.  **性能**:
    *   **数据获取**: 组件已实现高效的 **Promise 缓存机制**。当需要获取物品的默认属性或描述时，会优先从模块级缓存中查找正在进行的请求。这可以有效防止在列表渲染中因快速划过多个物品而导致的大量并发请求。
    *   **数据传递**: 调用方应尽量提供完整的 `item` 对象（包含名称、描述、穿戴要求等），以实现最快的初始渲染速度。组件会优先展示传入的数据，仅在数据不完整时才触发后台请求作为补充。

## 8. 开发规范与要求 (新增)
1.  **文档更新**: 每次修改代码后，必须同步更新本文档的进度和内容，**只能新增，禁止删除旧记录**，以保持开发历史的可追溯性。
2.  **前端规范**: 严格遵守 `gms-ui/docs/前端开发规范与流程.md`，包括：
    *   使用 `src/api/` 封装接口。
    *   保持代码风格一致 (Prettier)。
    *   使用 TypeScript 类型定义。
    *   组件命名遵循 PascalCase。
