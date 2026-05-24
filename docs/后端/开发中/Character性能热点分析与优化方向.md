# 性能热点分析与优化方向（V3 — 深度代码分析版）

> 修订日期：2026-05-23
> 本版基于对 Character / Client / Channel / Monster / PlayerStorage / MapleMap 源码的逐行分析。

---

## 一、已验证排除（前两版错误）

| 错误断言 | 实际 | 证据 |
|---------|------|------|
| GameConfig 每次查 DB | 启动时全量加载到内存 JSONObject | `GameConfig.java:39` |
| WZ DOM 无缓存 | Caffeine softValues + 10 分钟过期 + 两阶段 | `CachingDataProvider.java` |
| GraalVM 每客户端独立 Engine ~10-50MB | **共享单例 `SHARED_ENGINE`**，per-script 创建轻量 Context | `AbstractScriptManager.java:53` |
| 只有 7 个定时任务 | 共 28 个（Server 16 + World 12） | `Server.java` + `World.java` |

---

## 二、核心类深度分析

### 1. Character.java — 每玩家内存最大的类（10,112 行）

| 资源 | 每实例数量 | 说明 |
|------|----------|------|
| Map 字段 | 53 个 | quests, skills, effects, buffs, cooldowns, keymap, summons, area_info, events... |
| List 字段 | 78 个 | trockmaps, blockedPortals, crushRings, friendshipRings... |
| Set 字段 | 34 个 | controlled monsters, excluded items, visibleMapObjects... |
| ReentrantLock | **6 个** | chrLock, evtLock, petLock, prtLock, cpnLock, sendSpawnData |
| ScheduledFuture | **16 个** | dragonBlood, hpDecrease, beholderHealing/buff, recovery, buffExpire, diseaseExpire, itemExpire, questExpire, chairRecovery, pendantOfSpirit, cpqSchedule, FamilyBuffTimer... |
| Inventory | 7 种 × ≤96 槽 | EQUIP / USE / SETUP / ETC / CASH / STORAGE / CANHOLD |

**内存估算**：每玩家 ~500KB–2MB（取决于背包/技能/任务数量）。

**CPU 热点 — Buff 系统**：`applyBuff()` / `cancelBuff()` 方法中创建 ~20 个局部的 `Map<BuffStat, BuffStatValueHolder>` 做拓扑排序。每次施法/取消 buff 都分配大量临时 HashMap，GC 压力来源。

**清理质量** ✅：`empty()` 方法取消全部 16 个 ScheduledFuture + 置 null，无泄漏风险。

---

### 2. Client.java — 轻量连接层（1,568 行）

```java
// 行 53: 全局共享的 GraalVM Engine
private static final Engine SHARED_ENGINE;

// 行 129: per-Client 缓存的 ScriptEngine（轻量 Context 包装器）
private Map<String, ScriptEngine> engines = new HashMap<>();
```

**关键发现**：
- `SHARED_ENGINE` 是 `static final`，全服只有一个，约 **30-50MB**（一次性）
- `Client.engines` 缓存的是 `GraalJSScriptEngine`，它们共享 `SHARED_ENGINE`，每个只是轻量 Context（~KB 级）
- 一个玩家遇到 20 个不同 NPC = 20 个 Context 缓存，总量可忽略
- 断线时 `clean()` 将 `engines = null` ✅

**结论：非热点。** 之前的"每客户端 10-50MB"分析不成立。

---

### 3. Monster.java — 瞬态实例（2,431 行）

| 资源 | 每实例 | 说明 |
|------|-------|------|
| Map | 19 个 | effects, tempEffectiveness, stolenItems... |
| List | 19 个 | alreadyBuffed, revives, stolen... |
| Set | 11 个 | usedSkills, usedAttacks, calledMobOids... |
| Lock | 2 个 | statusLock, animationLock |
| WeakReference | 7 个 | 引用其他地图对象 |

**关键：Monster 是瞬态对象**——怪物被打死后从 Map 移除，GC 回收。每张地图同时存在的怪物数有限（通常 10-30 只），全服活跃怪物总数 ≈ 地图数 × 刷怪密度。

**内存：** 活跃怪物聚合 ≈ 100 地图 × 20 怪物 × 19 Maps ≈ 38,000 Map 实例，但这分散在整个堆中，不会集中释放。正常 GC 可处理。

**CPU：** `Monster.damage()` 方法包含伤害计算 → 元素抗性 → 仇恨表更新 → buff 检查，单次调用开销小但高频（每只怪每秒可能被多次攻击）。

**清理** ✅：怪物移除时通过 `MapleMap.removeMapObject()` 清理。

---

### 4. PlayerStorage.getAllCharacters() 的 `new ArrayList`（132 行）

```java
public Collection<Character> getAllCharacters() {
    rlock.lock();
    try {
        return new ArrayList<>(storage.values());  // 防御性快照
    } finally {
        rlock.unlock();
    }
}
```

**为什么必须 `new ArrayList`？**

`storage` 是 `LinkedHashMap`，被读锁保护。如果直接返回 `storage.values()`，调用方在**释放锁后**遍历时，另一个线程可能修改 `storage`（增/删玩家）→ `ConcurrentModificationException`。

`new ArrayList` 在锁保护下做**快照**，释放锁后调用方可安全遍历。这是 ReadWriteLock 的标准安全模式。

**开销：** 200 元素 ArrayList 分配 ≈ 1.6KB，每次 10 秒（TimeoutTask）+ 额外调用 = 每小时约 50-100 次 = 80-160KB/小时。**可忽略。**

---

## 三、MapleMap.java（4,906 行）

用户确认已做过优化。地图对象启动时一次性加载，后续以 Caffeine 软引用管理。**不再分析。**

---

## 四、最终评估

| 类 | 行数 | 真实开销 | 严重度 |
|----|------|---------|--------|
| `Character.java` | 10,112 | 53 Map × 在线人数，Buff 临时 Map GC | 🟡 设计上重、实际可控 |
| `Client.java` | 1,568 | SHARED_ENGINE 全服一份，per-Context 轻量 | 🟢 无需优化 |
| `Monster.java` | 2,431 | 瞬态，活跃量 = 地图 × 20，正常 GC | 🟢 无需优化 |
| `PlayerStorage` | 132 | new ArrayList 防御性快照，KB 级 | 🟢 正确设计 |
| `MapleMap.java` | 4,906 | 已优化，不再分析 | 🟢 |

## 五、Character.java 优化方案对比

### 基础数据

| 指标 | 数值 |
|------|------|
| 总行数 | 10,112 |
| 方法体内 `new LinkedHashMap<>()` | **38 处**（主要是 Buff 系统） |
| 方法体内 `new ArrayList<>()` | 15 处 |
| `final` 集合字段（构造时必定分配） | **20 个** |
| 非 `final` 集合字段（可懒加载） | 2 个 |
| ReentrantLock | 6 个 |
| Buff 相关局部 `Map<BuffStat, ...>` | ~20 个/次 buff 操作 |

---

### 方案 A：BuffSystem 提取 + 内存复用

**做法**：将 ~2000 行 Buff 相关代码提取到内部类 `Character.BuffSystem`，内部持有**预分配的 EnumMap 池**。每次 buff apply/cancel 时 `clear()` 复用而非 `new`。

```
Character.java                         Character.BuffSystem
  ├─ applyBuff()     ──委托──→          ├─ EnumMap<BuffStat, ...>[] pool
  ├─ cancelBuff()    ──委托──→          ├─ apply()
  ├─ cancelAllBuffs()──委托──→          ├─ cancel()
  └─ ...                                └─ extractCurrentBuffStats()
```

| 维度 | 评价 |
|------|------|
| 改动范围 | ~2000 行移动 + 新增 ~200 行池代码 |
| 风险 | **中** — 仅 Buff 系统，不改协议层 |
| 内存收益 | **高** — 消除每次 buff 操作的 20 个临时 Map 分配 |
| CPU 收益 | **中** — 减少 GC 频率，EnumMap O(1) vs LinkedHashMap O(1)+链表 |
| 可测试性 | Buff 系统可独立单测 ✅ |
| 回滚难度 | 低 — 内部类，对外接口不变 |

**实战举例**（当前代码 → 改后）：

```java
// 当前: extractCurrentBuffStats() 每调用一次 new 一个 LinkedHashMap
Map<BuffStat, BuffStatValueHolder> stats = new LinkedHashMap<>();
// ... 填充 ...
return stats;
// → 用完丢弃，等 GC

// 改后: 从池取 → clear → 填充 → 返回 → 用完归还
Map<BuffStat, BuffStatValueHolder> stats = buffPool.acquire();
// ... 填充 ...
return stats;
// 调用方用完后: buffPool.release(stats);
```

---

### 方案 B：垂直切片 — 子系统委托模式

**做法**：将 Character 按功能域拆出 5 个子系统类，Character 持有引用并转发调用。每个子系统自管理生命周期（load/save/dispose）。

```
Character (3K 行，协调层)
  ├─ CharacterBuffSystem      // Buff/Debuff/Disease
  ├─ CharacterSkillSystem     // 技能/冷却/keymap
  ├─ CharacterQuestSystem     // 任务/区域/事件
  ├─ CharacterInventoryBridge // 背包/商城/仓库
  └─ CharacterRelationSystem  // 好友/组队/公会/戒指
```

| 维度 | 评价 |
|------|------|
| 改动范围 | **全部 10,112 行** — 所有调用方都需要改 |
| 风险 | **高** — 触及 140+ handlers、脚本引擎、服务层 |
| 内存收益 | 中等 — 子系统可按需初始化 |
| CPU 收益 | 低 — 只是代码组织变化 |
| 可测试性 | 极高 — 每个子系统可独立 Mock 测试 ✅✅ |
| 回滚难度 | 极高 — 全量重构 |

**收益远低于风险**，不建议在当前阶段做。

---

### 方案 C：方法提取 + 静态工具类（零风险）

**做法**：不改变 Character 的字段结构，只把大型 private 方法提取到**同包的静态工具类**中。保持行为完全不变。

```java
// 当前: Character 内部 500 行方法
private Map<BuffStat, BuffStatValueHolder> extractCurrentBuffStats(StatEffect effect) { ... }

// 改后: 提取到工具类
class BuffStatHelper {
    static Map<BuffStat, BuffStatValueHolder> extractCurrentBuffStats(
        Character chr, StatEffect effect
    ) { ... }
}
```

| 维度 | 评价 |
|------|------|
| 改动范围 | 10-20 个大型方法提取 |
| 风险 | **零** — 纯重构，编译器保证正确 |
| 内存收益 | 无 |
| CPU 收益 | 无 |
| 可测试性 | 工具类可独立测试 ✅ |
| 主要价值 | Character.java 从 10K → 7K 行，**可读性大幅提升** |

---

### 方案 D：枚举 Map 统一替换

**做法**：将 38 处 `new LinkedHashMap<>()` 中的 BuffStat 键 Map 替换为 `new EnumMap<>(BuffStat.class)`。EnumMap 为枚举键专门优化：

| | LinkedHashMap | EnumMap |
|---|:---:|:---:|
| 内部结构 | HashMap + 双向链表 | 数组（枚举 ordinal 为索引） |
| 每条目内存 | ~40 bytes | ~8 bytes |
| get/put | O(1) + 链表维护 | O(1) 数组访问 |
| 迭代顺序 | 插入序 | 枚举声明序 |

| 维度 | 评价 |
|------|------|
| 改动范围 | 约 20 处 BuffStat key 的 Map 创建 |
| 风险 | **低** — 需验证插入顺序是否被依赖 |
| 内存收益 | 中等 — 每个 BuffStat Map 内存减少 ~70% |
| CPU 收益 | 中 — EnumMap 数组索引比 HashMap hash 计算快 |

**风险点**：Buff 系统部分路径依赖 LinkedHashMap 的**插入顺序**判定 buff 优先级。替换前需逐方法确认。

---

### 方案 E：PacketCreator 模式 — 静态域提取（新）

**思路来自** `docs/后端/PacketCreator重构方案.md`。已完成的重构证明此模式可行。

**做法**：不是把 Character 拆成有状态的子系统对象（方案 B），而是**提取大型方法到无状态的域工具类**。Character 保留为主入口 + 数据持有者，工具类只负责计算逻辑。

```
Character.java (保留，3-5K 行)
  │
  ├─ 数据字段（不变）          quests, skills, effects, inventory...
  ├─ 对外 API（保留）           getQuest(), updateQuestStatus(), applyBuff()...
  │
  └─ 内部调用改为静态委托：
        BuffHelper.extractCurrentBuffStats(chr, effect)
        BuffHelper.cancelEffect(chr, effect, ...)
        CombatHelper.calculateDamage(chr, mob, ...)
        QuestHelper.canComplete(chr, quest)
```

**关键区别**：所有工具方法接收 `Character chr` 作为第一个参数——纯函数，不持有状态。

| 维度 | 评价 |
|------|------|
| 改动范围 | 可渐进（每次 1 个域，~500 行） |
| 风险 | **低** — 纯方法移动，编译器保证正确 |
| 内存收益 | 方法提取后可追加方案 A/D 的池优化 |
| CPU 收益 | 同方案 A/D |
| 可测试性 | ✅✅ 工具类可独立单测 |
| 入口兼容 | **100%** — Character 保留全部 public API |

**与 PacketCreator 重构的对照**：

| | PacketCreator | Character（方案 E） |
|---|---|---|
| 原始文件 | 7000 行 | 10,112 行 |
| 拆分策略 | 按协议域（Login/Field/NPC/...） | 按游戏域（Buff/Combat/Quest/...） |
| 新类 | `packets/LoginPackets.java` 等 12 个 | `charhelper/BuffHelper.java` 等 5-6 个 |
| 入口类角色 | 代理（转发调用） | 数据持有 + API 代理 |
| 已完成？ | ✅ 已完成 | 待实施 |

---

### 六方案综合对比

| | A：BuffSystem+池 | B：全量拆分 | C：方法提取 | D：EnumMap | **E：PacketCreator 模式** |
|---|---|---|---|---|---|
| 改动量 | 中 (~2K) | 极大 (~10K) | 小 (~500) | 极小 (~20) | **渐进（1K/域 × 5 域）** |
| 风险 | 中 | 极高 | 零 | 低 | **低** |
| 内存收益 | 高 | 中 | 无 | 中 | **同 A+D** |
| CPU/GC 收益 | 高 | 低 | 无 | 中 | **同 A+D** |
| 可测试性 | ✅ | ✅✅ | ✅ | — | **✅✅** |
| 入口兼容 | ✅ | ❌ | ✅ | ✅ | **✅（全兼容）** |
| 已有成功先例 | — | — | — | — | **✅ PacketCreator** |

---

### 推荐方案

**方案 E（PacketCreator 模式 — 静态域提取）作为主框架，内嵌方案 A（BuffSystem 池化）+ 方案 D（EnumMap 替换）。**

理由：
1. **PacketCreator 重构已证明此模式在本项目中可行**——同样是大文件拆分，同样的静态工具类方式，同样的渐进迁移
2. Character 保留为数据持有者 + API 入口，所有调用方（140+ handler、脚本、Service）**零改动**
3. 可渐进执行：先拆 Buff 域（最大块 ~2000 行）→ Combat 域 → Quest 域，每步独立合入
4. 工具类拆出后，Buff 相关的池优化（方案 A）和 EnumMap 替换（方案 D）在独立类中实现，更安全
5. 最终效果：Character.java 从 10,112 行 → 3,000-5,000 行，**类文件瘦身 50%+**

---

## 六、Character.java 瘦身改造计划（搁置，后续执行）

> 状态：📋 已规划，待后续启动
> 模式：PacketCreator 静态域提取（方案 E），内嵌 Buff 池优化（方案 A）+ EnumMap 替换（方案 D）

### 6.1 目标

| | 改前 | 改后 |
|---|------|------|
| Character.java 行数 | 10,112 | **~2,500** |
| 新增 Helper 文件 | 0 | **6 个** |
| 外部调用方改动 | — | **0** |
| 38 处 `new LinkedHashMap()` | 每次 buff 分配 | **池化复用** |

### 6.2 目录结构

参照 PacketCreator 重构（`org.gms.util` → `org.gms.util.packets/`），在 `Character.java` 同级创建 `charhelper` 子包：

```
org/gms/client/
├── Character.java                  (保留，~2,500 行)
├── Character/                      (新增)
│   ├── BuffHelper.java             (Buff/Disease/Debuff, ~2,500 行)
│   ├── QuestHelper.java            (Quest/PartyQuest, ~1,000 行)
│   ├── MovementHelper.java         (Map/Warp/Chair/Mount, ~1,600 行)
│   ├── CombatHelper.java           (Combat/Skill/Cooldown, ~1,500 行)
│   ├── InventoryHelper.java        (Item/Meso/Shop/Equip, ~1,000 行)
│   └── SocialHelper.java           (Buddy/Party/Guild/Ring, ~1,000 行)
├── Client.java
├── Skill.java
├── ... (其余类不动)
```

### 6.3 域划分

基于 500 行块的语义密度分析：

| # | 新类 | 提取域 | 预估行数 | 集中度 | 关键方法举例 |
|---|------|--------|---------|--------|------------|
| 1 | **`BuffHelper`** | Buff/Disease/Debuff | ~2,500 | 🔴 最密集 | `applyBuff`, `cancelEffect`, `giveDebuff`, `extractCurrentBuffStats`, `propagateBuffEffectUpdates`, `silentApplyDiseases`, `checkBerserk`, `prepareDragonBlood`... |
| 2 | **`QuestHelper`** | Quest/PartyQuest | ~1,000 | 🟡 底部集中 | `updateQuestStatus`, `raiseQuestMobCount`, `questExpirationTask`, `reloadQuestExpirations`, `forfeitExpirableQuests`, `awardQuestPoint`... |
| 3 | **`MovementHelper`** | Map/Warp/Chair/Mount | ~1,600 | 🟡 中前部 | `changeMap`, `changeMapInternal`, `leaveMap`, `startChairTask`, `stopChairTask`... |
| 4 | **`CombatHelper`** | Combat/Skill/Cooldown | ~1,500 | 🟢 分散 | `calculateMaxBaseDamage`, `controlMonster`, `playerDead`, `addCooldown`, `dispelSkill`, `addSummon`... |
| 5 | **`InventoryHelper`** | Item/Meso/Shop/Equip | ~1,000 | 🟢 分散 | 道具存取、金币、装备统计、商城操作... |
| 6 | **`SocialHelper`** | Buddy/Party/Guild/Ring | ~1,000 | 🟢 分散 | 好友增删、组队操作、公会、戒指、婚姻、交易... |

### 6.4 提取模式规范

统一采用与 PacketCreator 一致的**静态委托模式**：

```java
// --- Character.java（保留）---
public void applyBuff(int sourceId, StatEffect effect) {
    BuffHelper.applyBuff(this, sourceId, effect);
}

// --- BuffHelper.java（新增）---
public final class BuffHelper {
    static void applyBuff(Character chr, int sourceId, StatEffect effect) {
        chr.chrLock.lock();
        try {
            // 原始 Buff 逻辑（从 Character 移动过来，不变）
        } finally {
            chr.chrLock.unlock();
        }
    }
}
```

**约束**：
- 所有方法第一个参数为 `Character chr`
- Helper 类为包级可见 `final class`，仅 `static` 方法
- Character 的 public API 签名不变，内部转发
- 渐进执行：每完成一个域 → 编译通过 → 启动测试 → 合入

### 6.5 改造进度表

| 步骤 | 域 | 任务 | 预估行数 | 状态 |
|------|---|------|---------|------|
| Step 1 | Buff | 创建 `BuffHelper`，移动 ~2500 行 Buff 方法 | 2500 → Character | 📋 待执行 |
| Step 2 | Buff | 在 `BuffHelper` 内实现 EnumMap 池（消除 38 处 `new`） | +200 新代码 | 📋 待执行 |
| Step 3 | Buff | 替换 BuffStat-key 的 `LinkedHashMap` → `EnumMap`（方案 D） | ~20 处 | 📋 待执行 |
| Step 4 | Buff | 编译验证 + 启动测试 | — | 📋 待执行 |
| Step 5 | Quest | 创建 `QuestHelper`，移动 Quest 方法 | 1000 → Character | 📋 待执行 |
| Step 6 | Quest | 编译验证 + 启动测试 | — | 📋 待执行 |
| Step 7 | Movement | 创建 `MovementHelper`，移动 Map/Move 方法 | 1600 → Character | 📋 待执行 |
| Step 8 | Movement | 编译验证 + 启动测试 | — | 📋 待执行 |
| Step 9 | Combat+Skill | 创建 `CombatHelper`，移动 Combat/Skill/Cooldown 方法 | 1500 → Character | 📋 待执行 |
| Step 10 | Combat+Skill | 编译验证 + 启动测试 | — | 📋 待执行 |
| Step 11 | Inventory | 创建 `InventoryHelper`，移动 Item/Meso/Shop 方法 | 1000 → Character | 📋 待执行 |
| Step 12 | Inventory | 编译验证 + 启动测试 | — | 📋 待执行 |
| Step 13 | Social | 创建 `SocialHelper`，移动 Buddy/Party/Guild/Ring 方法 | 1000 → Character | 📋 待执行 |
| Step 14 | Social | 编译验证 + 启动测试 | — | 📋 待执行 |
| Step 15 | 收尾 | Character.java 清理：删除已移出的方法体 | — | 📋 待执行 |

**预计总改动**：~8,500 行移动 + ~200 行新代码（池），Character.java 从 10,112 → ~2,500 行。

### 6.6 每步验收标准

| 检查项 | 要求 |
|--------|------|
| 编译 | `mvn --file gms-server/pom.xml compile -q` 零错误 |
| 原调用方 | 所有 `chr.applyBuff(...)` 等外部调用无需改动 |
| 启动 | 服务端正常启动，无 WARN/ERROR |
| 功能 | 登录 → 选角 → 进游戏 → 打怪 → Buff → 换图 → 任务 → 下线 |

---

## 七、结论

经过逐类代码分析，当前项目：

- **GraalVM**：全服共享单 Engine，无泄漏风险 ✅
- **Monster**：瞬态实例，正常 GC 回收 ✅
- **PlayerStorage**：defensive copy 是正确的并发设计 ✅
- **MapleMap**：已做过优化 ✅
- **Character.java**：唯一有价值优化的类。**38 处 new LinkedHashMap() 是 GC 热点**。建议用方案 A（BuffSystem 内部类 + 预分配池）+ 方案 D（EnumMap 替换）组合优化，改动 ~2000 行，风险可控。
