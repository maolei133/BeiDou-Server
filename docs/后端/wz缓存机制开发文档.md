# WZ 数据加载与缓存机制开发文档

## 1. 背景与问题

本服务端采用 XML 格式存储 WZ 数据。在原始设计中，数据加载通过标准的 DOM (Document Object Model) 解析器进行。实践证明，DOM 解析虽然功能强大，但存在一个致命缺陷：**内存占用巨大**。

一个几 MB 的 XML 文件在解析成 DOM 树后，其内存占用可能膨胀数十倍（例如，一个 3MB 的文件可能占用超过 100MB 内存）。由于这些加载后的数据被长久地保存在内存中，没有有效的释放机制，导致服务器在长时间运行后，内存占用持续增高，最终因内存溢出（OOM）而崩溃。

为了从根本上解决此问题，我们设计并实现了一套全新的、智能的、高性能的 WZ 数据加载与缓存机制。

## 2. 核心设计思想：分类施策

经过深入分析，我们发现服务器内的数据加载行为主要分为两种截然不同的模式：

1.  **“提取-转换”模式 (Extract-Transform)**
    *   **行为**: 模块加载一个 XML 文件，将其完整地解析成 DOM 树，然后遍历这棵树，将所有需要的数据提取出来，并转换成轻量级的 Java 对象（POJO）。一旦转换完成，原始的、庞大的 DOM 树就再也用不到了。
    *   **典型案例**: `SkillFactory`, `CashItemFactory`。
    *   **策略**: **用完即弃 (Load-and-Release)**。

2.  **“部分持有”模式 (Partial-Hold)**
    *   **行为**: 模块加载一个 XML 文件并解析成 DOM 树。但它只在初始化时读取少量顶层数据，其创建的业务对象（如 `Quest` 对象）会继续**持有对原始 DOM 节点的引用**。后续的很多操作，都是在这些被持有的 DOM 节点上进行的“懒加载”或按需查询。
    *   **典型案例**: `Quest`。
    *   **策略**: **长期智能缓存 (Long-Term Smart Caching)**。

基于此，我们的核心思想是：**为不同模式的模块，提供不同的数据加载接口，从源头上实现最精细的内存管理。**

## 3. 两大核心策略详解

我们通过对 `DataProvider` 框架的装饰，实现了一个核心的 `CachingDataProvider` 类，它提供了两种核心的数据获取方法。

### 3.1 用完即弃 (Load-and-Release)

- **接口**: `cachingDataProvider.getDataAndRelease(String path)`
- **工作原理**:
    1.  此方法会直接调用最原始的 `XMLWZFile` 来加载并解析指定的 XML 文件，返回一个包含完整 DOM 树的 `Data` 对象。
    2.  这个加载过程**完全绕过了所有缓存机制**。
    3.  返回的 `Data` 对象没有被任何缓存系统所引用。
    4.  当调用方（例如 `SkillFactory`）使用完这个 `Data` 对象（即完成了数据提取和转换），这个巨大的 DOM 对象就会因为不再有任何引用，而在下一次 GC 中被**立即、彻底地回收**。
- **优势**: 实现了内存的**主动、即时释放**，将“提取-转换”模式模块的内存占用降至最低（仅保留转换后的 POJO 所占用的内存）。

### 3.2 长期智能缓存 (Long-Term Smart Caching)

- **接口**: `cachingDataProvider.getData(String path)`
- **工作原理**: 这是一个复杂但极其健壮的两阶段缓存系统，使用了业界顶级的 `Caffeine` 缓存库。
    1.  **阶段一：启动时 (强引用保护)**
        *   在服务器启动的核心初始化期间，所有通过此方法加载的数据都会被存入一个临时的、基于**强引用**的 `ConcurrentHashMap` 中。
        *   **目的**: 强引用确保了这些核心数据在启动时的高并发、高内存压力下，**绝对不会**被 GC 意外回收，从根本上保证了服务器启动的稳定性。
    2.  **阶段二：运行中 (软引用 + 时间过期)**
        *   当服务器核心初始化**完全结束后**，系统会自动将启动时缓存的所有数据**一次性地转移**到最终的 Caffeine 缓存中。
        *   这个 Caffeine 缓存配置了两种驱逐策略：
            *   `softValues()`: **基于内存压力**。这是主要的内存安全阀。当 JVM 内存开始紧张时，GC 会自动回收这些被软引用持有的 DOM 对象。
            *   `expireAfterAccess(10, TimeUnit.MINUTES)`: **基于访问时间**。如果一个缓存项在 10 分钟内没有被任何代码访问过，它也会被自动驱逐，主动释放“冷数据”占用的内存。
- **优势**: 实现了性能和稳定性的完美平衡。在内存充裕时，数据常驻内存，访问极快；在内存紧张或数据变冷时，又能被自动回收，保证了服务器的长期健康。

## 4. 底层保障：线程安全

在实现缓存机制的过程中，我们发现并修复了原始 `XMLDomMapleData` 类的一个底层设计缺陷：**伪线程安全**。

原始类的 `synchronized` 方法只能保证单个 `XMLDomMapleData` 实例的方法调用是同步的，但无法保证当多个实例引用同一个底层 DOM 节点时，对该节点的操作是线程安全的。

我们的解决方案是：
1.  为 `XMLDomMapleData` 引入一个共享的 `treeLock` 对象。
2.  所有从同一个 XML 文件派生出的 `XMLDomMapleData` 实例，都会共享同一个 `treeLock`。
3.  所有的数据操作方法都改为同步在这个共享的 `treeLock` 上。

这确保了对同一棵 DOM 树的所有操作都是严格串行化的，彻底杜绝了并发访问导致的数据损坏问题，是整个缓存系统能够稳定运行的基石。

## 5. WZ 文件加载分析与优化路线图

下表总结了项目中主要 WZ 文件的加载方、加载模式及其对应的缓存策略和优化潜力。

| WZ 文件 | 主要加载类 | 缓存策略 | POJO 改造潜力与难度 |
| :--- | :--- | :--- | :--- |
| **`Skill.wz`** | [`SkillFactory`](../src/main/java/org/gms/client/SkillFactory.java)<br>[`MobSkillFactory`](../src/main/java/org/gms/server/life/MobSkillFactory.java)<br>[`CarnivalFactory`](../src/main/java/org/gms/server/partyquest/CarnivalFactory.java) | **混合** | **部分已完成** (`SkillFactory` 已改造)。<br>`MobSkillFactory` 潜力巨大/中等。 |
| **`Etc.wz`** | [`CashItemFactory`](../src/main/java/org/gms/server/CashShop.java)<br>[`ItemInformationProvider`](../src/main/java/org/gms/server/ItemInformationProvider.java)<br>[`MakeCharInfoValidator`](../src/main/java/org/gms/client/creator/MakeCharInfoValidator.java)<br>... | **混合** | **部分已完成** (`CashItemFactory` 已改造)。<br>其他类多为临时加载，适合“用完即弃”。 |
| **`List.wz`** | *（零星使用）* | **用完即弃** | **已完成** |
| **`Item.wz`** | [`ItemInformationProvider`](../src/main/java/org/gms/server/ItemInformationProvider.java)<br>[`PetDataFactory`](../src/main/java/org/gms/client/inventory/PetDataFactory.java)<br>[`SpawnPetProcessor`](../src/main/java/org/gms/client/processor/action/SpawnPetProcessor.java) | 长期智能缓存 | **巨大 / 中等** (核心优化目标)。<br>可为 `ItemInformationProvider` 创建 `ItemInfo` POJO。 |
| **`Mob.wz`** | [`LifeFactory`](../src/main/java/org/gms/server/life/LifeFactory.java)<br>[`MobAttackInfoFactory`](../src/main/java/org/gms/server/life/MobAttackInfoFactory.java) | 长期智能缓存 | **巨大 / 中等** (核心优化目标)。<br>可为 `LifeFactory` 创建 `MobInfo` POJO。 |
| **`Npc.wz`** | [`LifeFactory`](../src/main/java/org/gms/server/life/LifeFactory.java)<br>[`Storage`](../src/main/java/org/gms/server/Storage.java)<br>[`PlayerNPCFactory`](../src/main/java/org/gms/server/life/PlayerNPCFactory.java) | 长期智能缓存 | **巨大 / 中等**。<br>可为 `LifeFactory` 创建 `NpcInfo` POJO。 |
| **`Reactor.wz`** | [`ReactorFactory`](../src/main/java/org/gms/server/maps/ReactorFactory.java) | 长期智能缓存 | **巨大 / 中等**。<br>可为 `ReactorFactory` 创建 `ReactorInfo` POJO。 |
| **`Character.wz`** | [`ItemInformationProvider`](../src/main/java/org/gms/server/ItemInformationProvider.java) | 长期智能缓存 | **巨大 / 中等** (应与 `Item.wz` 一同改造)。 |
| **`Map.wz`** | [`MapFactory`](../src/main/java/org/gms/server/maps/MapFactory.java)<br>[`GameConstants`](../src/main/java/org/gms/constants/game/GameConstants.java) | 长期智能缓存 | **巨大 / 极高** (工作量巨大，建议作为长期重构目标)。 |
| **`Quest.wz`** | [`Quest`](../src/main/java/org/gms/server/quest/Quest.java)<br>[`SkillbookInformationProvider`](../src/main/java/org/gms/server/SkillbookInformationProvider.java) | 长期智能缓存 | **有限 / 高** (当前设计严重依赖DOM，改造风险高)。 |
| **`String.wz`** | *（多处使用，如 `MapFactory`, `ItemInformationProvider`, `LifeFactory` 等）* | 长期智能缓存 | **有限 / 高** (牵涉面过广，维持现状是最佳策略)。 |
| **`Sound.wz`** | *（零星使用）* | 长期智能缓存 | **低** (投入产出比低)。 |
| **`UI.wz`** | [`LifeFactory`](../src/main/java/org/gms/server/life/LifeFactory.java) | 长期智能缓存 | **低** (投入产出比低)。 |

## 6. 开发者指南

在后续开发中，当您需要加载 WZ 数据时，请遵循以下准则：

1.  **首先，分析您的加载模式。**
    *   问自己：“我是一次性把这个 XML 里的所有数据都读出来，存到我自己的 List 或 Map 里，然后就再也不需要那个原始的 `Data` 对象了吗？”
    *   **如果是**，那么您就属于“提取-转换”模式。
    *   **如果不是**（例如，您需要将 `Data` 对象作为成员变量长期持有，以便后续反复调用它的 `getChildByPath`），那么您就属于“部分持有”模式。

2.  **然后，选择正确的接口。**
    *   对于 **“提取-转换”** 模式，请使用 `getDataAndRelease()` 方法，以实现最佳的内存性能。
        ```java
        // 示例：
        CachingDataProvider provider = DataProviderFactory.getDataProvider(WZFiles.ETC);
        Data tempData = provider.getDataAndRelease("MyData.img");
        // ... 在这里将 tempData 中的数据提取到你自己的 List<MyObject> 中 ...
        // 方法结束后，tempData 及其包含的巨大DOM树将被自动回收。
        ```
    *   对于 **“部分持有”** 模式，请使用标准的 `getData()` 方法。
        ```java
        // 示例：
        DataProvider provider = DataProviderFactory.getDataProvider(WZFiles.QUEST);
        this.questData = provider.getData("QuestInfo.img"); // 将其作为成员变量持有
        // 后续可以安全地反复调用 this.questData.getChildByPath(...)
        // 其内存将由我们的智能缓存系统自动管理。
        ```

通过遵循以上准则，我们可以共同维护一个高性能、低内存、长期稳定的服务器。
