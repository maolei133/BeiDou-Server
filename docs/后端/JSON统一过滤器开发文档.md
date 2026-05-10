# JSON 统一序列化规范与开发文档

## 1. 目标

为了在特定业务场景下减少数据库存储压力、统一项目技术栈、提高代码可维护性，本项目规定在处理 **快递、仓库、雇佣商店、物品溯源、物品找回** 这五个系统中的 **物品（Item）对象** 序列化时，必须遵循统一的过滤和转换规则。

核心目标是：
1.  **过滤默认值**: 在序列化物品对象时，不将值为 `null`、`0`、`false` 等默认值的字段写入最终的JSON字符串中（即“稀疏存储”）。
2.  **字段名缩写**: 使用统一的、简短的字段名缩写，进一步压缩JSON体积。

**注意**：此规范 **仅限于** 特定系统对物品进行JSON转换的场景，不作为全项目通用的JSON处理标准。

## 2. 技术选型

本项目统一使用 **Jackson (`com.fasterxml.jackson`)** 作为唯一的JSON处理库。

**理由**:
- **Spring Boot 默认集成**: 与框架无缝集成，易于配置和管理。
- **功能强大**: 提供成熟的注解系统，可以进行灵活、声明式的序列化配置。
- **社区庞大**: 拥有最广泛的社区支持和最完善的文档。
- **安全性高**: 拥有良好的安全记录。

**禁止使用**:
- `com.alibaba.fastjson` / `com.alibaba.fastjson2`
- `com.google.gson`
- 其他任何第三方JSON库

## 3. 实现方案

我们通过**分离 `ObjectMapper` 配置**与**面向对象设计**相结合的方式，从根本上保证了特定场景下物品序列化行为的统一，同时避免对其他业务造成影响。

### 3.1. `ObjectMapper` 分离配置

为了避免序列化规则污染全局，我们在 `org.gms.config.JacksonConfig` 中定义了两个独立的 `ObjectMapper` Bean。

```java
@Configuration
public class JacksonConfig {

    /**
     * 提供一个标准的、全局的 ObjectMapper 实例。
     * 这个 Bean 被标记为 {@code @Primary}，是Spring依赖注入时的首选。
     * 它不包含任何特殊的序列化规则，确保项目大部分功能的JSON行为保持默认和可预测。
     */
    @Bean
    @Primary
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

    /**
     * 提供一个专用于“稀疏存储”场景的 ObjectMapper 实例。
     * 核心配置: {@code JsonInclude.Include.NON_DEFAULT}
     * 这个 Bean 有一个特定的名称 "sparseItemObjectMapper"，只能通过 {@code @Qualifier("sparseItemObjectMapper")} 进行注入。
     */
    @Bean
    @Qualifier("sparseItemObjectMapper")
    public ObjectMapper sparseItemObjectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        // 设置序列化规则：不包含值为默认值的字段 (null, 0, false 等)
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_DEFAULT);
        return objectMapper;
    }
}
```

- **`objectMapper`**: 默认的、全局的实例，用于项目中绝大部分的JSON操作。
- **`sparseItemObjectMapper`**: 特殊配置的实例，**仅用于**需要“稀疏存储”的物品序列化场景。它通过 `JsonInclude.Include.NON_DEFAULT` 实现了过滤默认值的功能。

### 3.2. 物品数据转换层 (`toInfoRtnDTO` 模式)

为了配合 `NON_DEFAULT` 规则并实现字段缩写，我们引入了一个专用于物品的**数据传输对象（DTO）层** (`ItemInfoRtnDTO`)。

#### 3.2.1. DTO 定义 (`ItemInfoRtnDTO.java`)

DTO是一个纯粹的POJO。它的所有属性都使用**包装类型**（`Integer`, `Short`, `Long` 等），并通过 `@JsonProperty` 注解指定了缩写。

```java
// org.gms.model.dto.ItemInfoRtnDTO.java
@Setter
@Getter
@JsonIgnoreProperties(ignoreUnknown = true) // 反序列化时忽略未知字段
public class ItemInfoRtnDTO {
    @JsonProperty("id")
    private Integer itemId;
    @JsonProperty("qty")
    private Integer quantity;
    // ... 其他属性
}
```

#### 3.2.2. 转换方法 (`toInfoRtnDTO`)

转换逻辑被内聚到数据对象自身。

- **基类 `Item.java`**:
  ```java
  public ItemInfoRtnDTO toInfoRtnDTO() {
      ItemInfoRtnDTO itemDTO = new ItemInfoRtnDTO();
      itemDTO.setItemId(this.getItemId());
      itemDTO.setQuantity((int) this.getQuantity());
      // ... 只设置非默认值
      if (this.getOwner() != null && !this.getOwner().isEmpty()) {
          itemDTO.setOwner(this.getOwner());
      }
      // ...
      return itemDTO;
  }
  ```

- **子类 `Equip.java`**:
  ```java
  @Override
  public ItemInfoRtnDTO toInfoRtnDTO() {
      ItemInfoRtnDTO dto = super.toInfoRtnDTO(); // 首先获取基础属性
      // 然后只设置值 > 0 的装备特有属性
      if (this.getStr() > 0) dto.setStr(this.getStr());
      if (this.getDex() > 0) dto.setDex(this.getDex());
      // ...
      return dto;
  }
  ```

这种模式确保了：当一个装备的 `str` 属性为 `0` 时，`toInfoRtnDTO()` 方法不会调用 `dto.setStr()`，使得DTO中的 `str` 字段保持为 `null`。这样，`sparseItemObjectMapper` 在序列化时就能正确地将其过滤掉。

### 3.3. 字段缩写规范

为了最大化地节省数据库空间，`ItemInfoRtnDTO` 中的所有字段都使用了缩写。

| 完整字段名 | 缩写 (`@JsonProperty`) | 描述 |
| :--- | :--- | :--- |
| `itemId` | `id` | 物品ID |
| `quantity` | `qty` | 数量 |
| `owner` | `own` | 制造者/所有者 |
| `expiration` | `exp` | 过期时间 |
| `name` | `nm` | 物品名称 |
| `sn` | `sn` | 序列号 (Cash SN) |
| `uid` | `@JsonIgnore` | **不在JSON中存储** |
| `str` | `s` | 力量 |
| `dex` | `d` | 敏捷 |
| `int_` | `i` | 智力 |
| `luk` | `l` | 运气 |
| `hp` | `h` | HP |
| `mp` | `m` | MP |
| `watk` | `wa` | 物理攻击力 |
| `matk` | `ma` | 魔法攻击力 |
| `wdef` | `wd` | 物理防御力 |
| `mdef` | `md` | 魔法防御力 |
| `acc` | `ac` | 命中值 |
| `avoid` | `av` | 回避值 |
| `hands` | `hd` | 手技 |
| `speed` | `sp` | 移动速度 |
| `jump` | `jp` | 跳跃力 |
| `upgradeSlots`| `us` | 可升级次数 |
| `level` | `lv` | 已升级次数 |
| `itemLevel` | `il` | 物品等级 |
| `flag` | `f` | 物品标志 |
| `vicious` | `vc` | 金锤子次数 |

## 4. 适用系统与场景

本序列化规范明确应用于以下系统的物品数据持久化场景：

| 系统名称 | 应用场景 | 数据库字段 | 责任服务 |
| :--- | :--- | :--- | :--- |
| **快递系统** | 在发送快递时，将包裹内的物品序列化为JSON进行备份。 | `dueypackages.item_data` | `DueyService` |
| **仓库系统** | 存入物品时，将物品的核心属性序列化为JSON进行存储。 | `storage_items.item_data` | `StorageService` |
| **雇佣商店** | 上架物品时，将物品的完整属性序列化为JSON进行存储。 | `hired_merchant_items.item_data` | `HiredMerchantService` (示例) |
| **物品溯源系统** | 记录价值品流转时，保存物品的状态快照。 | `item_trace_logs.item_snapshot` | `TraceabilityService` |
| **物品找回系统** | 记录玩家丢弃或出售的价值品信息，以备找回。 | `item_recovery_logs.item_data` | `TraceabilityService` |

## 5. 开发规范（必须遵守）

### 5.1. 如何为新功能启用稀疏存储

如果未来有新的业务系统（例如“拍卖行”）需要对物品进行“稀疏存储”，必须遵循以下步骤：

1.  **找到负责该功能的 Service 类** (例如 `AuctionHouseService`)。
2.  **修改其构造函数**，使用 `@Qualifier("sparseItemObjectMapper")` 注解来精确注入我们配置好的、带过滤规则的 `ObjectMapper`。

**示例**:
```java
// 错误的方式：依赖注入了全局默认的 ObjectMapper
@Service
public class SomeNewService {
    private final ObjectMapper objectMapper;
    // ...
    public SomeNewService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }
    // ...
}

// 正确的方式：通过 @Qualifier 精确注入专用的 ObjectMapper
@Service
public class SomeNewService {
    private final ObjectMapper objectMapper;
    // ...
    public SomeNewService(@Qualifier("sparseItemObjectMapper") ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }
    // ...
}
```

### 5.2. 通用规范

1.  **禁止手动创建 `ObjectMapper`**:
    - **错误**: `ObjectMapper mapper = new ObjectMapper();`
    - **正确 (在Spring Bean中)**: 通过构造函数注入。
    - **正确 (在静态方法或非Spring管理类中)**: `ObjectMapper objectMapper = SpringContextUtil.getBean(ObjectMapper.class);` (注意：这将获取**默认**的`ObjectMapper`，如果需要稀疏存储，应使用 `getBean("sparseItemObjectMapper", ObjectMapper.class)`)。

2.  **禁止直接序列化 `Item` / `Equip` 对象**:
    - **错误**: `objectMapper.writeValueAsString(itemObject);`
    - **正确**: `objectMapper.writeValueAsString(itemObject.toInfoRtnDTO());`

3.  **反序列化**:
    - 从数据库读取JSON字符串后，应使用对应的`ObjectMapper`反序列化为`ItemInfoRtnDTO`。
    - **错误**: `new ObjectMapper().readValue(json, ...)`
    - **正确**: `objectMapper.readValue(json, ItemInfoRtnDTO.class)`

4.  **数据恢复**:
    - 提供了一个全局工具类 `org.gms.util.ItemConverter` 用于将 `ItemInfoRtnDTO` 对象安全地转换回 `Item` 或 `Equip` 对象。
    - **正确**: `Item item = ItemConverter.restoreItemFromDTO(dto);`

## 6. 总结

通过 **`分离ObjectMapper配置` + `toInfoRtnDTO转换模式` + `@JsonProperty缩写`**，我们为特定系统构建了一套健壮、统一、高效的物品JSON序列化体系。所有开发者在处理上述系统的物品持久化，或为新系统添加类似功能时，都必须遵循此文档规定的开发规范。
