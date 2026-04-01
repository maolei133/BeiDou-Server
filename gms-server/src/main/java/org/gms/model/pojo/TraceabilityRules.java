package org.gms.model.pojo;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;
import org.gms.util.UpperCaseNamingStrategy;

import java.util.List;

/**
 * 物品溯源系统动态配置规则对象映射
 * 应用自定义命名策略，将所有字段名序列化为全大写，以统一前后端字段命名。
 */
@Data
@JsonNaming(UpperCaseNamingStrategy.class)
public class TraceabilityRules {

    /** 总开关，分别控制数据库和Loki的记录功能 */
    private Enabled enabled;
    
    /** 记录目标：可精细化控制有价值和无价值物品的日志分别写入哪里 */
    private RecordingTargets recordingTargets;
    
    /** 保留策略：日志在数据库中的最大保留天数和最大存储条数 */
    private Retention retention;
    
    /** 临时禁用开关：用于临时屏蔽某些高频行为的记录 */
    private TemporaryDisables temporaryDisables;
    
    /** 行为开关：决定一个ActionType是否需要被处理 */
    private LogActionSwitches logActionSwitches;
    
    /** 价值判断条件：定义了“有价值物品”的标准 */
    private ValueConditions valueConditions;
    
    /** 性能调优配置 */
    private Performance performance;

    @Data
    @JsonNaming(UpperCaseNamingStrategy.class)
    public static class Enabled {
        /** 是否启用写入到数据库表item_trace_logs */
        private boolean database;
        /** 是否启用并行写入Loki日志系统 */
        private boolean loki;
    }

    @Data
    @JsonNaming(UpperCaseNamingStrategy.class)
    public static class RecordingTargets {
        /** 有价值物品(通过下方的valueConditions判断)的记录目标 */
        private Target valuable;
        /** 无价值物品(普通物品)的记录目标 */
        private Target nonValuable;
    }

    @Data
    @JsonNaming(UpperCaseNamingStrategy.class)
    public static class Target {
        private boolean database;
        private boolean loki;
    }

    @Data
    @JsonNaming(UpperCaseNamingStrategy.class)
    public static class Retention {
        /** 有价值物品在数据库中保留策略 */
        private RetentionDetail valuable;
        /** 无价值物品在数据库中保留策略 */
        private RetentionDetail nonValuable;
    }

    @Data
    @JsonNaming(UpperCaseNamingStrategy.class)
    public static class RetentionDetail {
        /** 最大保留天数 */
        private int days;
        /** 最大存储条数 */
        private long maxCount;
    }

    @Data
    @JsonNaming(UpperCaseNamingStrategy.class)
    public static class TemporaryDisables {
        /** 怪物掉落/拾取记录配置 */
        private DisableDetail LOOT;
        /** 商店购买记录配置 */
        private DisableDetail SHOP_BUY;
    }

    @Data
    @JsonNaming(UpperCaseNamingStrategy.class)
    public static class DisableDetail {
        /** 是否启用该行为的记录 */
        private boolean enabled;
        /** 如果设置为未来的时间戳 (ISO 8601格式)，则在该时间点之前记录将被临时屏蔽 */
        private String disableUntil;
    }

    @Data
    @JsonNaming(UpperCaseNamingStrategy.class)
    public static class LogActionSwitches {
        /** 是否记录 玩家间交易 */
        private boolean TRADE;
        /** 是否记录 玩家丢弃 */
        private boolean DROP;
        /** 是否记录 玩家出售给NPC */
        private boolean SELL;
        /** 是否记录 存入仓库 */
        private boolean STORAGE_IN;
        /** 是否记录 从仓库取出 */
        private boolean STORAGE_OUT;
        /** 是否记录 GM通过命令创造物品 */
        private boolean GM_CREATE;
    }

    @Data
    @JsonNaming(UpperCaseNamingStrategy.class)
    public static class ValueConditions {
        /** 装备类价值判断条件 */
        private Equip equip;
        /** 消耗品/其它物品类价值判断条件 */
        private Item item;
    }

    @Data
    @JsonNaming(UpperCaseNamingStrategy.class)
    public static class Equip {
        /** 装备最低穿戴等级限制（满足即视为有价值） */
        private int minLevel;
        /** 装备最低已砸卷次数（满足即视为有价值） */
        private int minUpgradeSlotsUsed;
        /** 装备最低成长等级（满足即视为有价值） */
        private int minGrowthLevel;
        /** 装备最低金锤子使用次数（满足即视为有价值） */
        private int minViciousHammerUsed;
        /** 装备当前属性总和(不含HP/MP)超过白板属性的最低值（满足即视为有价值） */
        private int minStatsAboveBase;
    }

    @Data
    @JsonNaming(UpperCaseNamingStrategy.class)
    public static class Item {
        /** 投掷武器(飞镖/子弹)的价值判断 */
        private ThrowingWeapons throwingWeapons;
        /** 增益药水的价值判断 */
        private Potions potions;
        /** 检测ID前缀的配置 */
        private List<ItemType> itemTypes;
        /** 强制视为有价值的特定物品ID列表 (如混沌卷轴) */
        private List<SpecificItemId> specificItemIds;
    }

    @Data
    @JsonNaming(UpperCaseNamingStrategy.class)
    public static class ThrowingWeapons {
        /** 是否启用投掷武器的价值判断 */
        private boolean enabled;
        /** 投掷武器(飞镖)的最低攻击力 */
        private int minAttackPower;
        /** 投掷武器(子弹)的最低攻击力 */
        @JsonProperty("MINATTACKPOWER_BULLET")
        private int minAttackPowerBullet;
    }

    @Data
    @JsonNaming(UpperCaseNamingStrategy.class)
    public static class Potions {
        /** 是否启用药水的价值判断 */
        private boolean enabled;
        /** 增益类药水提供的属性总和(力/敏/智/运/攻/魔)的最低值 */
        private int minTotalStatBonus;
    }

    @Data
    @JsonNaming(UpperCaseNamingStrategy.class)
    public static class ItemType {
        /** 物品ID前缀 */
        private int t;
        /** 描述 */
        private String d;
        /** 是否启用此条目 */
        private boolean enabled;
    }

    @Data
    @JsonNaming(UpperCaseNamingStrategy.class)
    public static class SpecificItemId {
        /** 物品ID */
        private int id;
        /** 描述 */
        private String d;
        /** 是否启用此条目 */
        private boolean enabled;
    }

    @Data
    @JsonNaming(UpperCaseNamingStrategy.class)
    public static class Performance {
        /** 忽略记录所有事件的地图ID列表 (如自由市场) */
        private List<IgnoredMapId> ignoredMapIds;
    }

    @Data
    @JsonNaming(UpperCaseNamingStrategy.class)
    public static class IgnoredMapId {
        /** 地图ID */
        private int id;
        /** 描述 */
        private String d;
        /** 是否启用此条目 */
        private boolean enabled;
    }
}
