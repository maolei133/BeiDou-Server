# 内置辅助插件系统使用文档

## 系统架构

### 核心组件

1. **CheatPlugin接口** - 内置辅助插件接口，定义了插件的基本方法
2. **BaseCheatPlugin类** - 内置辅助插件基类，提供了插件的基础实现
3. **CheatManager类** - 管理单个玩家的所有内置辅助插件
4. **CheatModuleManager类** - 管理所有玩家的内置辅助管理器实例
5. **CheatPluginFactory类** - 内置辅助插件工厂，负责创建插件实例

### 插件生命周期

插件遵循标准的生命周期：
1. `initialize()` - 初始化插件
2. `start()` - 启动插件（无参数）
3. `start(Map<String, Object>)` - 启动插件（带参数）
4. `stop()` - 停止插件
5. `updateConfig()` - 更新插件配置

## 插件开发指南

### 创建新内置辅助插件

1. 继承`BaseCheatPlugin`内置辅助基类
2. 实现`getName()`和`getDescription()`方法
3. 重写`onStart()`和`onStop()`方法来实现插件特定的启动和停止逻辑
4. 在`CheatPluginFactory`中注册插件

### 示例内置辅助插件

``java
public class ExampleCheatPlugin extends BaseCheatPlugin {
    @Override
    public String getName() {
        return "ExamplePlugin";
    }
    
    @Override
    public String getDescription() {
        return "示例内置辅助功能";
    }
    
    @Override
    protected void onStart() {
        super.onStart();
        // 插件启动逻辑
        Map<String, Object> params = getStartParameters();
        if (params != null) {
            // 处理启动参数
        }
    }
    
    @Override
    protected void onStop() {
        super.onStop();
        // 插件停止逻辑
    }
    
    @Override
    public void updateConfig() {
        // 配置更新逻辑
    }
}
```

### 生命周期方法

- `start()` - 公共方法，用于启动插件（无参数），会自动调用`onStart()`
- `start(Map<String, Object>)` - 公共方法，用于启动插件（带参数），会自动调用`onStart()`
- `stop()` - 公共方法，用于停止插件，会自动调用`onStop()`
- `onStart()` - 受保护方法，插件特定的启动逻辑
- `onStop()` - 受保护方法，插件特定的停止逻辑

### 内置辅助启动参数支持

插件系统支持在启动时传递一次性参数：

``java
// 创建参数映射
Map<String, Object> params = new HashMap<>();
params.put("duration", 60);  // 设置持续时间
params.put("enable", true);  // 设置启用状态

// 启动插件并传递参数
plugin.start(params);
```

插件可以通过以下方法获取参数：
- `getStartParameters()` - 获取所有启动参数
- `getStartParameter(key, defaultValue)` - 获取指定参数
- `getStartParameterAsString(key, defaultValue)` - 获取字符串类型参数
- `getStartParameterAsInt(key, defaultValue)` - 获取整数类型参数
- `getStartParameterAsBoolean(key, defaultValue)` - 获取布尔类型参数

### 内置辅助日志记录

基类提供了以下日志记录方法：
- `logPluginActivation()` - 记录插件激活
- `logPluginDeactivation()` - 记录插件停用
- `logPluginUsage()` - 记录插件使用
- `logCheatSystem()` - 记录通用系统日志

## 现有内置辅助插件

### ItemVacPlugin (物品自动拾取内置辅助插件)

功能：自动拾取范围内的物品
配置参数：
- `cheat_pet_itemvac_switch` - 总开关
- `cheat_pet_itemvac_allow_in_event` - 是否允许在事件地图中使用
- `cheat_pet_itemvac_show_params` - 是否在界面上展示参数提示信息
- `cheat_pet_itemvac_max_level` - 宠吸功能支持的最高宠物等级
- `cheat_pet_itemvac_radius_max` - 最大拾取半径限制
- `cheat_pet_itemvac_sleep_min` - 最小拾取间隔时间（毫秒）
- `cheat_pet_itemvac_sleep_max` - 最大拾取间隔时间（毫秒）
- `cheat_pet_itemvac_radius_auto` - 是否自动计算拾取范围和间隔

### MobVacPlugin (怪物吸怪内置辅助插件)

功能：将范围内的怪物吸到玩家身边
配置参数：
- `cheat_mob_vac_switch` - 总开关
- `cheat_mob_vac_daily_limit` - 每天可用次数
- `cheat_mob_vac_duration` - 每次使用时长（分钟）
- `cheat_mob_vac_radius` - 吸怪范围半径

支持启动参数：
- `enable` - 布尔值，覆盖总开关设置
- `dailyLimit` - 整数值，覆盖每日限制设置
- `duration` - 整数值，覆盖持续时间设置
- `radius` - 双精度浮点数，覆盖吸怪范围设置
- `ignoreEnableCheck` - 布尔值，是否忽略启用检查

## 内置辅助使用方法

### 启动/停止内置辅助插件

``java
// 获取内置辅助插件管理器
CheatManager cheatManager = player.getCheatManager();

// 获取特定插件
ItemVacPlugin itemVacPlugin = cheatManager.getPlugin("ItemVac");

// 启动插件（无参数）
itemVacPlugin.start();

// 启动插件（带参数）
Map<String, Object> params = new HashMap<>();
params.put("enable", true);
params.put("duration", 60);
params.put("ignoreEnableCheck", true);  // 忽略启用检查
itemVacPlugin.start(params);

// 停止插件
itemVacPlugin.stop();
```

### 更新内置辅助插件配置

``java
// 更新所有插件配置
cheatManager.updateAllConfig();

// 更新特定插件配置
itemVacPlugin.updateConfig();
```

## 内置辅助最佳实践

1. **统一接口使用**：始终使用`start()`和`stop()`方法来控制内置辅助插件状态，而不是直接调用内部方法
2. **生命周期管理**：在`onStart()`和`onStop()`中实现内置辅助插件特定的逻辑
3. **日志记录**：使用基类提供的日志方法记录内置辅助插件活动
4. **配置管理**：使用`updateConfig()`方法统一管理内置辅助插件配置
5. **错误处理**：在内置辅助插件方法中适当处理异常，避免影响游戏主线程
6. **参数处理**：使用基类提供的参数获取方法，确保内置辅助类型安全和默认值处理