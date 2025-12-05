/* This file is part of the BeiDou Maple Story Server
Copyright (C) 2025 BeiDou Server https://github.com/BeiDouMS/BeiDou-Server
Magical-H https://github.com/Magical-H

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation version 3 as published by
the Free Software Foundation. You may not use, modify or distribute
this program under any otheer version of the GNU Affero General Public
License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; witout even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.


You should have received a copy of the GNU Affero General Public License
along with this program. If not, see http://www.gnu.org/licenses/.
*/

package org.gms.logsystem.category;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.annotation.LogCategory;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * 动态分类管理器 - 负责日志分类的创建、更新、删除和查询
 * 支持注解驱动、配置文件驱动和动态API驱动三种方式的分类管理
 *
 * @author logs-system
 */
@Slf4j
@Component
public class DynamicCategoryManager {
    /**
     * 日志分类常量 - 统一定义和管理所有日志分类
     * 在DynamicCategoryManager初始化时自动注册，其他类直接引用这些常量
     */
    public static class Category {
        // 大类常量
        /** 内置辅助系统 */
        public static final String MAJOR_CHEATSYSTEM = "cheatsystem";
        /** 安全相关 */
        public static final String MAJOR_SECURITY = "security";
        
        // 小类常量 - CheatSystem
        /** 插件激活 */
        public static final String MINOR_PLUGIN_ACTIVATION = "plugin_activation";
        /** 插件操作 */
        public static final String MINOR_PLUGIN_OPERATION = "plugin_operation";
        /** 插件系统 */
        public static final String MINOR_PLUGIN_SYSTEM = "plugin_system";
        
        // 小类常量 - Security
        /** 外挂检测 */
        public static final String MINOR_HACK_DETECTION = "hack_detection";
        /** 账号安全 */
        public static final String MINOR_ACCOUNT_SECURITY = "account_security";
    }
    
    /**
     * 分类注册器
     */
    private final CategoryRegistry categoryRegistry;

    public DynamicCategoryManager() {
        this.categoryRegistry = new CategoryRegistry();
        initializeDefaultCategories();
    }

    /**
     * 初始化默认分类
     * 包含系统预定义的分类及其子类
     */
    private void initializeDefaultCategories() {
        // CheatSystem相关日志
        registerCategory(Category.MAJOR_CHEATSYSTEM, Category.MINOR_PLUGIN_ACTIVATION, "插件激活", "HIGH");
        registerCategory(Category.MAJOR_CHEATSYSTEM, Category.MINOR_PLUGIN_OPERATION, "插件操作", "HIGH");
        registerCategory(Category.MAJOR_CHEATSYSTEM, Category.MINOR_PLUGIN_SYSTEM, "插件系统", "HIGH");
        
        // Security相关日志
        registerCategory(Category.MAJOR_SECURITY, Category.MINOR_HACK_DETECTION, "外挂检测", "HIGH");
        registerCategory(Category.MAJOR_SECURITY, Category.MINOR_ACCOUNT_SECURITY, "账号安全", "HIGH");
        
        // Player相关日志
        registerCategory("player", "login", "玩家登录日志", "HIGH");
        registerCategory("player", "logout", "玩家登出日志", "HIGH");
        registerCategory("player", "movement", "玩家移动日志", "HIGH");
        registerCategory("player", "combat", "玩家战斗日志", "MEDIUM");

        // Item相关日志
        registerCategory("item", "acquire", "物品获取日志", "MEDIUM");
        registerCategory("item", "use", "物品使用日志", "MEDIUM");
        registerCategory("item", "drop", "物品丢弃日志", "MEDIUM");
        registerCategory("item", "trade", "物品交易日志", "MEDIUM");

        // Economy相关日志
        registerCategory("economy", "trade", "经济交易日志", "MEDIUM");
        registerCategory("economy", "npc_shop", "NPC商店日志", "LOW");
        registerCategory("economy", "currency", "货币流动日志", "MEDIUM");

        // Quest相关日志
        registerCategory("quest", "accept", "任务接取日志", "LOW");
        registerCategory("quest", "complete", "任务完成日志", "LOW");
        registerCategory("quest", "progress", "任务进度日志", "LOW");

        // Dungeon相关日志
        registerCategory("dungeon", "enter", "副本进入日志", "MEDIUM");
        registerCategory("dungeon", "clear", "副本清除日志", "MEDIUM");
        registerCategory("dungeon", "fail", "副本失败日志", "LOW");

        // Equipment相关日志
        registerCategory("equipment", "equip", "装备穿戴日志", "MEDIUM");
        registerCategory("equipment", "unequip", "装备卸下日志", "MEDIUM");
        registerCategory("equipment", "upgrade", "装备升级日志", "MEDIUM");

        // Skill相关日志
        registerCategory("skill", "learn", "技能学习日志", "LOW");
        registerCategory("skill", "use", "技能使用日志", "HIGH");
        registerCategory("skill", "cooldown", "技能冷却日志", "MEDIUM");

        // Pet相关日志
        registerCategory("pet", "capture", "宠物捕获日志", "LOW");
        registerCategory("pet", "evolve", "宠物进化日志", "LOW");
        registerCategory("pet", "battle", "宠物战斗日志", "MEDIUM");

        // Guild相关日志
        registerCategory("guild", "create", "公会创建日志", "LOW");
        registerCategory("guild", "join", "公会加入日志", "LOW");
        registerCategory("guild", "leave", "公会离开日志", "LOW");

        // Social相关日志
        registerCategory("social", "friend_add", "好友添加日志", "LOW");
        registerCategory("social", "friend_remove", "好友移除日志", "LOW");
        registerCategory("social", "chat", "聊天日志", "HIGH");

        // System相关日志
        registerCategory("system", "server_event", "服务器事件日志", "MEDIUM");
        registerCategory("system", "error", "系统错误日志", "HIGH");
        registerCategory("system", "performance", "性能监控日志", "MEDIUM");

        // Packet相关日志
        registerCategory("packet", "inbound", "入站网络包日志", "HIGH");
        registerCategory("packet", "outbound", "出站网络包日志", "HIGH");
        registerCategory("packet", "monitor", "监控角色网络包日志", "MEDIUM");

        log.info("默认分类已初始化");
    }

    /**
     * 注册一个新的日志分类
     *
     * @param majorCategory 大类名称
     * @param minorCategory 小类名称
     * @param description   描述
     * @param level         性能等级
     * @return 是否注册成功
     */
    public boolean registerCategory(String majorCategory, String minorCategory, String description, String level) {
        CategoryInfo categoryInfo = CategoryInfo.builder()
                .majorCategory(majorCategory)
                .minorCategory(minorCategory)
                .description(description)
                .level(level)
                .enabled(true)
                .consoleOutput(false)
                .fileOutput(true)
                .build();
        return categoryRegistry.register(categoryInfo);
    }

    /**
     * 从注解注册分类
     *
     * @param logCategory 分类注解
     * @return 是否注册成功
     */
    public boolean registerFromAnnotation(LogCategory logCategory) {
        return registerCategory(logCategory.majorCategory(), logCategory.minorCategory(),
                logCategory.description(), logCategory.level());
    }

    /**
     * 注销分类
     *
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return 是否注销成功
     */
    public boolean unregisterCategory(String majorCategory, String minorCategory) {
        return categoryRegistry.unregister(majorCategory, minorCategory);
    }

    /**
     * 获取分类信息
     *
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return 分类信息
     */
    public CategoryInfo getCategory(String majorCategory, String minorCategory) {
        return categoryRegistry.getCategory(majorCategory, minorCategory);
    }

    /**
     * 获取所有分类
     *
     * @return 所有分类列表
     */
    public Collection<CategoryInfo> getAllCategories() {
        return categoryRegistry.getAllCategories();
    }

    /**
     * 按大类获取分类
     *
     * @param majorCategory 大类名称
     * @return 分类列表
     */
    public Collection<CategoryInfo> getCategoriesByMajor(String majorCategory) {
        return categoryRegistry.getCategoriesByMajor(majorCategory);
    }

    /**
     * 获取所有大类
     *
     * @return 大类名称集合
     */
    public Set<String> getAllMajorCategories() {
        return categoryRegistry.getAllMajorCategories();
    }

    /**
     * 更新分类信息
     *
     * @param categoryInfo 新的分类信息
     * @return 是否更新成功
     */
    public boolean updateCategory(CategoryInfo categoryInfo) {
        return categoryRegistry.update(categoryInfo);
    }

    /**
     * 启用/禁用分类
     *
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @param enabled       是否启用
     * @return 是否操作成功
     */
    public boolean setEnabled(String majorCategory, String minorCategory, boolean enabled) {
        CategoryInfo categoryInfo = getCategory(majorCategory, minorCategory);
        if (categoryInfo != null) {
            categoryInfo.setEnabled(enabled);
            return updateCategory(categoryInfo);
        }
        return false;
    }

    /**
     * 设置分类输出选项
     *
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @param consoleOutput 是否输出到控制台
     * @param fileOutput    是否输出到文件
     * @return 是否操作成功
     */
    public boolean setOutputOptions(String majorCategory, String minorCategory, boolean consoleOutput, boolean fileOutput) {
        CategoryInfo categoryInfo = getCategory(majorCategory, minorCategory);
        if (categoryInfo != null) {
            categoryInfo.setConsoleOutput(consoleOutput);
            categoryInfo.setFileOutput(fileOutput);
            return updateCategory(categoryInfo);
        }
        return false;
    }
}
