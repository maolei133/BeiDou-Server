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
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 分类注册器 - 管理所有日志分类的注册和查询
 * 线程安全的分类存储和查询机制
 *
 * @author logs-system
 */
@Slf4j
public class CategoryRegistry {
    /**
     * 分类存储：key=categoryId, value=CategoryInfo
     */
    private final Map<String, CategoryInfo> categoryMap = new ConcurrentHashMap<>();

    /**
     * 按大类索引：key=majorCategory, value=小类集合
     */
    private final Map<String, Set<String>> majorCategoryIndex = new ConcurrentHashMap<>();

    /**
     * 按性能等级索引：key=level, value=分类ID集合
     */
    private final Map<String, Set<String>> levelIndex = new ConcurrentHashMap<>();

    /**
     * 注册一个日志分类
     *
     * @param categoryInfo 分类信息
     * @return 是否注册成功
     */
    public synchronized boolean register(CategoryInfo categoryInfo) {
        if (categoryInfo == null || categoryInfo.getMajorCategory() == null || categoryInfo.getMinorCategory() == null) {
            log.warn("无效的分类信息: {}", categoryInfo);
            return false;
        }

        String categoryId = buildCategoryId(categoryInfo.getMajorCategory(), categoryInfo.getMinorCategory());
        categoryInfo.setCategoryId(categoryId);
        categoryInfo.setCreatedTime(System.currentTimeMillis());
        categoryInfo.setModifiedTime(System.currentTimeMillis());

        categoryMap.put(categoryId, categoryInfo);

        // 更新大类索引
        majorCategoryIndex.computeIfAbsent(categoryInfo.getMajorCategory(), k -> ConcurrentHashMap.newKeySet())
                .add(categoryId);

        // 更新性能等级索引
        levelIndex.computeIfAbsent(categoryInfo.getLevel(), k -> ConcurrentHashMap.newKeySet())
                .add(categoryId);

        log.info("分类已注册: {} -> {}", categoryId, categoryInfo);
        return true;
    }

    /**
     * 注销一个日志分类
     *
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return 是否注销成功
     */
    public synchronized boolean unregister(String majorCategory, String minorCategory) {
        String categoryId = buildCategoryId(majorCategory, minorCategory);
        CategoryInfo removed = categoryMap.remove(categoryId);

        if (removed != null) {
            majorCategoryIndex.get(majorCategory).remove(categoryId);
            levelIndex.get(removed.getLevel()).remove(categoryId);
            log.info("分类已注销: {}", categoryId);
            return true;
        }
        return false;
    }

    /**
     * 获取指定的分类信息
     *
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return 分类信息，如果不存在返回null
     */
    public CategoryInfo getCategory(String majorCategory, String minorCategory) {
        String categoryId = buildCategoryId(majorCategory, minorCategory);
        return categoryMap.get(categoryId);
    }

    /**
     * 获取所有分类
     *
     * @return 所有分类信息的集合
     */
    public Collection<CategoryInfo> getAllCategories() {
        return new ArrayList<>(categoryMap.values());
    }

    /**
     * 按大类获取分类
     *
     * @param majorCategory 大类名称
     * @return 属于该大类的所有分类信息
     */
    public Collection<CategoryInfo> getCategoriesByMajor(String majorCategory) {
        Set<String> categoryIds = majorCategoryIndex.get(majorCategory);
        if (categoryIds == null) {
            return Collections.emptyList();
        }
        List<CategoryInfo> result = new ArrayList<>();
        for (String categoryId : categoryIds) {
            CategoryInfo info = categoryMap.get(categoryId);
            if (info != null) {
                result.add(info);
            }
        }
        return result;
    }

    /**
     * 按性能等级获取分类
     *
     * @param level 性能等级
     * @return 属于该等级的所有分类信息
     */
    public Collection<CategoryInfo> getCategoriesByLevel(String level) {
        Set<String> categoryIds = levelIndex.get(level);
        if (categoryIds == null) {
            return Collections.emptyList();
        }
        List<CategoryInfo> result = new ArrayList<>();
        for (String categoryId : categoryIds) {
            CategoryInfo info = categoryMap.get(categoryId);
            if (info != null) {
                result.add(info);
            }
        }
        return result;
    }

    /**
     * 获取所有大类
     *
     * @return 大类名称集合
     */
    public Set<String> getAllMajorCategories() {
        return new HashSet<>(majorCategoryIndex.keySet());
    }

    /**
     * 获取所有性能等级
     *
     * @return 性能等级集合
     */
    public Set<String> getAllLevels() {
        return new HashSet<>(levelIndex.keySet());
    }

    /**
     * 更新分类信息
     *
     * @param categoryInfo 更新的分类信息
     * @return 是否更新成功
     */
    public synchronized boolean update(CategoryInfo categoryInfo) {
        String categoryId = buildCategoryId(categoryInfo.getMajorCategory(), categoryInfo.getMinorCategory());
        if (!categoryMap.containsKey(categoryId)) {
            log.warn("未找到分类: {}", categoryId);
            return false;
        }

        categoryInfo.setCategoryId(categoryId);
        categoryInfo.setModifiedTime(System.currentTimeMillis());
        categoryMap.put(categoryId, categoryInfo);
        log.info("分类已更新: {}", categoryId);
        return true;
    }

    /**
     * 清空所有分类
     */
    public synchronized void clear() {
        categoryMap.clear();
        majorCategoryIndex.clear();
        levelIndex.clear();
        log.info("所有分类已清空");
    }

    /**
     * 构建分类ID
     *
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return 分类ID (格式: majorCategory.minorCategory)
     */
    private String buildCategoryId(String majorCategory, String minorCategory) {
        return majorCategory + "." + minorCategory;
    }

    /**
     * 获取分类总数
     *
     * @return 分类数量
     */
    public int size() {
        return categoryMap.size();
    }

    /**
     * 检查分类是否存在
     *
     * @param majorCategory 大类
     * @param minorCategory 小类
     * @return 是否存在
     */
    public boolean exists(String majorCategory, String minorCategory) {
        String categoryId = buildCategoryId(majorCategory, minorCategory);
        return categoryMap.containsKey(categoryId);
    }
}
