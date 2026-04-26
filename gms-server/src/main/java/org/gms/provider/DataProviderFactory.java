/*
	This file is part of the OdinMS Maple Story Server
    Copyright (C) 2008 Patrick Huy <patrick.huy@frz.cc>
		       Matthias Butz <matze@odinms.de>
		       Jan Christian Meyer <vimes@odinms.de>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation version 3 as published by
    the Free Software Foundation. You may not use, modify or distribute
    this program under any other version of the GNU Affero General Public
    License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package org.gms.provider;

import lombok.extern.slf4j.Slf4j;
import org.gms.provider.wz.WZFiles;
import org.gms.provider.wz.XMLWZFile;

import java.io.File;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class DataProviderFactory {
    private static final String WZ_DIR = "wz";
    // 注解：存储具体的 CachingDataProvider 实例，以便进行类型转换和方法调用
    private static final Map<String, CachingDataProvider> providers = new ConcurrentHashMap<>();

    private static CachingDataProvider getWZ(File fileIn) {
        String key = fileIn.getName().toLowerCase();
        return providers.computeIfAbsent(key, k -> {
            DataProvider rawProvider = new XMLWZFile(fileIn.toPath());
            return new CachingDataProvider(rawProvider);
        });
    }

    /**
     * 注解：返回具体的 CachingDataProvider 类型，以便上层代码能调用其特有方法。
     */
    public static CachingDataProvider getDataProvider(WZFiles in) {
        String wzName = in.name();
        File wzDir = new File(WZ_DIR);

        if (!wzDir.exists() || !wzDir.isDirectory()) {
            throw new IllegalStateException("WZ目录不存在或不是一个有效的目录，路径: " + wzDir.getAbsolutePath());
        }

        File finalDir = null;
        String targetNameWithExt = wzName + ".wz";
        String targetNameWithoutExt = wzName;

        File[] files = wzDir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    if (file.getName().equalsIgnoreCase(targetNameWithExt)) {
                        finalDir = file;
                        break;
                    }
                    if (file.getName().equalsIgnoreCase(targetNameWithoutExt)) {
                        finalDir = file;
                    }
                }
            }
        }

        if (finalDir == null) {
            throw new IllegalStateException(
                    "加载 " + wzName + " 失败：在 " + wzDir.getAbsolutePath() + " 目录下找不到对应的WZ目录。"
            );
        }

        return getWZ(finalDir);
    }

    /**
     * 获取所有缓存提供者的Map。
     */
    public static Map<String, CachingDataProvider> getProviders() {
        return providers;
    }
}
