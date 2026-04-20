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

@Slf4j
public class DataProviderFactory {
    private static final String WZ_DIR = "wz";

    private static DataProvider getWZ(Object in, boolean provideImages) {
        if (in instanceof File) {
            return new XMLWZFile(((File) in).toPath());
        }
        throw new IllegalArgumentException("getWZ 不支持内存中的 WZ 文件");
    }

    /**
     * 获取数据提供者实例，并在加载前检查WZ目录的有效性。
     * 此方法通过不区分大小写的方式查找目录，以兼容Windows和Linux系统。
     *
     * @param in WZ文件枚举
     * @return 数据提供者实例
     * @throws IllegalStateException 如果找不到对应的WZ目录
     */
    public static DataProvider getDataProvider(WZFiles in) {
        String wzName = in.name();
        File wzDir = new File(WZ_DIR);

        // 检查基础wz目录是否存在
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
                    // 优先匹配带 .wz 后缀的目录（不区分大小写）
                    if (file.getName().equalsIgnoreCase(targetNameWithExt)) {
                        finalDir = file;
                        break;
                    }
                    // 如果没有找到带后缀的，则匹配不带后缀的目录（不区分大小写）
                    if (file.getName().equalsIgnoreCase(targetNameWithoutExt)) {
                        finalDir = file;
                        // 继续循环，因为带.wz后缀的优先级更高
                    }
                }
            }
        }

        // 如果两种格式的目录都不存在，则抛出异常
        if (finalDir == null) {
            throw new IllegalStateException(
                    "加载 " + wzName + " 失败：在 " + wzDir.getAbsolutePath() + " 目录下找不到对应的WZ目录。" +
                            "请确认是否存在 '" + targetNameWithExt + "' 或 '" + targetNameWithoutExt + "' 文件夹（大小写不限）。"
            );
        }

        return getWZ(finalDir, false);
    }
}
