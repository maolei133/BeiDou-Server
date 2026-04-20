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
package org.gms.provider.wz;

import lombok.extern.slf4j.Slf4j;
import org.gms.provider.Data;
import org.gms.provider.DataDirectoryEntry;
import org.gms.provider.DataProvider;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;

@Slf4j
public class XMLWZFile implements DataProvider {
	private final Path root;
    private final WZDirectoryEntry rootForNavigation;

    public XMLWZFile(Path fileIn) {
        root = fileIn;
        rootForNavigation = new WZDirectoryEntry(fileIn.getFileName().toString(), 0, 0, null);
        fillMapleDataEntitys(root, rootForNavigation);
    }

    private void fillMapleDataEntitys(Path lroot, WZDirectoryEntry wzdir) {

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(lroot)) {
            for (Path path : stream) {
                String fileName = path.getFileName().toString();
                if (Files.isDirectory(path) && !fileName.endsWith(".img")) {
                    WZDirectoryEntry newDir = new WZDirectoryEntry(fileName, 0, 0, wzdir);
                    wzdir.addDirectory(newDir);
                    fillMapleDataEntitys(path, newDir);
                } else if (fileName.endsWith(".xml")) {
                    wzdir.addFile(new WZFileEntry(fileName.substring(0, fileName.length() - 4), 0, 0, wzdir));
                }
            }
        } catch (IOException e) {
            log.warn("无法打开文件/目录，路径: {}", lroot.toAbsolutePath());
        }
    }

    @Override
    public synchronized Data getData(String path) {
        Path dataFile = root.resolve(path + ".xml");
        
        // 在尝试加载前，先检查文件是否存在
        if (!Files.exists(dataFile)) {
            // 如果文件不存在，记录错误日志并返回null
            log.error("数据文件不存在，路径: {}", dataFile.toAbsolutePath());
            return null;
        }

        Path imageDataDir = root.resolve(path);
        final XMLDomMapleData domMapleData;
        try (FileInputStream fis = new FileInputStream(dataFile.toFile())) {
            domMapleData = new XMLDomMapleData(fis, imageDataDir.getParent());
        } catch (FileNotFoundException e) {
            // 这个异常理论上不应该再触发，因为我们已经提前检查了文件存在性
            log.error("严重错误：文件在检查后消失了。路径: {}", dataFile.toAbsolutePath(), e);
            return null;
        } catch (IOException e) {
            log.error("读取或解析XML文件时发生IO异常，路径: {}", dataFile.toAbsolutePath(), e);
            throw new RuntimeException("读取或解析XML文件失败: " + dataFile.toAbsolutePath(), e);
        } catch (Exception e) {
            log.error("解析XML文件时发生未知异常，文件可能已损坏。路径: {}", dataFile.toAbsolutePath(), e);
            throw new RuntimeException("解析XML文件失败: " + dataFile.toAbsolutePath(), e);
        }

        return domMapleData;
    }

	@Override
	public DataDirectoryEntry getRoot() {
		return rootForNavigation;
	}
}
