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

import org.gms.constants.game.GameConstants;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import org.gms.provider.Data;
import org.gms.provider.DataEntity;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.awt.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class XMLDomMapleData implements Data {
    private final Node node;
    private Path imageDataDir;
    // 注解：引入一个共享的锁对象。这是实现线程安全的关键。
    private final Object treeLock;

    public XMLDomMapleData(FileInputStream fis, Path imageDataDir) {
        try {
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
            Document document = documentBuilder.parse(fis);
            this.node = document.getFirstChild();
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new RuntimeException(e);
        }
        this.imageDataDir = imageDataDir;
        // 注解：对于从文件创建的根节点，创建一个新的锁实例。
        this.treeLock = new Object();
    }

    /**
     * 注解：内部构造函数，用于创建子节点。
     * @param node 底层DOM节点
     * @param treeLock 共享的锁对象，从父节点传递而来。
     */
    private XMLDomMapleData(Node node, Object treeLock) {
        this.node = node;
        this.treeLock = treeLock;
    }

    @Override
    public Data getChildByPath(String path) {
        // 注解：将 'synchronized' 关键字替换为对共享锁的同步块。
        synchronized (treeLock) {
            String[] segments = path.split("/");
            if (segments[0].equals("..")) {
                return ((Data) getParent()).getChildByPath(path.substring(path.indexOf("/") + 1));
            }

            Node myNode = node;
            for (String s : segments) {
                NodeList childNodes = myNode.getChildNodes();
                boolean foundChild = false;
                for (int i = 0; i < childNodes.getLength(); i++) {
                    Node childNode = childNodes.item(i);
                    if (childNode != null && childNode.getNodeType() == Node.ELEMENT_NODE
                            && childNode.getAttributes().getNamedItem("name").getNodeValue().equals(s)) {
                        myNode = childNode;
                        foundChild = true;
                        break;
                    }
                }
                if (!foundChild) {
                    return null;
                }
            }

            // 注解：创建子节点时，将共享锁传递下去。
            XMLDomMapleData ret = new XMLDomMapleData(myNode, treeLock);
            ret.imageDataDir = imageDataDir.resolve(getName().trim()).resolve(path).getParent();
            return ret;
        }
    }

    @Override
    public List<Data> getChildren() {
        synchronized (treeLock) {
            List<Data> ret = new ArrayList<>();
            NodeList childNodes = node.getChildNodes();
            for (int i = 0; i < childNodes.getLength(); i++) {
                Node childNode = childNodes.item(i);
                if (childNode != null && childNode.getNodeType() == Node.ELEMENT_NODE) {
                    // 注解：创建子节点时，将共享锁传递下去。
                    XMLDomMapleData child = new XMLDomMapleData(childNode, treeLock);
                    child.imageDataDir = imageDataDir.resolve(getName().trim());
                    ret.add(child);
                }
            }
            return ret;
        }
    }

    @Override
    public Object getData() {
        synchronized (treeLock) {
            NamedNodeMap attributes = node.getAttributes();
            DataType type = getType();
            if (type == null) return null;
            switch (type) {
                case DOUBLE: case FLOAT: case INT: case SHORT: {
                    String value = attributes.getNamedItem("value").getNodeValue();
                    Number nval = GameConstants.parseNumber(value);
                    switch (type) {
                        case DOUBLE: return nval.doubleValue();
                        case FLOAT: return nval.floatValue();
                        case INT: return nval.intValue();
                        case SHORT: return nval.shortValue();
                        default: return null;
                    }
                }
                case STRING: case UOL: {
                    return attributes.getNamedItem("value").getNodeValue();
                }
                case VECTOR: {
                    String x = attributes.getNamedItem("x").getNodeValue();
                    String y = attributes.getNamedItem("y").getNodeValue();
                    return new Point(Integer.parseInt(x), Integer.parseInt(y));
                }
                case CANVAS: {
                    String width = attributes.getNamedItem("width").getNodeValue();
                    String height = attributes.getNamedItem("height").getNodeValue();
                    return new Point(Integer.parseInt(width), Integer.parseInt(height));
                }
                default:
                    return null;
            }
        }
    }

    @Override
    public DataType getType() {
        synchronized (treeLock) {
            String nodeName = node.getNodeName();
            return switch (nodeName) {
                case "imgdir" -> DataType.PROPERTY;
                case "canvas" -> DataType.CANVAS;
                case "convex" -> DataType.CONVEX;
                case "sound" -> DataType.SOUND;
                case "uol" -> DataType.UOL;
                case "double" -> DataType.DOUBLE;
                case "float" -> DataType.FLOAT;
                case "int" -> DataType.INT;
                case "short" -> DataType.SHORT;
                case "string" -> DataType.STRING;
                case "vector" -> DataType.VECTOR;
                case "null" -> DataType.IMG_0x00;
                default -> null;
            };
        }
    }

    @Override
    public DataEntity getParent() {
        synchronized (treeLock) {
            Node parentNode = node.getParentNode();
            if (parentNode == null || parentNode.getNodeType() == Node.DOCUMENT_NODE) {
                return null;
            }
            // 注解：创建父节点时，将共享锁传递下去。
            XMLDomMapleData parentData = new XMLDomMapleData(parentNode, treeLock);
            parentData.imageDataDir = imageDataDir.getParent();
            return parentData;
        }
    }

    @Override
    public String getName() {
        synchronized (treeLock) {
            return node.getAttributes().getNamedItem("name").getNodeValue();
        }
    }

    @Override
    public Iterator<Data> iterator() {
        synchronized (treeLock) {
            return getChildren().iterator();
        }
    }

    public String getAttributeValue(String name) {
        synchronized (treeLock) {
            Node attr = node.getAttributes().getNamedItem(name);
            return attr == null ? null : attr.getNodeValue();
        }
    }
}
