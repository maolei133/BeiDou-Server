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
import org.gms.provider.wz.DataType;

import java.awt.*;

@Slf4j
public class DataTool {

    /**
     * 私有辅助方法，用于获取子节点并进行空值检查。
     * 如果找不到子节点，则抛出带有详细路径信息的 NullPointerException。
     *
     * @param path 子节点路径
     * @param data 父数据节点
     * @return 如果找到，则返回子数据节点
     * @throws NullPointerException 如果找不到子节点
     */
    private static Data getAndCheckChildByPath(String path, Data data) {
        final Data d = data.getChildByPath(path);
        if (d == null) {
            log.error("在 {} 中找不到子路径 {}", getFullDataPath(data), path);
            // 抛出异常，指明在哪个父路径下找不到哪个子路径
//            throw new NullPointerException("在路径 " + getFullDataPath(data) + " 中找不到子路径 " + path);
        }
        return d;
    }

    public static String getString(Data data) {
        return ((String) data.getData());
    }

    public static String getString(Data data, String def) {
        if (data == null || data.getData() == null) {
            return def;
        } else {
            return ((String) data.getData());
        }
    }

    public static String getString(String path, Data data) {
        // 使用辅助方法获取子节点
        return getString(getAndCheckChildByPath(path, data));
    }

    public static String getString(String path, Data data, String def) {
        // 带默认值的方法保持原样，因为它们需要处理 null 情况
        return getString(data.getChildByPath(path), def);
    }

    public static double getDouble(Data data) {
        return (Double) data.getData();
    }

    public static float getFloat(Data data) {
        return (Float) data.getData();
    }

    public static int getInt(Data data) {
        if (data == null || data.getData() == null) {
            return 0; // 默认返回 0
        }
        return (Integer) data.getData();
    }

    public static int getInt(String path, Data data) {
        // 使用辅助方法获取子节点
        return getInt(getAndCheckChildByPath(path, data));
    }

    public static int getIntConvert(Data data) {
        if (data.getType() == DataType.STRING) {
            return Integer.parseInt(getString(data));
        } else {
            return getInt(data);
        }
    }

    public static int getIntConvert(Data data, int def) {
        if (data == null) {
            return def;
        }
        if (data.getType() == DataType.STRING) {
            String dd = getString(data);
            if (dd.endsWith("%")) {
                dd = dd.substring(0, dd.length() - 1);
            }
            try {
                return Integer.parseInt(dd);
            } catch (NumberFormatException nfe) {
                return def;
            }
        } else {
            return getInt(data, def);
        }
    }

    public static int getIntConvert(String path, Data data) {
        // 使用辅助方法获取子节点
        Data d = getAndCheckChildByPath(path, data);
        if (d.getType() == DataType.STRING) {
            return Integer.parseInt(getString(d));
        } else {
            return getInt(d);
        }
    }

    public static int getInt(Data data, int def) {
        if (data == null || data.getData() == null) {
            return def;
        } else if (data.getType() == DataType.STRING) {
            return Integer.parseInt(getString(data));
        } else {
            Object numData = data.getData();
            if (numData instanceof Integer) {
                return (Integer) numData;
            } else {
                return (Short) numData;
            }
        }
    }

    public static int getInt(String path, Data data, int def) {
        // 带默认值的方法保持原样
        return getInt(data.getChildByPath(path), def);
    }

    public static int getIntConvert(String path, Data data, int def) {
        Data d = data.getChildByPath(path);
        if (d == null) {
            return def;
        }
        if (d.getType() == DataType.STRING) {
            try {
                return Integer.parseInt(getString(d));
            } catch (NumberFormatException nfe) {
                nfe.printStackTrace();
                return def;
            }
        } else {
            return getInt(d, def);
        }
    }

    public static Integer getInteger(String path, Data data) {
        Data child = data.getChildByPath(path);
        if (child == null || child.getData() == null) {
            return null;
        } else if (child.getType() == DataType.STRING) {
            return Integer.parseInt(getString(child));
        } else {
            Object numData = child.getData();
            return ((Number) numData).intValue();
        }
    }

    public static int getInteger(String path, Data data, int def) {
        Integer val = getInteger(path, data);
        return val == null ? def : val;
    }

    public static Short getShort(String path, Data data) {
        Data child = data.getChildByPath(path);
        if (child == null || child.getData() == null) {
            return null;
        } else if (child.getType() == DataType.STRING) {
            return Short.parseShort(getString(child));
        } else {
            Object numData = child.getData();
            return ((Number) numData).shortValue();
        }
    }

    public static short getShort(String path, Data data, short def) {
        Short val = getShort(path, data);
        return val == null ? def : val;
    }

    public static Long getLong(String path, Data data) {
        Data child = data.getChildByPath(path);
        if (child == null || child.getData() == null) {
            return null;
        } else if (child.getType() == DataType.STRING) {
            return Long.parseLong(getString(child));
        } else {
            Object numData = child.getData();
            return ((Number) numData).longValue();
        }
    }

    public static long getLong(String path, Data data, long def) {
        Long val = getLong(path, data);
        return val == null ? def : val;
    }

    public static Point getPoint(Data data) {
        return ((Point) data.getData());
    }

    public static Point getPoint(String path, Data data) {
        // 使用辅助方法获取子节点
        return getPoint(getAndCheckChildByPath(path, data));
    }

    public static Point getPoint(String path, Data data, Point def) {
        final Data pointData = data.getChildByPath(path);
        if (pointData == null) {
            return def;
        }
        return getPoint(pointData);
    }

    public static String getFullDataPath(Data data) {
        if (data == null) {
            return "null";
        }
        String path = "";
        DataEntity myData = (DataEntity) data;
        while (myData != null) {
            path = myData.getName() + "/" + path;
            myData = myData.getParent();
        }
        // 移除末尾的 "/"
        if (path.length() > 0) {
            return path.substring(0, path.length() - 1);
        }
        return "";
    }

    public static String getAttributeValue(Data data, String name) {
        return data.getAttributeValue(name);
    }

    public static String getAttributeValue(Data data, String name, String def) {
        String val = getAttributeValue(data, name);
        return val == null ? def : val;
    }

    public static int getAttributeValueInt(Data data, String name, int def) {
        String val = getAttributeValue(data, name);
        return val == null ? def : Integer.parseInt(val);
    }
}
