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
package org.gms.server.maps;

import java.awt.*;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Matze
 */
public class FootholdTree {
    private FootholdTree nw = null;
    private FootholdTree ne = null;
    private FootholdTree sw = null;
    private FootholdTree se = null;
    private final List<Foothold> footholds = new LinkedList<>();
    private final Point p1;
    private final Point p2;
    private final Point center;
    private int depth = 0;
    private static final int maxDepth = 8;
    private int maxDropX;
    private int minDropX;

    public FootholdTree(Point p1, Point p2) {
        this.p1 = p1;
        this.p2 = p2;
        center = new Point((p2.x - p1.x) / 2, (p2.y - p1.y) / 2);
    }

    public FootholdTree(Point p1, Point p2, int depth) {
        this.p1 = p1;
        this.p2 = p2;
        this.depth = depth;
        center = new Point((p2.x - p1.x) / 2, (p2.y - p1.y) / 2);
    }

    public void insert(Foothold f) {
        if (depth == 0) {
            if (f.getX1() > maxDropX) {
                maxDropX = f.getX1();
            }
            if (f.getX1() < minDropX) {
                minDropX = f.getX1();
            }
            if (f.getX2() > maxDropX) {
                maxDropX = f.getX2();
            }
            if (f.getX2() < minDropX) {
                minDropX = f.getX2();
            }
        }
        if (depth == maxDepth ||
                (f.getX1() >= p1.x && f.getX2() <= p2.x &&
                        f.getY1() >= p1.y && f.getY2() <= p2.y)) {
            footholds.add(f);
        } else {
            if (nw == null) {
                nw = new FootholdTree(p1, center, depth + 1);
                ne = new FootholdTree(new Point(center.x, p1.y), new Point(p2.x, center.y), depth + 1);
                sw = new FootholdTree(new Point(p1.x, center.y), new Point(center.x, p2.y), depth + 1);
                se = new FootholdTree(center, p2, depth + 1);
            }
            if (f.getX2() <= center.x && f.getY2() <= center.y) {
                nw.insert(f);
            } else if (f.getX1() > center.x && f.getY2() <= center.y) {
                ne.insert(f);
            } else if (f.getX2() <= center.x && f.getY1() > center.y) {
                sw.insert(f);
            } else {
                se.insert(f);
            }
        }
    }

    private List<Foothold> getRelevants(Point p) {
        return getRelevants(p, new LinkedList<>());
    }

    private List<Foothold> getRelevants(Point p, List<Foothold> list) {
        list.addAll(footholds);
        if (nw != null) {
            if (p.x <= center.x && p.y <= center.y) {
                nw.getRelevants(p, list);
            } else if (p.x > center.x && p.y <= center.y) {
                ne.getRelevants(p, list);
            } else if (p.x <= center.x && p.y > center.y) {
                sw.getRelevants(p, list);
            } else {
                se.getRelevants(p, list);
            }
        }
        return list;
    }

    private Foothold findWallR(Point p1, Point p2) {
        Foothold ret;
        for (Foothold f : footholds) {
            if (f.isWall() && f.getX1() >= p1.x && f.getX1() <= p2.x &&
                    f.getY1() >= p1.y && f.getY2() <= p1.y) {
                return f;
            }
        }
        if (nw != null) {
            if (p1.x <= center.x && p1.y <= center.y) {
                ret = nw.findWallR(p1, p2);
                if (ret != null) {
                    return ret;
                }
            }
            if ((p1.x > center.x || p2.x > center.x) && p1.y <= center.y) {
                ret = ne.findWallR(p1, p2);
                if (ret != null) {
                    return ret;
                }
            }
            if (p1.x <= center.x && p1.y > center.y) {
                ret = sw.findWallR(p1, p2);
                if (ret != null) {
                    return ret;
                }
            }
            if ((p1.x > center.x || p2.x > center.x) && p1.y > center.y) {
                ret = se.findWallR(p1, p2);
                return ret;
            }
        }
        return null;
    }

    public Foothold findWall(Point p1, Point p2) {
        if (p1.y != p2.y) {
            throw new IllegalArgumentException();
        }
        return findWallR(p1, p2);
    }

    /**
     * 寻找位于点 p: x, y 下方的平台
     * @param p  点 p: x, y
     * @return 找到的 Foothold
     */
    public Foothold findBelow_old(Point p) {
        List<Foothold> relevants = getRelevants(p);
        List<Foothold> xMatches = new LinkedList<>();
        for (Foothold fh : relevants) {
            if (fh.getX1() <= p.x && fh.getX2() >= p.x) {
                xMatches.add(fh);
            }
        }
        Collections.sort(xMatches);
        for (Foothold fh : xMatches) {
            if (!fh.isWall()) {
                if (fh.getY1() != fh.getY2()) {
                    int calcY;
                    double s1 = Math.abs(fh.getY2() - fh.getY1());
                    double s2 = Math.abs(fh.getX2() - fh.getX1());
                    double s4 = Math.abs(p.x - fh.getX1());
                    double alpha = Math.atan(s2 / s1);
                    double beta = Math.atan(s1 / s2);
                    double s5 = Math.cos(alpha) * (s4 / Math.cos(beta));
                    if (fh.getY2() < fh.getY1()) {
                        calcY = fh.getY1() - (int) s5;
                    } else {
                        calcY = fh.getY1() + (int) s5;
                    }
                    if (calcY >= p.y) {
                        return fh;
                    }
                } else {
                    if (fh.getY1() >= p.y) {
                        return fh;
                    }
                }
            }
        }
        return null;
    }

    /**
     * 寻找位于点 p: x, y 下方的平台或者最近的上方平台
     * @param p  点 p: x, y
     * @return 找到的 Foothold
     */
    public Foothold findBelow(Point p) {
//        System.out.println("======== 正在寻找位于点 p: " + p.x + ", " + p.y + " 下方的平台 ========");
        List<Foothold> relevants = getRelevants(p);

        Foothold bestBelow = null;
        double minBelowDistSq = Double.MAX_VALUE;
        Foothold bestAbove = null;
        double minAboveDistSq = Double.MAX_VALUE;

        for (Foothold fh : relevants) {
            if (fh.isWall()) {
                continue;
            }

            // 计算点p到线段fh的最近点(closestX, closestY)
            int x1 = fh.getX1();
            int y1 = fh.getY1();
            int x2 = fh.getX2();
            int y2 = fh.getY2();

            double dx = x2 - x1;
            double dy = y2 - y1;
            double closestX, closestY;

            if (dx == 0 && dy == 0) { // fh是一个点
                closestX = x1;
                closestY = y1;
            } else {
                double t = ((p.x - x1) * dx + (p.y - y1) * dy) / (dx * dx + dy * dy);
                if (t < 0) {
                    closestX = x1;
                    closestY = y1;
                } else if (t > 1) {
                    closestX = x2;
                    closestY = y2;
                } else {
                    closestX = x1 + t * dx;
                    closestY = y1 + t * dy;
                }
            }

            double distSq = (p.x - closestX) * (p.x - closestX) + (p.y - closestY) * (p.y - closestY);

            // 根据平台在上方还是下方，分组处理
            if (closestY >= p.y) { // 平台在下方或同一高度
//                System.out.println("[下方候选] p.x: " + p.x + ", p.y: " + p.y + ", fh.x1: " + x1 + ", fh.x2: " + x2 + ", fh.y1: " + y1 + ", fh.y2: " + y2 + ", 距离平方: " + distSq);
                if (distSq < minBelowDistSq) {
                    minBelowDistSq = distSq;
                    bestBelow = fh;
//                    System.out.println("  -> 更新下方最佳平台! ID: " + fh.getId() + ", 距离平方: " + minBelowDistSq);
                }
            } else { // 平台在上方
//                System.out.println("[上方候选] p.x: " + p.x + ", p.y: " + p.y + ", fh.x1: " + x1 + ", fh.x2: " + x2 + ", fh.y1: " + y1 + ", fh.y2: " + y2 + ", 距离平方: " + distSq);
                if (distSq < minAboveDistSq) {
                    minAboveDistSq = distSq;
                    bestAbove = fh;
//                    System.out.println("  -> 更新上方最佳平台! ID: " + fh.getId() + ", 距离平方: " + minAboveDistSq);
                }
            }
        }

        // 优先返回下方的最近平台
        if (bestBelow != null) {
//            System.out.println("======== 最终决策: 优先返回下方最近的平台 ID " + bestBelow.getId() + " [" + bestBelow.getX1() + "," + bestBelow.getY1() + "] to [" + bestBelow.getX2() + "," + bestBelow.getY2() + "] ========");
            return bestBelow;
        }

        // 如果没有下方的，再返回上方的最近平台作为备选
        if (bestAbove != null) {
//            System.out.println("======== 最终决策: 未找到下方平台, 返回上方最近的平台 ID " + bestAbove.getId() + " [" + bestAbove.getX1() + "," + bestAbove.getY1() + "] to [" + bestAbove.getX2() + "," + bestAbove.getY2() + "] ========");
            return bestAbove;
        }

//        System.out.println("======== 最终决策: 未找到任何合适的平台. ========");
        return null;
    }

    public int getX1() {
        return p1.x;
    }

    public int getX2() {
        return p2.x;
    }

    public int getY1() {
        return p1.y;
    }

    public int getY2() {
        return p2.y;
    }

    public int getMaxDropX() {
        return maxDropX;
    }

    public int getMinDropX() {
        return minDropX;
    }
}
