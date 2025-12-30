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
package org.gms.net.server.channel.handlers;

import com.mybatisflex.core.query.QueryWrapper;
import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.dao.entity.BbsRepliesDO;
import org.gms.dao.entity.BbsThreadsDO;
import org.gms.dao.mapper.BbsRepliesMapper;
import org.gms.dao.mapper.BbsThreadsMapper;
import org.gms.net.AbstractPacketHandler;
import org.gms.net.packet.InPacket;
import org.gms.net.server.guild.GuildPackets;
import org.gms.util.SpringContextUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.List;

public final class BBSOperationHandler extends AbstractPacketHandler {
    private static final Logger log = LoggerFactory.getLogger(BBSOperationHandler.class);

    private String correctLength(String in, int maxSize) {
        return in.length() > maxSize ? in.substring(0, maxSize) : in;
    }

    @Override
    public void handlePacket(InPacket p, Client c) {
        if (c.getPlayer().getGuildId() < 1) {
            return;
        }
        byte mode = p.readByte();
        int localthreadid = 0;
        switch (mode) {
            case 0: // 新增/编辑帖子
                boolean bEdit = p.readByte() == 1;
                if (bEdit) {
                    localthreadid = p.readInt();
                }
                boolean bNotice = p.readByte() == 1;
                String title = correctLength(p.readString(), 25);
                String text = correctLength(p.readString(), 600);
                int icon = p.readInt();
                if (icon >= 0x64 && icon <= 0x6a) {
                    if (!c.getPlayer().haveItemWithId(5290000 + icon - 0x64, false)) {
                        return;
                    }
                } else if (icon < 0 || icon > 3) {
                    return;
                }
                if (!bEdit) {
                    newBBSThread(c, title, text, icon, bNotice);
                } else {
                    editBBSThread(c, title, text, icon, localthreadid);
                }
                break;
            case 1: // 删除帖子
                localthreadid = p.readInt();
                deleteBBSThread(c, localthreadid);
                break;
            case 2: // 帖子列表
                int start = p.readInt();
                listBBSThreads(c, start * 10);
                break;
            case 3: // 查看帖子和回复
                localthreadid = p.readInt();
                displayThread(c, localthreadid);
                break;
            case 4: // 回复帖子
                localthreadid = p.readInt();
                text = correctLength(p.readString(), 25);
                newBBSReply(c, localthreadid, text);
                break;
            case 5: // 删除回复
                p.readInt(); // 未使用
                int replyid = p.readInt();
                deleteBBSReply(c, replyid);
                break;
            default:
                log.warn("未处理的BBS操作模式: {}", mode);
        }
    }

    private static void listBBSThreads(Client c, int start) {
        BbsThreadsMapper mapper = SpringContextUtil.getBean(BbsThreadsMapper.class);
        if (mapper != null) {
            List<BbsThreadsDO> threads = mapper.selectListByQuery(
                    new QueryWrapper()
                            .eq(BbsThreadsDO::getGuildid, c.getPlayer().getGuildId())
                            .orderBy(BbsThreadsDO::getLocalthreadid, false) // false for DESC
            );
            c.sendPacket(GuildPackets.BBSThreadList(threads, start));
        }
    }

    private static void newBBSReply(Client c, int localthreadid, String text) {
        if (c.getPlayer().getGuildId() <= 0) {
            return;
        }
        
        BbsThreadsMapper threadsMapper = SpringContextUtil.getBean(BbsThreadsMapper.class);
        BbsRepliesMapper repliesMapper = SpringContextUtil.getBean(BbsRepliesMapper.class);
        
        if (threadsMapper == null || repliesMapper == null) return;

        BbsThreadsDO thread = threadsMapper.selectOneByQuery(
                new QueryWrapper()
                        .eq(BbsThreadsDO::getGuildid, c.getPlayer().getGuildId())
                        .eq(BbsThreadsDO::getLocalthreadid, (long) localthreadid)
        );

        if (thread == null) {
            return;
        }
        
        long threadid = thread.getThreadid();

        BbsRepliesDO reply = new BbsRepliesDO();
        reply.setThreadid(threadid);
        reply.setPostercid((long) c.getPlayer().getId());
        reply.setTimestamp(BigInteger.valueOf(System.currentTimeMillis()));
        reply.setContent(text);
        repliesMapper.insert(reply);

        thread.setReplycount(thread.getReplycount() + 1);
        threadsMapper.update(thread);

        displayThread(c, localthreadid);
    }

    private static void editBBSThread(Client client, String title, String text, int icon, int localthreadid) {
        Character chr = client.getPlayer();
        if (chr.getGuildId() < 1) {
            return;
        }
        
        BbsThreadsMapper mapper = SpringContextUtil.getBean(BbsThreadsMapper.class);
        if (mapper == null) return;

        BbsThreadsDO thread = mapper.selectOneByQuery(
                new QueryWrapper()
                        .eq(BbsThreadsDO::getGuildid, chr.getGuildId())
                        .eq(BbsThreadsDO::getLocalthreadid, (long) localthreadid)
        );

        if (thread != null && (thread.getPostercid() == chr.getId() || chr.getGuildRank() < 3)) {
            thread.setName(title);
            thread.setTimestamp(BigInteger.valueOf(System.currentTimeMillis()));
            thread.setIcon(icon);
            thread.setStartpost(text);
            mapper.update(thread);
            
            displayThread(client, localthreadid);
        }
    }

    private static void newBBSThread(Client client, String title, String text, int icon, boolean bNotice) {
        Character chr = client.getPlayer();
        if (chr.getGuildId() <= 0) {
            return;
        }
        
        BbsThreadsMapper mapper = SpringContextUtil.getBean(BbsThreadsMapper.class);
        if (mapper == null) return;

        long nextId = 0;
        if (!bNotice) {
            BbsThreadsDO lastThread = mapper.selectOneByQuery(
                    new QueryWrapper()
                            .select(BbsThreadsDO::getLocalthreadid)
                            .eq(BbsThreadsDO::getGuildid, chr.getGuildId())
                            .orderBy(BbsThreadsDO::getLocalthreadid, false)
                            .limit(1)
            );
            if (lastThread != null && lastThread.getLocalthreadid() != null) {
                nextId = lastThread.getLocalthreadid() + 1;
            } else {
                nextId = 1;
            }
        }

        BbsThreadsDO newThread = new BbsThreadsDO();
        newThread.setPostercid((long) chr.getId());
        newThread.setName(title);
        newThread.setTimestamp(BigInteger.valueOf(System.currentTimeMillis()));
        newThread.setIcon(icon);
        newThread.setStartpost(text);
        newThread.setGuildid((long) chr.getGuildId());
        newThread.setLocalthreadid(nextId);
        newThread.setReplycount(0);
        
        mapper.insert(newThread);

        displayThread(client, (int) nextId);
    }

    public static void deleteBBSThread(Client client, int localthreadid) {
        Character mc = client.getPlayer();
        if (mc.getGuildId() <= 0) {
            return;
        }
        
        BbsThreadsMapper threadsMapper = SpringContextUtil.getBean(BbsThreadsMapper.class);
        BbsRepliesMapper repliesMapper = SpringContextUtil.getBean(BbsRepliesMapper.class);
        if (threadsMapper == null || repliesMapper == null) return;

        BbsThreadsDO thread = threadsMapper.selectOneByQuery(
                new QueryWrapper()
                        .eq(BbsThreadsDO::getGuildid, mc.getGuildId())
                        .eq(BbsThreadsDO::getLocalthreadid, (long) localthreadid)
        );

        if (thread == null) {
            return;
        }

        if (mc.getId() != thread.getPostercid() && mc.getGuildRank() > 2) {
            return;
        }

        long threadid = thread.getThreadid();

        repliesMapper.deleteByQuery(new QueryWrapper().eq(BbsRepliesDO::getThreadid, threadid));
        threadsMapper.deleteById(threadid);
    }

    public static void deleteBBSReply(Client client, int replyid) {
        Character mc = client.getPlayer();
        if (mc.getGuildId() <= 0) {
            return;
        }
        
        BbsThreadsMapper threadsMapper = SpringContextUtil.getBean(BbsThreadsMapper.class);
        BbsRepliesMapper repliesMapper = SpringContextUtil.getBean(BbsRepliesMapper.class);
        if (threadsMapper == null || repliesMapper == null) return;

        BbsRepliesDO reply = repliesMapper.selectOneById(replyid);

        if (reply == null) {
            return;
        }

        if (mc.getId() != reply.getPostercid() && mc.getGuildRank() > 2) {
            return;
        }

        long threadid = reply.getThreadid();

        repliesMapper.deleteById(replyid);

        BbsThreadsDO thread = threadsMapper.selectOneById(threadid);
        if (thread != null) {
            thread.setReplycount(Math.max(0, thread.getReplycount() - 1));
            threadsMapper.update(thread);
            
            displayThread(client, thread.getLocalthreadid().intValue());
        }
    }

    public static void displayThread(Client client, int localthreadid) {
        displayThread(client, localthreadid, true);
    }

    public static void displayThread(Client client, int localthreadid, boolean bIsThreadIdLocal) {
        Character mc = client.getPlayer();
        if (mc.getGuildId() <= 0) {
            return;
        }
        
        BbsThreadsMapper threadsMapper = SpringContextUtil.getBean(BbsThreadsMapper.class);
        BbsRepliesMapper repliesMapper = SpringContextUtil.getBean(BbsRepliesMapper.class);
        if (threadsMapper == null || repliesMapper == null) return;

        QueryWrapper query = new QueryWrapper().eq(BbsThreadsDO::getGuildid, mc.getGuildId());
        if (bIsThreadIdLocal) {
            query.eq(BbsThreadsDO::getLocalthreadid, (long) localthreadid);
        } else {
            query.eq(BbsThreadsDO::getThreadid, (long) localthreadid);
        }
        
        BbsThreadsDO thread = threadsMapper.selectOneByQuery(query);
        
        if (thread == null) {
            return;
        }
        
        List<BbsRepliesDO> replies = null;
        if (thread.getReplycount() > 0) {
            replies = repliesMapper.selectListByQuery(new QueryWrapper().eq(BbsRepliesDO::getThreadid, thread.getThreadid()));
        }
        
        client.sendPacket(GuildPackets.showThread(thread.getLocalthreadid().intValue(), thread, replies));
    }
}
