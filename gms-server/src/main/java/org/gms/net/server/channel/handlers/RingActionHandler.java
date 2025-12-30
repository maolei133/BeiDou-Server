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
import org.gms.client.Ring;
import org.gms.client.inventory.Equip;
import org.gms.client.inventory.InventoryType;
import org.gms.client.inventory.Item;
import org.gms.client.inventory.manipulator.InventoryManipulator;
import org.gms.client.processor.npc.DueyProcessor;
import org.gms.constants.id.ItemId;
import org.gms.dao.entity.CharactersDO;
import org.gms.dao.entity.InventoryitemsDO;
import org.gms.dao.mapper.CharactersMapper;
import org.gms.dao.mapper.InventoryitemsMapper;
import org.gms.net.AbstractPacketHandler;
import org.gms.net.packet.InPacket;
import org.gms.net.server.channel.Channel;
import org.gms.net.server.world.World;
import org.gms.scripting.event.EventInstanceManager;
import org.gms.server.ItemInformationProvider;
import org.gms.service.NoteService;
import org.gms.util.PacketCreator;
import org.gms.util.Pair;
import org.gms.util.SpringContextUtil;
import org.gms.util.packets.WeddingPackets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Jvlaple
 * @author Ronan - major overhaul on Ring handling mechanics
 * @author Drago (Dragohe4rt) - on Wishlist
 */
public final class RingActionHandler extends AbstractPacketHandler {
    private static final Logger log = LoggerFactory.getLogger(RingActionHandler.class);

    private final NoteService noteService;

    public RingActionHandler(NoteService noteService) {
        this.noteService = noteService;
    }

    private static int getEngagementBoxId(int useItemId) {
        return switch (useItemId) {
            case ItemId.ENGAGEMENT_BOX_MOONSTONE -> ItemId.EMPTY_ENGAGEMENT_BOX_MOONSTONE;
            case ItemId.ENGAGEMENT_BOX_STAR -> ItemId.EMPTY_ENGAGEMENT_BOX_STAR;
            case ItemId.ENGAGEMENT_BOX_GOLDEN -> ItemId.EMPTY_ENGAGEMENT_BOX_GOLDEN;
            case ItemId.ENGAGEMENT_BOX_SILVER -> ItemId.EMPTY_ENGAGEMENT_BOX_SILVER;
            default -> ItemId.CARAT_RING_BASE + (useItemId - ItemId.CARAT_RING_BOX_BASE);
        };
    }

    public static void sendEngageProposal(final Client c, final String name, final int itemid) {
        final int newBoxId = getEngagementBoxId(itemid);
        final Character target = c.getChannelServer().getPlayerStorage().getCharacterByName(name);
        final Character source = c.getPlayer();

        if (source.isMarried()) {
            source.dropMessage(1, "你已经结婚了！");
            source.sendPacket(WeddingPackets.OnMarriageResult((byte) 0));
            return;
        } else if (source.getPartnerId() > 0) {
            source.dropMessage(1, "你已经订婚了！");
            source.sendPacket(WeddingPackets.OnMarriageResult((byte) 0));
            return;
        } else if (source.getMarriageItemId() > 0) {
            source.dropMessage(1, "你已经在向某人求婚了！");
            source.sendPacket(WeddingPackets.OnMarriageResult((byte) 0));
            return;
        } else if (target == null) {
            source.dropMessage(1, "在这个频道找不到 " + name + "。");
            source.sendPacket(WeddingPackets.OnMarriageResult((byte) 0));
            return;
        } else if (target == source) {
            source.dropMessage(1, "你不能向自己求婚。");
            source.sendPacket(WeddingPackets.OnMarriageResult((byte) 0));
            return;
        } else if (target.getLevel() < 50) {
            source.dropMessage(1, "你只能向50级或以上的玩家求婚。");
            source.sendPacket(WeddingPackets.OnMarriageResult((byte) 0));
            return;
        } else if (source.getLevel() < 50) {
            source.dropMessage(1, "你必须达到50级或以上才能求婚。");
            source.sendPacket(WeddingPackets.OnMarriageResult((byte) 0));
            return;
        } else if (!target.getMap().equals(source.getMap())) {
            source.dropMessage(1, "请确保你的伴侣在同一张地图上！");
            source.sendPacket(WeddingPackets.OnMarriageResult((byte) 0));
            return;
        } else if (!source.haveItem(itemid) || itemid < ItemId.ENGAGEMENT_BOX_MIN || itemid > ItemId.ENGAGEMENT_BOX_MAX) {
            source.sendPacket(WeddingPackets.OnMarriageResult((byte) 0));
            return;
        } else if (target.isMarried()) {
            source.dropMessage(1, "该玩家已经结婚了！");
            source.sendPacket(WeddingPackets.OnMarriageResult((byte) 0));
            return;
        } else if (target.getPartnerId() > 0 || target.getMarriageItemId() > 0) {
            source.dropMessage(1, "该玩家已经订婚了！");
            source.sendPacket(WeddingPackets.OnMarriageResult((byte) 0));
            return;
        } else if (target.haveWeddingRing()) {
            source.dropMessage(1, "该玩家已经拥有结婚戒指了...");
            source.sendPacket(WeddingPackets.OnMarriageResult((byte) 0));
            return;
        } else if (source.haveWeddingRing()) {
            source.dropMessage(1, "你不能在拥有结婚戒指时求婚！");
            source.sendPacket(WeddingPackets.OnMarriageResult((byte) 0));
            return;
        } else if (target.getGender() == source.getGender()) {
            source.dropMessage(1, "你只能向" + (source.getGender() == 1 ? "男性" : "女性") + "求婚！");
            source.sendPacket(WeddingPackets.OnMarriageResult((byte) 0));
            return;
        } else if (!InventoryManipulator.checkSpace(c, newBoxId, 1, "")) {
            source.dropMessage(5, "你现在没有可用的其他栏空间！");
            source.sendPacket(WeddingPackets.OnMarriageResult((byte) 0));
            return;
        } else if (!InventoryManipulator.checkSpace(target.getClient(), newBoxId + 1, 1, "")) {
            source.dropMessage(5, "你求婚的对象现在没有可用的其他栏空间。");
            source.sendPacket(WeddingPackets.OnMarriageResult((byte) 0));
            return;
        }

        source.setMarriageItemId(itemid);
        target.sendPacket(WeddingPackets.onMarriageRequest(source.getName(), source.getId()));
    }

    private static void eraseEngagementOffline(int characterId) {
        CharactersMapper mapper = SpringContextUtil.getBean(CharactersMapper.class);
        if (mapper != null) {
            CharactersDO updateEntity = new CharactersDO();
            updateEntity.setId(characterId);
            updateEntity.setMarriageItemId(-1);
            updateEntity.setPartnerId(-1);
            mapper.update(updateEntity);
        }
    }

    private static void breakEngagementOffline(int characterId) {
        CharactersMapper charMapper = SpringContextUtil.getBean(CharactersMapper.class);
        InventoryitemsMapper itemsMapper = SpringContextUtil.getBean(InventoryitemsMapper.class);
        
        if (charMapper != null) {
            CharactersDO character = charMapper.selectOneById(characterId);
            
            if (character != null) {
                int marriageItemId = character.getMarriageItemId();

                if (marriageItemId > 0 && itemsMapper != null) {
                    InventoryitemsDO updateEntity = new InventoryitemsDO();
                    updateEntity.setExpiration(0L);
                    
                    itemsMapper.updateByQuery(updateEntity, 
                            new QueryWrapper()
                                    .eq(InventoryitemsDO::getItemid, marriageItemId)
                                    .eq(InventoryitemsDO::getCharacterid, characterId)
                    );
                }
            }
            
            eraseEngagementOffline(characterId);
        }
    }

    private synchronized static void breakMarriage(Character chr) {
        int partnerid = chr.getPartnerId();
        if (partnerid <= 0) {
            return;
        }

        chr.getClient().getWorldServer().deleteRelationship(chr.getId(), partnerid);
        Ring.removeRing(chr.getMarriageRing());

        Character partner = chr.getClient().getWorldServer().getPlayerStorage().getCharacterById(partnerid);
        if (partner == null) {
            eraseEngagementOffline(partnerid);
        } else {
            partner.dropMessage(5, chr.getName() + " 决定解除婚姻关系。");
            partner.sendPacket(WeddingPackets.OnNotifyWeddingPartnerTransfer(0, 0));
            resetRingId(partner);
            partner.setPartnerId(-1);
            partner.setMarriageItemId(-1);
            partner.setMarriageRing(null);
        }

        chr.dropMessage(5, "你已成功解除与 " + Character.getNameById(partnerid) + " 的婚姻关系。");
        chr.sendPacket(WeddingPackets.OnNotifyWeddingPartnerTransfer(0, 0));
        resetRingId(chr);
        chr.setPartnerId(-1);
        chr.setMarriageItemId(-1);
        chr.setMarriageRing(null);
    }

    private static void resetRingId(Character player) {
        int ringitemid = player.getMarriageRing().getItemId();

        Item it = player.getInventory(InventoryType.EQUIP).findById(ringitemid);
        if (it == null) {
            it = player.getInventory(InventoryType.EQUIPPED).findById(ringitemid);
        }

        if (it != null) {
            Equip eqp = (Equip) it;
            eqp.setRingId(-1);
        }
    }

    private synchronized static void breakEngagement(Character chr) {
        int partnerid = chr.getPartnerId();
        int marriageitemid = chr.getMarriageItemId();

        chr.getClient().getWorldServer().deleteRelationship(chr.getId(), partnerid);

        Character partner = chr.getClient().getWorldServer().getPlayerStorage().getCharacterById(partnerid);
        if (partner == null) {
            breakEngagementOffline(partnerid);
        } else {
            partner.dropMessage(5, chr.getName() + " 决定解除婚约。");

            int partnerMarriageitemid = marriageitemid + ((chr.getGender() == 0) ? 1 : -1);
            if (partner.haveItem(partnerMarriageitemid)) {
                InventoryManipulator.removeById(partner.getClient(), InventoryType.ETC, partnerMarriageitemid, (short) 1, false, false);
            }

            partner.sendPacket(WeddingPackets.OnNotifyWeddingPartnerTransfer(0, 0));
            partner.setPartnerId(-1);
            partner.setMarriageItemId(-1);
        }

        if (chr.haveItem(marriageitemid)) {
            InventoryManipulator.removeById(chr.getClient(), InventoryType.ETC, marriageitemid, (short) 1, false, false);
        }
        chr.dropMessage(5, "你已成功解除与 " + Character.getNameById(partnerid) + " 的婚约。");
        chr.sendPacket(WeddingPackets.OnNotifyWeddingPartnerTransfer(0, 0));
        chr.setPartnerId(-1);
        chr.setMarriageItemId(-1);
    }

    public static void breakMarriageRing(Character chr, final int wItemId) {
        final InventoryType type = InventoryType.getByType((byte) (wItemId / 1000000));
        final Item wItem = chr.getInventory(type).findById(wItemId);
        final boolean weddingToken = (wItem != null && type == InventoryType.ETC && wItemId / 10000 == 403);
        final boolean weddingRing = (wItem != null && wItemId / 10 == 111280);

        if (weddingRing) {
            if (chr.getPartnerId() > 0) {
                breakMarriage(chr);
            }

            chr.getMap().disappearingItemDrop(chr, chr, wItem, chr.getPosition());
        } else if (weddingToken) {
            if (chr.getPartnerId() > 0) {
                breakEngagement(chr);
            }

            chr.getMap().disappearingItemDrop(chr, chr, wItem, chr.getPosition());
        }
    }

    public static void giveMarriageRings(Character player, Character partner, int marriageRingId) {
        Pair<Integer, Integer> rings = Ring.createRing(marriageRingId, player, partner);
        ItemInformationProvider ii = ItemInformationProvider.getInstance();

        Item ringObj = ii.getEquipById(marriageRingId);
        Equip ringEqp = (Equip) ringObj;
        ringEqp.setRingId(rings.getLeft());
        player.setMarriageRing(Ring.loadFromDb(rings.getLeft()));
        InventoryManipulator.addFromDrop(player.getClient(), ringEqp, false, -1);
        player.broadcastMarriageMessage();

        ringObj = ii.getEquipById(marriageRingId);
        ringEqp = (Equip) ringObj;
        ringEqp.setRingId(rings.getRight());
        partner.setMarriageRing(Ring.loadFromDb(rings.getRight()));
        InventoryManipulator.addFromDrop(partner.getClient(), ringEqp, false, -1);
        partner.broadcastMarriageMessage();
    }

    @Override
    public final void handlePacket(InPacket p, Client c) {
        byte mode = p.readByte();
        String name;
        byte slot;
        switch (mode) {
            case 0: // 发送求婚
                sendEngageProposal(c, p.readString(), p.readInt());
                break;

            case 1: // 取消求婚
                if (c.getPlayer().getMarriageItemId() / 1000000 != 4) {
                    c.getPlayer().setMarriageItemId(-1);
                }
                break;

            case 2: // 接受/拒绝求婚
                final boolean accepted = p.readByte() > 0;
                name = p.readString();
                final int id = p.readInt();

                final Character source = c.getWorldServer().getPlayerStorage().getCharacterByName(name);
                final Character target = c.getPlayer();

                if (source == null) {
                    target.sendPacket(PacketCreator.enableActions());
                    return;
                }

                final int itemid = source.getMarriageItemId();
                if (target.getPartnerId() > 0 || source.getId() != id || itemid <= 0 || !source.haveItem(itemid) || source.getPartnerId() > 0 || !source.isAlive() || !target.isAlive()) {
                    target.sendPacket(PacketCreator.enableActions());
                    return;
                }

                if (accepted) {
                    final int newItemId = getEngagementBoxId(itemid);
                    if (!InventoryManipulator.checkSpace(c, newItemId, 1, "") || !InventoryManipulator.checkSpace(source.getClient(), newItemId, 1, "")) {
                        target.sendPacket(PacketCreator.enableActions());
                        return;
                    }

                    try {
                        InventoryManipulator.removeById(source.getClient(), InventoryType.USE, itemid, 1, false, false);

                        int marriageId = c.getWorldServer().createRelationship(source.getId(), target.getId());
                        source.setPartnerId(target.getId()); // 订婚（新的 marriageitemid，双方的 partnerid）
                        target.setPartnerId(source.getId());

                        source.setMarriageItemId(newItemId);
                        target.setMarriageItemId(newItemId + 1);

                        InventoryManipulator.addById(source.getClient(), newItemId, (short) 1);
                        InventoryManipulator.addById(c, (newItemId + 1), (short) 1);

                        source.sendPacket(WeddingPackets.OnMarriageResult(marriageId, source, false));
                        target.sendPacket(WeddingPackets.OnMarriageResult(marriageId, source, false));

                        source.sendPacket(WeddingPackets.OnNotifyWeddingPartnerTransfer(target.getId(), target.getMapId()));
                        target.sendPacket(WeddingPackets.OnNotifyWeddingPartnerTransfer(source.getId(), source.getMapId()));
                    } catch (Exception e) {
                        log.error("订婚出错", e);
                    }
                } else {
                    source.dropMessage(1, "她礼貌地拒绝了你的订婚请求。");
                    source.sendPacket(WeddingPackets.OnMarriageResult((byte) 0));

                    source.setMarriageItemId(-1);
                }
                break;

            case 3: // 解除婚约
                breakMarriageRing(c.getPlayer(), p.readInt());
                break;

            case 5: // 邀请 %s 参加婚礼
                name = p.readString();
                int marriageId = p.readInt();
                slot = p.readByte(); // 这是一个 int

                int itemId;
                try {
                    itemId = c.getPlayer().getInventory(InventoryType.ETC).getItem(slot).getItemId();
                } catch (NullPointerException npe) {
                    c.sendPacket(PacketCreator.enableActions());
                    return;
                }

                if ((itemId != ItemId.INVITATION_CHAPEL && itemId != ItemId.INVITATION_CATHEDRAL) || !c.getPlayer().haveItem(itemId)) {
                    c.sendPacket(PacketCreator.enableActions());
                    return;
                }

                String groom = c.getPlayer().getName();
                String bride = Character.getNameById(c.getPlayer().getPartnerId());
                int guest = Character.getIdByName(name);
                if (groom == null || bride == null || groom.equals("") || bride.equals("") || guest <= 0) {
                    c.getPlayer().dropMessage(5, "找不到 " + name + "！");
                    return;
                }

                try {
                    World wserv = c.getWorldServer();
                    Pair<Boolean, Boolean> registration = wserv.getMarriageQueuedLocation(marriageId);

                    if (registration != null) {
                        if (wserv.addMarriageGuest(marriageId, guest)) {
                            boolean cathedral = registration.getLeft();
                            int newItemId = cathedral ? ItemId.RECEIVED_INVITATION_CATHEDRAL : ItemId.RECEIVED_INVITATION_CHAPEL;

                            Channel cserv = c.getChannelServer();
                            int resStatus = cserv.getWeddingReservationStatus(marriageId, cathedral);
                            if (resStatus > 0) {
                                long expiration = cserv.getWeddingTicketExpireTime(resStatus + 1);

                                String baseMessage = "你被邀请参加 %s 和 %s 的婚礼！".formatted(groom, bride);
                                Character guestChr = c.getWorldServer().getPlayerStorage().getCharacterById(guest);
                                if (guestChr != null && InventoryManipulator.checkSpace(guestChr.getClient(), newItemId, 1, "") && InventoryManipulator.addById(guestChr.getClient(), newItemId, (short) 1, expiration)) {
                                    guestChr.dropMessage(6, "[婚礼] %s".formatted(baseMessage));
                                } else {
                                    String dueyMessage = baseMessage + " 从 Duey 那里领取你的邀请函！";
                                    if (guestChr != null && guestChr.isLoggedInWorld()) {
                                        guestChr.dropMessage(6, "[婚礼] %s".formatted(dueyMessage));
                                    } else {
                                        noteService.sendNormal(dueyMessage, groom, name);
                                    }

                                    Item weddingTicket = new Item(newItemId, (short) 0, (short) 1);
                                    weddingTicket.setExpiration(expiration);

                                    DueyProcessor.dueyCreatePackage(weddingTicket, 0, groom, guest);
                                }
                            } else {
                                c.getPlayer().dropMessage(5, "婚礼已经在进行中。你不能再邀请更多客人了。");
                            }
                        } else {
                            c.getPlayer().dropMessage(5, "'" + name + "' 已经被邀请参加你的婚礼了。");
                        }
                    } else {
                        c.getPlayer().dropMessage(5, "邀请函未发送给 '" + name + "'。要么你的婚礼预定时间已经到了，要么未找到。");
                    }

                } catch (Exception ex) {
                    ex.printStackTrace();
                    return;
                }

                c.getAbstractPlayerInteraction().gainItem(itemId, (short) -1);
                break;

            case 6: // 打开婚礼邀请函
                slot = (byte) p.readInt();
                int invitationid = p.readInt();

                if (invitationid == ItemId.RECEIVED_INVITATION_CHAPEL || invitationid == ItemId.RECEIVED_INVITATION_CATHEDRAL) {
                    Item item = c.getPlayer().getInventory(InventoryType.ETC).getItem(slot);
                    if (item == null || item.getItemId() != invitationid) {
                        c.sendPacket(PacketCreator.enableActions());
                        return;
                    }

                    // 冲突情况：最近的婚礼将会显示
                    Pair<Integer, Integer> coupleId = c.getWorldServer().getWeddingCoupleForGuest(c.getPlayer().getId(), invitationid == ItemId.RECEIVED_INVITATION_CATHEDRAL);
                    if (coupleId != null) {
                        int groomId = coupleId.getLeft(), brideId = coupleId.getRight();
                        c.sendPacket(WeddingPackets.sendWeddingInvitation(Character.getNameById(groomId), Character.getNameById(brideId)));
                    }
                }

                break;

            case 9:
                try {
                    // By -- Dragoso (Drago)
                    // 新郎和新娘的愿望清单

                    Character player = c.getPlayer();

                    EventInstanceManager eim = player.getEventInstance();
                    if (eim != null) {
                        boolean isMarrying = (player.getId() == eim.getIntProperty("groomId") || player.getId() == eim.getIntProperty("brideId"));

                        if (isMarrying) {
                            int amount = p.readShort();
                            if (amount > 10) {
                                amount = 10;
                            }

                            String wishlistItems = "";
                            for (int i = 0; i < amount; i++) {
                                String s = p.readString();
                                wishlistItems += (s + "\r\n");
                            }

                            String wlKey;
                            if (player.getId() == eim.getIntProperty("groomId")) {
                                wlKey = "groomWishlist";
                            } else {
                                wlKey = "brideWishlist";
                            }

                            if (eim.getProperty(wlKey).contentEquals("")) {
                                eim.setProperty(wlKey, wishlistItems);
                            }
                        }
                    }
                } catch (NumberFormatException nfe) {
                }

                break;

            default:
                log.warn("未处理的 RING_ACTION 模式。数据包: {}", p);
                break;
        }

        c.sendPacket(PacketCreator.enableActions());
    }
}
