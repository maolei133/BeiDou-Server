/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package org.gms.util.packets;

import org.gms.client.Character;
import org.gms.client.inventory.Item;
import org.gms.constants.id.ItemId;
import org.gms.constants.id.MapId;
import org.gms.net.opcodes.SendOpcode;
import org.gms.net.packet.OutPacket;
import org.gms.net.packet.Packet;
import org.gms.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * WeddingPackets
 * 处理婚礼相关的数据包构建，包括 CField_Wedding, CField_WeddingPhoto, CWeddingMan, OnMarriageResult 以及所有婚礼/婚姻相关的枚举/结构体。
 *
 * @author Eric
 * <p>
 * 愿望清单由 Drago (Dragohe4rt) 编辑
 */
public class WeddingPackets {
    private static final Logger log = LoggerFactory.getLogger(WeddingPackets.class);

    /*
        00000000 CWeddingMan     struc ; (sizeof=0x104)
        00000000 vfptr           dd ?                    ; offset
        00000004 ___u1           $01CBC6800BD386B8A8FD818EAD990BEC ?
        0000000C m_mCharIDToMarriageNo ZMap<unsigned long,unsigned long,unsigned long> ?
        00000024 m_mReservationPending ZMap<unsigned long,ZRef<GW_WeddingReservation>,unsigned long> ?
        0000003C m_mReservationPendingGroom ZMap<unsigned long,ZRef<CUser>,unsigned long> ?
        00000054 m_mReservationPendingBride ZMap<unsigned long,ZRef<CUser>,unsigned long> ?
        0000006C m_mReservationStartUser ZMap<unsigned long,unsigned long,unsigned long> ?
        00000084 m_mReservationCompleted ZMap<unsigned long,ZRef<GW_WeddingReservation>,unsigned long> ?
        0000009C m_mGroomWishList ZMap<unsigned long,ZRef<ZArray<ZXString<char> > >,unsigned long> ?
        000000B4 m_mBrideWishList ZMap<unsigned long,ZRef<ZArray<ZXString<char> > >,unsigned long> ?
        000000CC m_mEngagementPending ZMap<unsigned long,ZRef<GW_MarriageRecord>,unsigned long> ?
        000000E4 m_nCurrentWeddingState dd ?
        000000E8 m_dwCurrentWeddingNo dd ?
        000000EC m_dwCurrentWeddingMap dd ?
        000000F0 m_bIsReservationLoaded dd ?
        000000F4 m_dwNumGuestBless dd ?
        000000F8 m_bPhotoSuccess dd ?
        000000FC m_tLastUpdate   dd ?
        00000100 m_bStartWeddingCeremony dd ?
        00000104 CWeddingMan     ends
    */

    public class Field_Wedding {
        public int m_nNoticeCount;
        public int m_nCurrentStep;
        public int m_nBlessStartTime;
    }

    public class Field_WeddingPhoto {
        public boolean m_bPictureTook;
    }

    public class GW_WeddingReservation {
        public int dwReservationNo;
        public int dwGroom, dwBride;
        public String sGroomName, sBrideName;
        public int usWeddingType;
    }

    public class WeddingWishList {
        public Character pUser;
        public int dwMarriageNo;
        public int nGender;
        public int nWLType;
        public int nSlotCount;
        public List<String> asWishList = new ArrayList<>();
        public int usModifiedFlag; // dword
        public boolean bLoaded;
    }

    public class GW_WeddingWishList {
        public final int WEDDINGWL_MAX = 0xA; // enum WEDDINGWL
        public int dwReservationNo;
        public byte nGender;
        public String sItemName;
    }

    public enum MarriageStatus {
        SINGLE(0x0),
        ENGAGED(0x1),
        RESERVED(0x2),
        MARRIED(0x3);
        private final int ms;

        MarriageStatus(int ms) {
            this.ms = ms;
        }

        public int getMarriageStatus() {
            return ms;
        }
    }

    public enum MarriageRequest {
        AddMarriageRecord(0x0),
        SetMarriageRecord(0x1),
        DeleteMarriageRecord(0x2),
        LoadReservation(0x3),
        AddReservation(0x4),
        DeleteReservation(0x5),
        GetReservation(0x6);
        private final int req;

        MarriageRequest(int req) {
            this.req = req;
        }

        public int getMarriageRequest() {
            return req;
        }
    }

    public enum WeddingType {
        CATHEDRAL(0x1),
        VEGAS(0x2),
        CATHEDRAL_PREMIUM(0xA),
        CATHEDRAL_NORMAL(0xB),
        VEGAS_PREMIUM(0x14),
        VEGAS_NORMAL(0x15);
        private final int wt;

        WeddingType(int wt) {
            this.wt = wt;
        }

        public int getType() {
            return wt;
        }
    }

    public enum WeddingMap {
        WEDDINGTOWN(MapId.AMORIA),
        CHAPEL_STARTMAP(MapId.CHAPEL_WEDDING_ALTAR),
        CATHEDRAL_STARTMAP(MapId.CATHEDRAL_WEDDING_ALTAR),
        PHOTOMAP(MapId.WEDDING_PHOTO),
        EXITMAP(MapId.WEDDING_EXIT);
        private final int wm;

        WeddingMap(int wm) {
            this.wm = wm;
        }

        public int getMap() {
            return wm;
        }
    }

    public enum WeddingItem {
        WR_MOONSTONE(ItemId.WEDDING_RING_MOONSTONE), // Wedding Ring
        WR_STARGEM(ItemId.WEDDING_RING_STAR),
        WR_GOLDENHEART(ItemId.WEDDING_RING_GOLDEN),
        WR_SILVERSWAN(ItemId.WEDDING_RING_SILVER),
        ERB_MOONSTONE(ItemId.ENGAGEMENT_BOX_MOONSTONE), // Engagement Ring Box
        ERB_STARGEM(ItemId.ENGAGEMENT_BOX_STAR),
        ERB_GOLDENHEART(ItemId.ENGAGEMENT_BOX_GOLDEN),
        ERB_SILVERSWAN(ItemId.ENGAGEMENT_BOX_SILVER),
        ERBE_MOONSTONE(ItemId.EMPTY_ENGAGEMENT_BOX_MOONSTONE), // Engagement Ring Box (Empty)
        ER_MOONSTONE(ItemId.ENGAGEMENT_RING_MOONSTONE), // Engagement Ring
        ERBE_STARGEM(ItemId.EMPTY_ENGAGEMENT_BOX_STAR),
        ER_STARGEM(ItemId.ENGAGEMENT_RING_STAR),
        ERBE_GOLDENHEART(ItemId.EMPTY_ENGAGEMENT_BOX_GOLDEN),
        ER_GOLDENHEART(ItemId.ENGAGEMENT_RING_GOLDEN),
        ERBE_SILVERSWAN(ItemId.EMPTY_ENGAGEMENT_BOX_SILVER),
        ER_SILVERSWAN(ItemId.ENGAGEMENT_RING_SILVER),
        PARENTS_BLESSING(ItemId.PARENTS_BLESSING), // Parents Blessing
        OFFICIATORS_PERMISSION(ItemId.OFFICIATORS_PERMISSION), // Officiator's Permission
        WR_CATHEDRAL_PREMIUM(ItemId.PREMIUM_CATHEDRAL_RESERVATION_RECEIPT), // Wedding Ring?
        WR_VEGAS_PREMIUM(ItemId.PREMIUM_CHAPEL_RESERVATION_RECEIPT),
        IB_VEGAS(ItemId.INVITATION_CHAPEL),      // toSend invitation
        IB_CATHEDRAL(ItemId.INVITATION_CATHEDRAL),  // toSend invitation
        IG_VEGAS(ItemId.RECEIVED_INVITATION_CHAPEL),      // rcvd invitation
        IG_CATHEDRAL(ItemId.RECEIVED_INVITATION_CATHEDRAL),  // rcvd invitation
        OB_FORCOUPLE(ItemId.ONYX_CHEST_FOR_COUPLE), // Onyx Box? For Couple
        WR_CATHEDRAL_NORMAL(ItemId.NORMAL_CATHEDRAL_RESERVATION_RECEIPT), // Wedding Ring?
        WR_VEGAS_NORMAL(ItemId.NORMAL_CHAPEL_RESERVATION_RECEIPT),
        WT_CATHEDRAL_NORMAL(ItemId.NORMAL_WEDDING_TICKET_CATHEDRAL), // Wedding Ticket
        WT_VEGAS_NORMAL(ItemId.NORMAL_WEDDING_TICKET_CHAPEL),
        WT_VEGAS_PREMIUM(ItemId.PREMIUM_WEDDING_TICKET_CHAPEL),
        WT_CATHEDRAL_PREMIUM(ItemId.PREMIUM_WEDDING_TICKET_CATHEDRAL);
        private final int wi;

        WeddingItem(int wi) {
            this.wi = wi;
        }

        public int getItem() {
            return wi;
        }
    }

    /**
     * 添加角色外观信息
     *
     * @param p    输出数据包
     * @param chr  角色对象
     * @param mega 是否为喇叭
     */
    public static void addCharLook(OutPacket p, Character chr, boolean mega) {
        PacketHelper.addCharLook(p, chr, mega);
    }

    /**
     * 添加物品信息
     *
     * @param p            输出数据包
     * @param item         物品对象
     * @param zeroPosition 是否位置为0
     */
    public static void addItemInfo(OutPacket p, Item item, boolean zeroPosition) {
        PacketHelper.addItemInfo(p, item, zeroPosition);
    }

    /**
     * <name> 请求订婚。你愿意接受这个提议吗？
     *
     * @param name     请求者名字
     * @param playerid 请求者ID
     * @return mplew
     */
    public static Packet onMarriageRequest(String name, int playerid) {
        OutPacket p = OutPacket.create(SendOpcode.MARRIAGE_REQUEST);
        p.writeByte(0); //mode, 0 = engage, 1 = cancel, 2 = answer.. etc // 模式，0 = 订婚，1 = 取消，2 = 回答.. 等
        p.writeString(name); // name // 名字
        p.writeInt(playerid); // playerid // 玩家ID
        return p;
    }

    /**
     * WeddingPhoto_OnTakePhoto 工作原理简述 (基于 BMS 搜索):
     * - 我们发送这个包，首先包含新郎/新娘的 IGN
     * - 然后发送一个 fieldId (目前不确定这部分，90% 确定它是地图 ID)
     * - 之后，我们写入当前地图中的角色数量 (即蛋糕地图 -- 排除退出地图中的用户)
     * - 一旦我们获取了角色的大小，我们就开始写入关于他们的信息 (编码他们的名字、公会等信息)
     * - 现在我们已经编码了角色数据，我们开始编码 ScreenShotPacket，它需要 TemplateID、IGN 和他们的位置
     * - 最后，在编码完所有数据后，我们将此包发送到 MapGen 应用程序服务器
     * - MapGen 服务器将检索包字节数组并将字节转换为 ImageIO 2D JPG 输出
     * - 转换为 JPG 后的结果将被远程上传到 /weddings/ 并以 ReservedGroomName_ReservedBrideName 命名，以便在 Web 服务器上显示。
     * <p>
     * - 将不再继续婚礼照片，需要 WvsMapGen :(
     *
     * @param ReservedGroomName 婚礼的新郎 IGN
     * @param ReservedBrideName 婚礼的新娘 IGN
     * @param m_dwField         当前字段 ID (蛋糕地图的 ID，例如 680000300)
     * @param m_dwUsers         当前蛋糕地图内的所有角色宾客列表，用于编码
     * @return mplew (MaplePacket) 用于 byte[]->ImageIO 转换和读取的字节数组
     */
    public static Packet onTakePhoto(String ReservedGroomName, String ReservedBrideName, int m_dwField, List<Character> m_dwUsers) { // OnIFailedAtWeddingPhotos
        OutPacket p = OutPacket.create(SendOpcode.WEDDING_PHOTO);// v53 header, convert -> v83 // v53 头部，转换为 v83
        p.writeString(ReservedGroomName);
        p.writeString(ReservedBrideName);
        p.writeInt(m_dwField); // field id? // 字段 ID？
        p.writeInt(m_dwUsers.size());

        for (Character guest : m_dwUsers) {
            // 开始头像编码
            addCharLook(p, guest, false); // CUser::EncodeAvatar
            p.writeInt(30000); // v20 = *(_DWORD *)(v13 + 2192) -- new groom marriage ID?? // 新新郎婚姻 ID？？
            p.writeInt(30000); // v20 = *(_DWORD *)(v13 + 2192) -- new bride marriage ID?? // 新新娘婚姻 ID？？
            p.writeString(guest.getName());
            p.writeString(guest.getGuildId() > 0 && guest.getGuild() != null ? guest.getGuild().getName() : "");
            p.writeShort(guest.getGuildId() > 0 && guest.getGuild() != null ? guest.getGuild().getLogoBG() : 0);
            p.writeByte(guest.getGuildId() > 0 && guest.getGuild() != null ? guest.getGuild().getLogoBGColor() : 0);
            p.writeShort(guest.getGuildId() > 0 && guest.getGuild() != null ? guest.getGuild().getLogo() : 0);
            p.writeByte(guest.getGuildId() > 0 && guest.getGuild() != null ? guest.getGuild().getLogoColor() : 0);
            p.writeShort(guest.getPosition().x); // v18 = *(_DWORD *)(v13 + 3204);
            p.writeShort(guest.getPosition().y); // v20 = *(_DWORD *)(v13 + 3208);
            // 开始截图编码
            p.writeByte(1); // // if ( *(_DWORD *)(v13 + 288) ) { COutPacket::Encode1(&thisa, v20);
            // CPet::EncodeScreenShotPacket(*(CPet **)(v13 + 288), &thisa);
            p.writeInt(1); // dwTemplateID // 模板 ID
            p.writeString(guest.getName()); // m_sName // 名字
            p.writeShort(guest.getPosition().x); // m_ptCurPos.x // 当前位置 X
            p.writeShort(guest.getPosition().y); // m_ptCurPos.y // 当前位置 Y
            p.writeByte(guest.getStance()); // guest.m_bMoveAction // 姿态
        }

        return p;
    }

    /**
     * 启用配偶聊天和他们的订婚戒指，无需 @relog
     *
     * @param marriageId 婚姻ID
     * @param chr        角色对象
     * @param wedding    是否为婚礼
     * @return mplew
     */
    public static Packet OnMarriageResult(int mode, Character chr, boolean success) {
        OutPacket p = OutPacket.create(SendOpcode.MARRIAGE_RESULT);
        p.writeByte(11);
        p.writeInt(mode);
        p.writeInt(chr.getGender() == 0 ? chr.getId() : chr.getPartnerId());
        p.writeInt(chr.getGender() == 0 ? chr.getPartnerId() : chr.getId());
        p.writeShort(success ? 3 : 1);
        if (success) {
            p.writeInt(chr.getMarriageItemId());
            p.writeInt(chr.getMarriageItemId());
        } else {
            p.writeInt(ItemId.WEDDING_RING_MOONSTONE); // 订婚戒指的结果（对于订婚来说并不重要）
            p.writeInt(ItemId.WEDDING_RING_MOONSTONE); // 订婚戒指的结果（对于订婚来说并不重要）
        }
        p.writeFixedString(StringUtil.getRightPaddedStr(chr.getGender() == 0 ? chr.getName() : Character.getNameById(chr.getPartnerId()), '\0', 13));
        p.writeFixedString(StringUtil.getRightPaddedStr(chr.getGender() == 0 ? Character.getNameById(chr.getPartnerId()) : chr.getName(), '\0', 13));

        return p;
    }

    /**
     * 退出订婚窗口（等待她的回应...），我们发送一个类似 GMS 的弹出窗口。
     *
     * @param msg 消息代码
     * @return mplew
     */
    public static Packet OnMarriageResult(final byte msg) {
        OutPacket p = OutPacket.create(SendOpcode.MARRIAGE_RESULT);
        p.writeByte(msg);
        if (msg == 36) {
            p.writeByte(1);
            p.writeString("You are now engaged.");
        }
        return p;
    }

    /**
     * 世界地图包含 'loverPos'，此包控制该位置
     *
     * @param partner 伴侣ID
     * @param mapid   地图ID
     * @return mplew
     */
    public static Packet OnNotifyWeddingPartnerTransfer(int partner, int mapid) {
        OutPacket p = OutPacket.create(SendOpcode.NOTIFY_MARRIED_PARTNER_MAP_TRANSFER);
        p.writeInt(mapid);
        p.writeInt(partner);
        return p;
    }

    /**
     * 婚礼包，用于显示 Pelvis Bebop 并启用两个角色之间的婚礼仪式效果
     * CField_Wedding::OnWeddingProgress - 阶段
     * CField_Wedding::OnWeddingCeremonyEnd - 婚礼仪式效果
     *
     * @param setBlessEffect 是否设置祝福效果
     * @param groom          新郎ID
     * @param bride          新娘ID
     * @param step           步骤
     * @return mplew
     */
    public static Packet OnWeddingProgress(boolean setBlessEffect, int groom, int bride, byte step) {
        OutPacket p = OutPacket.create(setBlessEffect ? SendOpcode.WEDDING_CEREMONY_END : SendOpcode.WEDDING_PROGRESS);
        if (!setBlessEffect) { // 为了发送仪式包，必须先发送 byte step = 2
            p.writeByte(step);
        }
        p.writeInt(groom);
        p.writeInt(bride);
        return p;
    }

    /**
     * 当我们打开婚礼请柬时，显示新郎和新娘
     *
     * @param groom 新郎名字
     * @param bride 新娘名字
     * @return mplew
     */
    public static Packet sendWeddingInvitation(String groom, String bride) {
        OutPacket p = OutPacket.create(SendOpcode.MARRIAGE_RESULT);
        p.writeByte(15);
        p.writeString(groom);
        p.writeString(bride);
        p.writeShort(1); // 0 = Cathedral Normal?, 1 = Cathedral Premium?, 2 = Chapel Normal? // 0 = 大教堂普通？，1 = 大教堂高级？，2 = 教堂普通？
        return p;
    }

    public static Packet sendWishList() { // fuck my life // 操蛋的生活
        OutPacket p = OutPacket.create(SendOpcode.MARRIAGE_REQUEST);
        p.writeByte(9);
        return p;
    }

    /**
     * 处理所有婚礼愿望清单数据包
     *
     * @param mode      模式
     * @param itemnames 物品名称列表
     * @param items     物品列表
     * @return mplew
     */
    public static Packet onWeddingGiftResult(byte mode, List<String> itemnames, List<Item> items) {
        OutPacket p = OutPacket.create(SendOpcode.WEDDING_GIFT_RESULT);
        p.writeByte(mode);
        switch (mode) {
            case 0xC: // 12 : 每个愿望清单只能赠送一份礼物
            case 0xE: // 14 : 发送礼物失败。
                break;

            case 0x09: { // 加载婚礼登记
                p.writeByte(itemnames.size());
                for (String names : itemnames) {
                    p.writeString(names);
                }
                break;
            }
            case 0xA: // 加载新娘的愿望清单
            case 0xF: // 10, 15, 16 = CWishListRecvDlg::OnPacket
            case 0xB: { // 添加物品到婚礼登记
                // 11 : 您已发送礼物 | | 13 : 发送礼物失败。 |
                if (mode == 0xB) {
                    p.writeByte(itemnames.size());
                    for (String names : itemnames) {
                        p.writeString(names);
                    }
                }
                p.writeLong(32);
                p.writeByte(items.size());
                for (Item item : items) {
                    addItemInfo(p, item, true);
                }
                break;
            }
            default: {
                log.warn("Unknown Wishlist Mode: {}", mode);
                break;
            }
        }
        return p;
    }
}
