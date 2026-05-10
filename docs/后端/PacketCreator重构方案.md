# PacketCreator 重构方案

## 1. 概述

`PacketCreator.java` 文件目前包含超过 7000 行代码，维护困难。本方案旨在通过**外观模式 (Facade Pattern)** 将其拆分为多个功能单一的小类，同时保留 `PacketCreator` 作为统一入口，确保不破坏现有代码的调用。

**当前状态**：重构已完成。所有方法已迁移至 `org.gms.util.packets` 包下的各个分类类中，`PacketCreator` 已重写为代理类。

## 2. 目录结构

`org.gms.util` 包下创建了 `packets` 子包，用于存放拆分后的类。

```
org/gms/util/
├── PacketCreator.java  (保留作为入口类，负责转发调用)
└── packets/            (新目录)
    ├── PacketHelper.java     (公共辅助方法，如写时间、写角色信息等)
    ├── LoginPackets.java     (登录、服务器列表相关)
    ├── FieldPackets.java     (地图、移动、特效相关)
    ├── NpcPackets.java       (NPC 对话、商店相关)
    ├── InventoryPackets.java (背包、道具、卷轴相关)
    ├── SocialPackets.java    (聊天、好友、组队、家族、公会相关)
    ├── CashShopPackets.java  (商城相关)
    ├── MiniGamePackets.java  (小游戏、雇佣商人相关)
    ├── MobPackets.java       (怪物相关)
    ├── PetPackets.java       (宠物相关)
    ├── AdminPackets.java     (GM 命令、管理相关)
    ├── WeddingPackets.java   (婚礼相关)
    └── MiscPackets.java      (杂项、未分类相关)
```

## 3. 重构原则与要求

1.  **完整性**：必须从旧版本代码里分析并整合 import，提取所有需要拆分的方法，避免遗漏。
2.  **逐步迁移**：采用按照单个文件逐步迁移和修改 `PacketCreator.java` 里对应的代码。
3.  **文档同步**：每次修改完成后更新到开发文档进度里。
4.  **中文注释**：每个方法都需要添加中文 JAVADOC 注解，如果有英文注释，需要翻译为中文。
5.  **分类管理**：所有方法必须按功能分类到表格里。

## 4. 拆分策略

### 4.1 公共辅助类 (PacketHelper.java)

包含被多个模块调用的底层方法。这些方法原先是 `private`，现在需要改为 `public` 以便其他包访问。

**包含方法：**
- `getTime(long utcTimestamp)`
- `addCharStats(OutPacket p, Character chr)`
- `addCharLook(OutPacket p, Character chr, boolean mega)`
- `addInventoryInfo(OutPacket p, Character chr)`
- `addSkillInfo(OutPacket p, Character chr)`
- `addQuestInfo(OutPacket p, Character chr)`
- `addItemInfo(OutPacket p, Item item, boolean zeroPosition)`
- `addExpirationTime(OutPacket p, long time)`
- ... 以及其他 `add` 开头的私有辅助方法。

### 4.2 业务分类

| 新类名 | 包含功能 | 示例方法 |
| :--- | :--- | :--- |
| **LoginPackets** | 登录流程、服务器列表、选角 | `getHello`, `getLoginFailed`, `getServerList`, `getCharList` |
| **FieldPackets** | 地图切换、传送门、天气、环境变化 | `getWarpToMap`, `spawnPortal`, `environmentChange`, `showEffect` |
| **NpcPackets** | NPC 生成、对话、商店 | `spawnNPC`, `getNPCTalk`, `getNPCShop` |
| **InventoryPackets** | 背包操作、捡取物品、丢弃物品 | `modifyInventory`, `getShowItemGain`, `dropItemFromMapObject` |
| **SocialPackets** | 聊天、组队、家族、公会、结婚 | `getChatText`, `partyStatusMessage`, `getFamilyInfo`, `guildInfo` |
| **CashShopPackets** | 商城操作、礼物、扩充栏位 | `openCashShop`, `showCashInventory`, `showBoughtCashItem` |
| **MiniGamePackets** | 小游戏、雇佣商人、玩家商店 | `getMiniGame`, `hiredMerchantBox`, `getPlayerShop` |
| **MobPackets** | 怪物生成、移动、伤害、血量显示 | `spawnMonster`, `moveMonster`, `damageMonster`, `showBossHP` |
| **PetPackets** | 宠物生成、移动、对话 | `showPet`, `movePet`, `petChat` |
| **AdminPackets** | GM 警告、封禁、测试包 | `getGMEffect`, `getPermBan`, `sendPolice` |
| **WeddingPackets** | 婚礼相关 | `OnNotifyWeddingPartnerTransfer`, `onWeddingGiftResult`, `sendWishList` |
| **MiscPackets** | 杂项、未分类 | `enableTV`, `updatePlayerStats`, `giveBuff` |

## 5. 进度记录

| 步骤 | 任务描述 | 状态 | 备注 |
| :--- | :--- | :--- | :--- |
| 1 | 分析旧代码，提取 Import 和方法列表 | **完成** | |
| 2 | 创建 `PacketHelper` 并迁移辅助方法 | **完成** | |
| 3 | 创建 `LoginPackets` 并迁移相关方法 | **完成** | |
| 4 | 创建 `FieldPackets` 并迁移相关方法 | **完成** | |
| 5 | 创建 `NpcPackets` 并迁移相关方法 | **完成** | |
| 6 | 创建 `InventoryPackets` 并迁移相关方法 | **完成** | |
| 7 | 创建 `SocialPackets` 并迁移相关方法 | **完成** | |
| 8 | 创建 `CashShopPackets` 并迁移相关方法 | **完成** | |
| 9 | 创建 `MiniGamePackets` 并迁移相关方法 | **完成** | |
| 10 | 创建 `MobPackets` 并迁移相关方法 | **完成** | |
| 11 | 创建 `PetPackets` 并迁移相关方法 | **完成** | |
| 12 | 创建 `AdminPackets` 并迁移相关方法 | **完成** | |
| 13 | 创建 `WeddingPackets` 并迁移相关方法 | **完成** | |
| 14 | 创建 `MiscPackets` 并迁移剩余方法 | **完成** | |
| 15 | 清理 `PacketCreator` 并完成重构 | **完成** | |

## 6. 待迁移方法列表 (分析中)

*(已全部迁移)*

## 7. 旧方法列表及新位置映射

| 方法 | 迁移位置 |
| :--- | :--- |
| `long getTime(long utcTimestamp)` | [PacketHelper.java:40](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void writeMobSkillId(OutPacket packet, MobSkillId msId)` | [PacketHelper.java:52](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet showHpHealed(int cid, int amount)` | [PacketHelper.java:57](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addRemainingSkillInfo(final OutPacket p, Character chr)` | [PacketHelper.java:65](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addCharStats(OutPacket p, Character chr)` | [PacketHelper.java:81](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addCharLook(final OutPacket p, Character chr, boolean mega)` | [PacketHelper.java:121](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addCharacterInfo(OutPacket p, Character chr)` | [PacketHelper.java:130](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addNewYearInfo(OutPacket p, Character chr)` | [PacketHelper.java:155](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addTeleportInfo(OutPacket p, Character chr)` | [PacketHelper.java:164](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addMiniGameInfo(OutPacket p, Character chr)` | [PacketHelper.java:174](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addAreaInfo(OutPacket p, Character chr)` | [PacketHelper.java:178](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addCharEquips(final OutPacket p, Character chr)` | [PacketHelper.java:186](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet setExtraPendantSlot(boolean toggleExtraSlot)` | [InventoryPackets.java:327](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `void addCharEntry(OutPacket p, Character chr, boolean viewall)` | [PacketHelper.java:222](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addQuestInfo(OutPacket p, Character chr)` | [PacketHelper.java:237](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addExpirationTime(final OutPacket p, long time)` | [PacketHelper.java:265](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addItemInfo(OutPacket p, Item item)` | [PacketHelper.java:269](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addItemInfo(final OutPacket p, Item item, boolean zeroPosition)` | [PacketHelper.java:273](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addInventoryInfo(OutPacket p, Character chr)` | [PacketHelper.java:365](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addSkillInfo(OutPacket p, Character chr)` | [PacketHelper.java:405](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addMonsterBookInfo(OutPacket p, Character chr)` | [PacketHelper.java:431](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet sendGuestTOS()` | [LoginPackets.java:227](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet getHello(short mapleVersion, InitializationVector sendIv, InitializationVector recvIv)` | [LoginPackets.java:24](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet getPing()` | [LoginPackets.java:40](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet getLoginFailed(int reason)` | [LoginPackets.java:68](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet getAfterLoginError(int reason)` | [LoginPackets.java:102](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet sendPolice()` | [AdminPackets.java:45](../src/main/java/org/gms/util/packets/AdminPackets.java) |
| `Packet sendPolice(String text)` | [AdminPackets.java:50](../src/main/java/org/gms/util/packets/AdminPackets.java) |
| `Packet getPermBan(byte reason)` | [AdminPackets.java:29](../src/main/java/org/gms/util/packets/AdminPackets.java) |
| `Packet getTempBan(long timestampTill, byte reason)` | [AdminPackets.java:38](../src/main/java/org/gms/util/packets/AdminPackets.java) |
| `Packet getAuthSuccess(Client c)` | [LoginPackets.java:112](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet pinOperation(byte mode)` | [LoginPackets.java:145](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet pinRegistered()` | [LoginPackets.java:151](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet requestPin()` | [LoginPackets.java:156](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet requestPinAfterFailure()` | [LoginPackets.java:160](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet registerPin()` | [LoginPackets.java:164](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet pinAccepted()` | [LoginPackets.java:168](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet wrongPic()` | [LoginPackets.java:172](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet getServerList(int serverId, String serverName, int flag, String eventmsg, List<Channel> channelLoad)` | [LoginPackets.java:187](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet getEndOfServerList()` | [LoginPackets.java:211](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet getServerStatus(int status)` | [LoginPackets.java:226](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet getServerIP(InetAddress inetAddr, int port, int clientId)` | [LoginPackets.java:239](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet getChannelChange(InetAddress inetAddr, int port)` | [LoginPackets.java:255](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet getCharList(Client c, int serverId, int status)` | [LoginPackets.java:271](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet enableTV()` | [MiscPackets.java:28](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet removeTV()` | [MiscPackets.java:34](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet sendTV(Character chr, List<String> messages, int type, Character partner)` | [MiscPackets.java:38](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet getCharInfo(Character chr)` | [MiscPackets.java:103](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet enableActions()` | [MiscPackets.java:61](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet updatePlayerStats(List<Pair<Stat, Integer>> stats, boolean enableActions, Character chr)` | [MiscPackets.java:65](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet getWarpToMap(MapleMap to, int spawnPoint, Character chr)` | [FieldPackets.java:39](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet getWarpToMap(MapleMap to, int spawnPoint, Point spawnPosition, Character chr)` | [FieldPackets.java:56](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet spawnPortal(int townId, int targetId, Point pos)` | [FieldPackets.java:76](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet spawnDoor(int ownerid, Point pos, boolean launched)` | [FieldPackets.java:89](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet removeDoor(int ownerId, boolean town)` | [FieldPackets.java:102](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet spawnSummon(Summon summon, boolean animated)` | [FieldPackets.java:120](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet removeSummon(Summon summon, boolean animated)` | [FieldPackets.java:139](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet spawnKite(int objId, int itemId, String name, String msg, Point pos, int ft)` | [FieldPackets.java:147](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet removeKite(int objId, int animationType)` | [FieldPackets.java:157](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet sendCannotSpawnKite()` | [FieldPackets.java:163](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet getRelogResponse()` | [LoginPackets.java:216](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet serverMessage(String message)` | [SocialPackets.java:62](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet serverNotice(int type, String message)` | [SocialPackets.java:66](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet serverNotice(int type, String message, int npc)` | [SocialPackets.java:70](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet serverNotice(int type, int channel, String message)` | [SocialPackets.java:74](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet serverNotice(int type, int channel, String message, boolean smegaEar)` | [SocialPackets.java:78](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet serverMessage(int type, int channel, String message, boolean servermessage, boolean megaEar, int npc)` | [SocialPackets.java:82](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet getAvatarMega(Character chr, String medal, int channel, int itemId, List<String> message, boolean ear)` | [SocialPackets.java:99](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet byeAvatarMega()` | [SocialPackets.java:112](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet gachaponMessage(Item item, String town, Character player)` | [MiscPackets.java:357](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet spawnNPC(NPC life)` | [NpcPackets.java:25](../src/main/java/org/gms/util/packets/NpcPackets.java) |
| `Packet spawnNPCRequestController(NPC life, boolean miniMap)` | [NpcPackets.java:43](../src/main/java/org/gms/util/packets/NpcPackets.java) |
| `Packet spawnMonster(Monster life, boolean newSpawn)` | [MobPackets.java:23](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet spawnMonster(Monster life, boolean newSpawn, int effect)` | [MobPackets.java:34](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet controlMonster(Monster life, boolean newSpawn, boolean aggro)` | [MobPackets.java:45](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet removeMonsterInvisibility(Monster life)` | [MobPackets.java:142](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet makeMonsterInvisible(Monster life)` | [MobPackets.java:148](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `void encodeParentlessMobSpawnEffect(OutPacket p, boolean newSpawn, int effect)` | [PacketHelper.java:655](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void encodeTemporary(OutPacket p, Map<MonsterStatus, MonsterStatusEffect> stati)` | [PacketHelper.java:667](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet spawnMonsterInternal(Monster life, boolean requestController, boolean newSpawn, boolean aggro, int effect, boolean makeInvis)` | [MobPackets.java:66](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet spawnFakeMonster(Monster life, int effect)` | [MobPackets.java:109](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet makeMonsterReal(Monster life)` | [MobPackets.java:127](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet stopControllingMonster(int oid)` | [MobPackets.java:54](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet moveMonsterResponse(int objectid, short moveid, int currentMp, boolean useSkills)` | [MobPackets.java:164](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet moveMonsterResponse(int objectid, short moveid, int currentMp, boolean useSkills, int skillId, int skillLevel)` | [MobPackets.java:168](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet getChatText(int cidfrom, String text, boolean gm, int show)` | [SocialPackets.java:29](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet getShowExpGain(int gain, int equip, int party, boolean inChat, boolean white)` | [PacketHelper.java:806](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet getShowFameGain(int gain)` | [PacketHelper.java:840](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet getShowMesoGain(int gain)` | [PacketHelper.java:846](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet getShowMesoGain(int gain, boolean inChat)` | [PacketHelper.java:850](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet getShowItemGain(int itemId, short quantity)` | [InventoryPackets.java:306](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet getShowItemGain(int itemId, short quantity, boolean inChat)` | [InventoryPackets.java:317](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet killMonster(int objId, boolean animation)` | [MobPackets.java:178](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet killMonster(int objId, int animation)` | [MobPackets.java:182](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet updateMapItemObject(MapItem drop, boolean giveOwnership)` | [InventoryPackets.java:289](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet dropItemFromMapObject(Character player, MapItem drop, Point dropfrom, Point dropto, byte mod)` | [InventoryPackets.java:268](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `void writeForeignBuffs(OutPacket p, Character chr)` | [PacketHelper.java:442](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet spawnPlayerMapObject(Client target, Character chr, boolean enteringField)` | [FieldPackets.java:483](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `void encodeNewYearCardInfo(OutPacket p, Character chr)` | [PacketHelper.java:508](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet onNewYearCardRes(Character user, int cardId, int mode, int msg)` | [MiscPackets.java:342](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet onNewYearCardRes(Character user, NewYearCardRecord newyear, int mode, int msg)` | [PacketHelper.java:762](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void encodeNewYearCard(NewYearCardRecord newyear, OutPacket p)` | [PacketHelper.java:520](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addRingLook(final OutPacket p, Character chr, boolean crush)` | [PacketHelper.java:533](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addMarriageRingLook(Client target, final OutPacket p, Character chr)` | [PacketHelper.java:555](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addAnnounceBox(final OutPacket p, PlayerShop shop, int availability)` | [PacketHelper.java:578](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addAnnounceBox(final OutPacket p, MiniGame game, int ammount, int joinable)` | [PacketHelper.java:589](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void updateHiredMerchantBoxInfo(OutPacket p, HiredMerchant hm)` | [PacketHelper.java:599](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet updateHiredMerchantBox(HiredMerchant hm)` | [MiniGamePackets.java:438](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `void updatePlayerShopBoxInfo(OutPacket p, PlayerShop shop)` | [PacketHelper.java:609](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet updatePlayerShopBox(PlayerShop shop)` | [MiniGamePackets.java:283](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet removePlayerShopBox(PlayerShop shop)` | [MiniGamePackets.java:289](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet facialExpression(Character from, int expression)` | [FieldPackets.java:457](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `void rebroadcastMovementList(OutPacket op, InPacket ip, long movementDataLength)` | [PacketHelper.java:621](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void serializeMovementList(OutPacket p, List<LifeMovementFragment> moves)` | [PacketHelper.java:627](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet movePlayer(int chrId, InPacket movementPacket, long movementDataLength)` | [FieldPackets.java:385](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet moveSummon(int cid, int oid, Point startPos, InPacket movementPacket, long movementDataLength)` | [FieldPackets.java:392](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet moveMonster(int oid, boolean skillPossible, int skill, int skillId, int skillLevel, int pOption, Point startPos, InPacket movementPacket, long movementDataLength)` | [MobPackets.java:152](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet summonAttack(int cid, int summonOid, byte direction, List<SummonAttackEntry> allDamage)` | [FieldPackets.java:400](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet closeRangeAttack(Character chr, int skill, int skilllevel, int stance, int numAttackedAndDamage, Map<Integer, List<Integer>> damage, int speed, int direction, int display)` | [FieldPackets.java:424](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet rangedAttack(Character chr, int skill, int skilllevel, int stance, int numAttackedAndDamage, int projectile, Map<Integer, List<Integer>> damage, int speed, int direction, int display)` | [FieldPackets.java:429](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet magicAttack(Character chr, int skill, int skilllevel, int stance, int numAttackedAndDamage, Map<Integer, List<Integer>> damage, int charge, int speed, int direction, int display)` | [FieldPackets.java:435](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `void addAttackBody(OutPacket p, Character chr, int skill, int skilllevel, int stance, int numAttackedAndDamage, int projectile, Map<Integer, List<Integer>> damage, int speed, int direction, int display)` | [PacketHelper.java:634](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet throwGrenade(int cid, Point pos, int keyDown, int skillId, int skillLevel)` | [FieldPackets.java:443](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `int doubleToShortBits(double d)` | [PacketHelper.java:659](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet getNPCShop(Client c, int sid, List<ShopItem> items)` | [NpcPackets.java:166](../src/main/java/org/gms/util/packets/NpcPackets.java) |
| `Packet shopTransaction(byte code)` | [NpcPackets.java:196](../src/main/java/org/gms/util/packets/NpcPackets.java) |
| `Packet updateInventorySlotLimit(int type, int newLimit)` | [InventoryPackets.java:56](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet modifyInventory(boolean updateTick, final List<ModifyInventory> mods)` | [InventoryPackets.java:22](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet getScrollEffect(int chr, ScrollResult scrollSuccess, boolean legendarySpirit, boolean whiteScroll)` | [InventoryPackets.java:83](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet removePlayerFromMap(int chrId)` | [FieldPackets.java:557](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet catchMessage(int message)` | [MobPackets.java:248](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet showAllCharacter(int totalWorlds, int totalChrs)` | [LoginPackets.java:286](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet showAriantScoreBoard()` | [MiscPackets.java:429](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet updateAriantPQRanking(final Character chr, final int score)` | [MiscPackets.java:433](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet updateAriantPQRanking(Map<Character, Integer> playerScore)` | [MiscPackets.java:439](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet updateWitchTowerScore(int score)` | [MiscPackets.java:447](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet silentRemoveItemFromMap(int objId)` | [InventoryPackets.java:232](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet removeItemFromMap(int objId, int animation, int chrId)` | [InventoryPackets.java:244](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet removeItemFromMap(int objId, int animation, int chrId, boolean pet, int slot)` | [InventoryPackets.java:259](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet updateCharLook(Client target, Character chr)` | [FieldPackets.java:562](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet damagePlayer(int skill, int monsteridfrom, int cid, int damage, int fake, int direction, boolean pgmr, int pgmr_1, boolean is_pg, int oid, int pos_x, int pos_y)` | [FieldPackets.java:452](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet sendMapleLifeCharacterInfo()` | [LoginPackets.java:323](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet sendMapleLifeNameError()` | [LoginPackets.java:328](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet sendMapleLifeError(int code)` | [LoginPackets.java:335](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet charNameResponse(String charname, boolean nameUsed)` | [LoginPackets.java:316](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet addNewCharEntry(Character chr)` | [LoginPackets.java:299](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet deleteCharResponse(int cid, int state)` | [LoginPackets.java:305](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet selectWorld(int world)` | [LoginPackets.java:280](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet sendRecommended(List<Pair<Integer, String>> worlds)` | [LoginPackets.java:235](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet charInfo(Character chr)` | [MiscPackets.java:115](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet giveBuff(int buffid, int bufflength, List<Pair<BuffStat, Integer>> statups)` | [MiscPackets.java:153](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet showMonsterRiding(int cid, Mount mount)` | [MiscPackets.java:308](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet forfeitQuest(short quest)` | [MiscPackets.java:502](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet completeQuest(short quest, long time)` | [MiscPackets.java:509](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet updateQuestInfo(short quest, int npc)` | [MiscPackets.java:480](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet onNotifyHPDecByField(int change)` | [MiscPackets.java:521](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet addQuestTimeLimit(final short quest, final int time)` | [MiscPackets.java:494](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet removeQuestTimeLimit(final short quest)` | [MiscPackets.java:498](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet updateQuest(Character chr, QuestStatus qs, boolean infoUpdate)` | [MiscPackets.java:466](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `void writeLongMaskD(final OutPacket p, List<Pair<Disease, Integer>> statups)` | [PacketHelper.java:663](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet giveDebuff(List<Pair<Disease, Integer>> statups, MobSkill skill)` | [MiscPackets.java:189](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet giveForeignDebuff(int chrId, List<Pair<Disease, Integer>> statups, MobSkill skill)` | [MiscPackets.java:201](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet cancelForeignFirstDebuff(int cid, long mask)` | [MiscPackets.java:221](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet cancelForeignDebuff(int cid, long mask)` | [MiscPackets.java:214](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet giveForeignBuff(int chrId, List<Pair<BuffStat, Integer>> statups)` | [MiscPackets.java:171](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet cancelForeignBuff(int chrId, List<BuffStat> statups)` | [MiscPackets.java:189](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet cancelBuff(List<BuffStat> statups)` | [MiscPackets.java:182](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `void writeLongMask(final OutPacket p, List<Pair<BuffStat, Integer>> statups)` | [PacketHelper.java:676](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void writeLongMaskFromList(OutPacket p, List<BuffStat> statups)` | [PacketHelper.java:688](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void writeLongEncodeTemporaryMask(final OutPacket p, Collection<MonsterStatus> stati)` | [PacketHelper.java:700](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet cancelDebuff(long mask)` | [MiscPackets.java:207](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `void writeLongMaskSlowD(final OutPacket p)` | [PacketHelper.java:713](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet giveForeignSlowDebuff(int chrId, List<Pair<Disease, Integer>> statups, MobSkill skill)` | [MiscPackets.java:228](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet cancelForeignSlowDebuff(int chrId)` | [MiscPackets.java:240](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `void writeLongMaskChair(OutPacket p)` | [PacketHelper.java:719](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet giveForeignChairSkillEffect(int cid)` | [FieldPackets.java:470](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet giveForeignWKChargeEffect(int cid, int buffid, List<Pair<BuffStat, Integer>> statups)` | [MiscPackets.java:246](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet cancelForeignChairSkillEffect(int chrId)` | [FieldPackets.java:486](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet getPlayerShopChat(Character chr, String chat, boolean owner)` | [MiniGamePackets.java:232](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getPlayerShopNewVisitor(Character chr, int slot)` | [MiniGamePackets.java:248](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getPlayerShopRemoveVisitor(int slot)` | [MiniGamePackets.java:256](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getTradePartnerAdd(Character chr)` | [MiniGamePackets.java:312](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet tradeInvite(Character chr)` | [MiniGamePackets.java:320](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getTradeMesoSet(byte number, int meso)` | [MiniGamePackets.java:329](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getTradeItemAdd(byte number, Item item)` | [MiniGamePackets.java:336](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getPlayerShopItemUpdate(PlayerShop shop)` | [MiniGamePackets.java:264](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getPlayerShopOwnerUpdate(PlayerShop.SoldItem item, int position)` | [MiniGamePackets.java:275](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getPlayerShop(PlayerShop shop, boolean owner)` | [MiniGamePackets.java:197](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getTradeStart(Client c, Trade trade, byte number)` | [MiniGamePackets.java:295](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getTradeConfirmation()` | [MiniGamePackets.java:308](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getTradeResult(byte number, byte operation)` | [MiniGamePackets.java:308](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getNPCTalk(int npc, byte msgType, String talk, String endBytes, byte speaker)` | [NpcPackets.java:65](../src/main/java/org/gms/util/packets/NpcPackets.java) |
| `Packet getDimensionalMirror(String talk)` | [NpcPackets.java:76](../src/main/java/org/gms/util/packets/NpcPackets.java) |
| `Packet getNPCTalkStyle(int npc, String talk, int[] styles)` | [NpcPackets.java:86](../src/main/java/org/gms/util/packets/NpcPackets.java) |
| `Packet getNPCTalkNum(int npc, String talk, int def, int min, int max)` | [NpcPackets.java:99](../src/main/java/org/gms/util/packets/NpcPackets.java) |
| `Packet getNPCTalkText(int npc, String talk, String def)` | [NpcPackets.java:125](../src/main/java/org/gms/util/packets/NpcPackets.java) |
| `Packet getNPCTalkNum(int npc, String talk, int def, int min, int max,byte speaker)` | [NpcPackets.java:112](../src/main/java/org/gms/util/packets/NpcPackets.java) |
| `Packet getNPCTalkText(int npc, String talk, String def,byte speaker)` | [NpcPackets.java:136](../src/main/java/org/gms/util/packets/NpcPackets.java) |
| `Packet OnAskQuiz(int nSpeakerTypeID, int nSpeakerTemplateID, int nResCode, String sTitle, String sProblemText, String sHintText, int nMinInput, int nMaxInput, int tRemainInitialQuiz)` | [NpcPackets.java:147](../src/main/java/org/gms/util/packets/NpcPackets.java) |
| `Packet OnAskSpeedQuiz(int nSpeakerTypeID, int nSpeakerTemplateID, int nResCode, int nType, int dwAnswer, int nCorrect, int nRemain, int tRemainInitialQuiz)` | [NpcPackets.java:162](../src/main/java/org/gms/util/packets/NpcPackets.java) |
| `Packet showBuffEffect(int chrId, int skillId, int effectId)` | [FieldPackets.java:326](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet showBuffEffect(int chrId, int skillId, int effectId, byte direction)` | [FieldPackets.java:330](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet showBuffEffect(int chrId, int skillId, int skillLv, int effectId, byte direction)` | [FieldPackets.java:340](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet showOwnBuffEffect(int skillId, int effectId)` | [FieldPackets.java:350](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet showOwnBerserk(int skilllevel, boolean Berserk)` | [FieldPackets.java:358](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet showBerserk(int chrId, int skillLv, boolean berserk)` | [FieldPackets.java:367](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet updateSkill(int skillId, int level, int masterlevel, long expiration)` | [MiscPackets.java:269](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet getShowQuestCompletion(int id)` | [MiscPackets.java:516](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet getKeymap(Map<Integer, KeyBinding> keybindings)` | [MiscPackets.java:332](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet QuickslotMappedInit(QuickslotBinding pQuickslot)` | [MiscPackets.java:346](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet getInventoryFull()` | [InventoryPackets.java:62](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet getShowInventoryFull()` | [InventoryPackets.java:66](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet showItemUnavailable()` | [InventoryPackets.java:70](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet getShowInventoryStatus(int mode)` | [InventoryPackets.java:74](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet getStorage(int npcId, byte slots, Collection<Item> items, int meso)` | [InventoryPackets.java:104](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet getStorageError(byte i)` | [InventoryPackets.java:126](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet mesoStorage(byte slots, int meso)` | [InventoryPackets.java:131](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet storeStorage(byte slots, InventoryType type, Collection<Item> items)` | [InventoryPackets.java:141](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet takeOutStorage(byte slots, InventoryType type, Collection<Item> items)` | [InventoryPackets.java:153](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet arrangeStorage(byte slots, Collection<Item> items)` | [InventoryPackets.java:165](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet showMonsterHP(int oid, int remhppercentage)` | [MobPackets.java:198](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet showBossHP(int oid, int currHP, int maxHP, byte tagColor, byte tagBgColor)` | [MobPackets.java:204](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Pair<Integer, Integer> normalizedCustomMaxHP(long currHP, long maxHP)` | [PacketHelper.java:725](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet customShowBossHP(byte call, int oid, long currHP, long maxHP, byte tagColor, byte tagBgColor)` | [MobPackets.java:214](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet giveFameResponse(int mode, String charname, int newfame)` | [PacketHelper.java:819](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet giveFameErrorResponse(int status)` | [PacketHelper.java:780](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet receiveFame(int mode, String charnameFrom)` | [PacketHelper.java:829](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet partyCreated(Party party, int partycharid)` | [SocialPackets.java:126](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet partyInvite(Character from)` | [SocialPackets.java:149](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet partySearchInvite(Character from)` | [SocialPackets.java:158](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet partyStatusMessage(int message)` | [SocialPackets.java:178](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet partyStatusMessage(int message, String charname)` | [SocialPackets.java:189](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `void addPartyStatus(int forchannel, Party party, OutPacket p, boolean leaving)` | [PacketHelper.java:741](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet updateParty(int forChannel, Party party, PartyOperation op, PartyCharacter target)` | [SocialPackets.java:195](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet partyPortal(int townId, int targetId, Point position)` | [SocialPackets.java:233](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet updatePartyMemberHP(int cid, int curhp, int maxhp)` | [SocialPackets.java:241](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet multiChat(String name, String chattext, int mode)` | [SocialPackets.java:42](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `void writeIntMask(OutPacket p, Map<MonsterStatus, Integer> stats)` | [PacketHelper.java:725](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet applyMonsterStatus(final int oid, final MonsterStatusEffect mse, final List<Integer> reflection)` | [MobPackets.java:224](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet cancelMonsterStatus(int oid, Map<MonsterStatus, Integer> stats)` | [MobPackets.java:249](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet getClock(Number time)` | [FieldPackets.java:386](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet getClockTime(int hour, int min, int sec)` | [FieldPackets.java:392](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet removeClock()` | [FieldPackets.java:400](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet spawnMobMist(int objId, int ownerMobId, MobSkillId msId, Mist mist)` | [FieldPackets.java:167](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet spawnMist(int objId, int ownerId, int skill, int level, Mist mist)` | [FieldPackets.java:171](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet removeMist(int objId)` | [FieldPackets.java:183](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet damageSummon(int cid, int oid, int damage, int monsterIdFrom)` | [FieldPackets.java:410](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet damageMonster(int oid, int damage)` | [MobPackets.java:188](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet healMonster(int oid, int heal, int curhp, int maxhp)` | [MobPackets.java:192](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet damageMonster(int oid, int damage, int curhp, int maxhp)` | [MobPackets.java:196](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet updateBuddylist(Collection<BuddylistEntry> buddylist)` | [SocialPackets.java:248](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet buddylistMessage(byte message)` | [SocialPackets.java:266](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet requestBuddylistAdd(int chrIdFrom, int chrId, String nameFrom)` | [SocialPackets.java:272](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet updateBuddyChannel(int characterid, int channel)` | [SocialPackets.java:286](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet itemEffect(int characterid, int itemid)` | [InventoryPackets.java:189](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet updateBuddyCapacity(int capacity)` | [SocialPackets.java:294](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet showChair(int characterid, int itemid)` | [FieldPackets.java:463](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet cancelChair(int id)` | [FieldPackets.java:469](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet spawnReactor(Reactor reactor)` | [FieldPackets.java:188](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet triggerReactor(Reactor reactor, int stance)` | [FieldPackets.java:199](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet destroyReactor(Reactor reactor)` | [FieldPackets.java:210](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet musicChange(String song)` | [FieldPackets.java:218](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet showEffect(String effect)` | [FieldPackets.java:222](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet playSound(String sound)` | [FieldPackets.java:226](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet environmentChange(String env, int mode)` | [FieldPackets.java:230](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet environmentMove(String env, int mode)` | [FieldPackets.java:236](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet environmentMoveList(Set<Entry<String, Integer>> envList)` | [FieldPackets.java:242](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet environmentMoveReset()` | [FieldPackets.java:252](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet startMapEffect(String msg, int itemId, boolean active)` | [FieldPackets.java:256](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet removeMapEffect()` | [FieldPackets.java:265](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet mapEffect(String path)` | [FieldPackets.java:271](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet mapSound(String path)` | [FieldPackets.java:277](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet skillEffect(Character from, int skillId, int level, byte flags, int speed, byte direction)` | [FieldPackets.java:376](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet skillCancel(Character from, int skillId)` | [FieldPackets.java:387](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet catchMonster(int mobOid, byte success)` | [MobPackets.java:257](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet catchMonster(int mobOid, int itemid, byte success)` | [MobPackets.java:263](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet sendHint(String hint, int width, int height)` | [FieldPackets.java:586](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet messengerInvite(String from, int messengerid)` | [SocialPackets.java:368](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet OnCoupleMessage(String fiance, String text, boolean spouse)` | [SocialPackets.java:387](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet addMessengerPlayer(String from, Character chr, int position, int channel)` | [SocialPackets.java:397](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet removeMessengerPlayer(int position)` | [SocialPackets.java:408](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet updateMessengerPlayer(String from, Character chr, int position, int channel)` | [SocialPackets.java:414](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet joinMessenger(int position)` | [SocialPackets.java:425](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet messengerChat(String text)` | [SocialPackets.java:431](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet messengerNote(String text, int mode, int mode2)` | [SocialPackets.java:437](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `void addPetInfo(final OutPacket p, Pet pet, boolean showpet)` | [PacketHelper.java:543](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet showPet(Character chr, Pet pet, boolean remove, boolean hunger)` | [PetPackets.java:14](../src/main/java/org/gms/util/packets/PetPackets.java) |
| `Packet movePet(int cid, int pid, byte slot, List<LifeMovementFragment> moves)` | [PetPackets.java:26](../src/main/java/org/gms/util/packets/PetPackets.java) |
| `Packet petChat(int cid, byte index, int act, String text)` | [PetPackets.java:34](../src/main/java/org/gms/util/packets/PetPackets.java) |
| `Packet petFoodResponse(int cid, byte index, boolean success, boolean balloonType)` | [PetPackets.java:44](../src/main/java/org/gms/util/packets/PetPackets.java) |
| `Packet commandResponse(int cid, byte index, boolean talk, int animation, boolean balloonType)` | [PetPackets.java:53](../src/main/java/org/gms/util/packets/PetPackets.java) |
| `Packet showOwnPetLevelUp(byte index)` | [PetPackets.java:63](../src/main/java/org/gms/util/packets/PetPackets.java) |
| `Packet showPetLevelUp(Character chr, byte index)` | [PetPackets.java:70](../src/main/java/org/gms/util/packets/PetPackets.java) |
| `Packet changePetName(Character chr, String newname, int slot)` | [PetPackets.java:78](../src/main/java/org/gms/util/packets/PetPackets.java) |
| `Packet loadExceptionList(final int cid, final int petId, final byte petIdx, final List<Integer> data)` | [PetPackets.java:86](../src/main/java/org/gms/util/packets/PetPackets.java) |
| `Packet petStatUpdate(Character chr)` | [PetPackets.java:97](../src/main/java/org/gms/util/packets/PetPackets.java) |
| `Packet showForcedEquip(int team)` | [FieldPackets.java:577](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet summonSkill(int cid, int summonSkillId, int newStance)` | [FieldPackets.java:418](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet skillCooldown(int sid, int time)` | [MiscPackets.java:280](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet skillBookResult(Character chr, int skillid, int maxlevel, boolean canuse, boolean success)` | [MiscPackets.java:286](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet getMacros(SkillMacro[] macros)` | [MiscPackets.java:296](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet showAllCharacterInfo(int worldid, List<Character> chars, boolean usePic)` | [LoginPackets.java:293](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet updateMount(int charid, Mount mount, boolean levelup)` | [MiscPackets.java:313](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet crogBoatPacket(boolean type)` | [FieldPackets.java:571](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet boatPacket(boolean type)` | [FieldPackets.java:565](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet getMiniGame(Client c, MiniGame minigame, boolean owner, int piece)` | [MiniGamePackets.java:25](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getMiniGameReady(MiniGame game)` | [MiniGamePackets.java:62](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getMiniGameUnReady(MiniGame game)` | [MiniGamePackets.java:68](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getMiniGameStart(MiniGame game, int loser)` | [MiniGamePackets.java:74](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getMiniGameSkipOwner(MiniGame game)` | [MiniGamePackets.java:81](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getMiniGameRequestTie(MiniGame game)` | [MiniGamePackets.java:93](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getMiniGameDenyTie(MiniGame game)` | [MiniGamePackets.java:99](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getMiniRoomError(int status)` | [MiniGamePackets.java:217](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getMiniGameSkipVisitor(MiniGame game)` | [MiniGamePackets.java:87](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getMiniGameMoveOmok(MiniGame game, int move1, int move2, int move3)` | [MiniGamePackets.java:105](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getMiniGameNewVisitor(MiniGame minigame, Character chr, int slot)` | [MiniGamePackets.java:114](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getMiniGameRemoveVisitor()` | [MiniGamePackets.java:126](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getMiniGameResult(MiniGame game, int tie, int result, int forfeit)` | [MiniGamePackets.java:144](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getMiniGameOwnerWin(MiniGame game, boolean forfeit)` | [MiniGamePackets.java:132](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getMiniGameVisitorWin(MiniGame game, boolean forfeit)` | [MiniGamePackets.java:136](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getMiniGameTie(MiniGame game)` | [MiniGamePackets.java:140](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getMiniGameClose(boolean visitor, int type)` | [MiniGamePackets.java:177](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getMatchCard(Client c, MiniGame minigame, boolean owner, int piece)` | [MiniGamePackets.java:185](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getMatchCardStart(MiniGame game, int loser)` | [MiniGamePackets.java:222](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getMatchCardNewVisitor(MiniGame minigame, Character chr, int slot)` | [MiniGamePackets.java:239](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getMatchCardSelect(MiniGame game, int turn, int slot, int firstslot, int type)` | [MiniGamePackets.java:251](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet openRPSNPC()` | [MiniGamePackets.java:450](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet rpsMesoError(int mesos)` | [MiniGamePackets.java:456](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet rpsSelection(byte selection, byte answer)` | [MiniGamePackets.java:464](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet rpsMode(byte mode)` | [MiniGamePackets.java:471](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet fredrickMessage(byte operation)` | [MiniGamePackets.java:413](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getFredrick(byte op)` | [MiniGamePackets.java:419](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getFredrick(Character chr, List<HiredMerchantsDO> merchants)` | [MiniGamePackets.java:433](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet addOmokBox(Character chr, int amount, int type)` | [MiniGamePackets.java:224](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet addMatchCardBox(Character chr, int amount, int type)` | [MiniGamePackets.java:230](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet removeMinigameBox(Character chr)` | [MiniGamePackets.java:236](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getPlayerShopChat(Character chr, String chat, byte slot)` | [MiniGamePackets.java:240](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getTradeChat(Character chr, String chat, boolean owner)` | [MiniGamePackets.java:344](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet hiredMerchantBox()` | [MiniGamePackets.java:353](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getOwlMessage(int msg)` | [MiniGamePackets.java:477](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet owlOfMinerva(Client c, int itemId, List<Pair<PlayerShopItem, AbstractMapObject>> hmsAvailable)` | [MiniGamePackets.java:483](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getOwlOpen(List<Integer> owlLeaderboards)` | [MiniGamePackets.java:518](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet retrieveFirstMessage()` | [MiniGamePackets.java:527](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet remoteChannelChange(byte ch)` | [MiniGamePackets.java:533](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet getHiredMerchant(Character chr, HiredMerchant hm, boolean firstTime)` | [MiniGamePackets.java:358](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet updateHiredMerchant(HiredMerchant hm, Character chr)` | [MiniGamePackets.java:400](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet hiredMerchantChat(String message, byte slot)` | [MiniGamePackets.java:413](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet hiredMerchantVisitorLeave(int slot)` | [MiniGamePackets.java:422](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet hiredMerchantOwnerLeave()` | [MiniGamePackets.java:431](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet hiredMerchantOwnerMaintenanceLeave()` | [MiniGamePackets.java:437](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet hiredMerchantMaintenanceMessage()` | [MiniGamePackets.java:443](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet leaveHiredMerchant(int slot, int status2)` | [MiniGamePackets.java:450](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet viewMerchantVisitorHistory(List<HiredMerchant.PastVisitor> pastVisitors)` | [MiniGamePackets.java:458](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet viewMerchantBlacklist(Set<String> chrNames)` | [MiniGamePackets.java:468](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet hiredMerchantVisitorAdd(Character chr, int slot)` | [MiniGamePackets.java:477](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet spawnHiredMerchantBox(HiredMerchant hm)` | [MiniGamePackets.java:485](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet removeHiredMerchantBox(int id)` | [MiniGamePackets.java:498](../src/main/java/org/gms/util/packets/MiniGamePackets.java) |
| `Packet spawnPlayerNPC(PlayerNPC npc)` | [NpcPackets.java:203](../src/main/java/org/gms/util/packets/NpcPackets.java) |
| `Packet getPlayerNPC(PlayerNPC npc)` | [NpcPackets.java:216](../src/main/java/org/gms/util/packets/NpcPackets.java) |
| `Packet removePlayerNPC(int oid)` | [NpcPackets.java:256](../src/main/java/org/gms/util/packets/NpcPackets.java) |
| `Packet sendYellowTip(String tip)` | [MiscPackets.java:350](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet givePirateBuff(List<Pair<BuffStat, Integer>> statups, int buffid, int duration)` | [MiscPackets.java:257](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet giveForeignPirateBuff(int cid, int buffid, int time, List<Pair<BuffStat, Integer>> statups)` | [MiscPackets.java:270](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet sendMTS(List<MTSItemInfo> items, int tab, int type, int page, int pages)` | [CashShopPackets.java:286](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet noteError(byte error)` | [SocialPackets.java:452](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet useChalkboard(Character chr, boolean close)` | [MiscPackets.java:319](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet trockRefreshMapList(Character chr, boolean delete, boolean vip)` | [PacketHelper.java:770](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet sendWorldTransferRules(int error, Client c)` | [CashShopPackets.java:237](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet showWorldTransferSuccess(Item item, int accountId)` | [CashShopPackets.java:250](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet sendNameTransferRules(int error)` | [CashShopPackets.java:263](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet sendNameTransferCheck(String availableName, boolean canUseName)` | [CashShopPackets.java:274](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet showNameChangeSuccess(Item item, int accountId)` | [CashShopPackets.java:281](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet showNameChangeCancel(boolean success)` | [CashShopPackets.java:287](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet showWorldTransferCancel(boolean success)` | [CashShopPackets.java:256](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet showMTSCash(Character chr)` | [CashShopPackets.java:293](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet MTSWantedListingOver(int nx, int items)` | [CashShopPackets.java:300](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet MTSConfirmSell()` | [CashShopPackets.java:307](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet MTSConfirmBuy()` | [CashShopPackets.java:312](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet MTSFailBuy()` | [CashShopPackets.java:317](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet MTSConfirmTransfer(int quantity, int pos)` | [CashShopPackets.java:323](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet notYetSoldInv(List<MTSItemInfo> items)` | [CashShopPackets.java:330](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet transferInventory(List<MTSItemInfo> items)` | [CashShopPackets.java:349](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet showCouponRedeemedItems(int accountId, int maplePoints, int mesos, List<Item> cashItems, List<Pair<Integer, Integer>> items)` | [CashShopPackets.java:208](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet showCash(Character mc)` | [CashShopPackets.java:78](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet enableCSUse(Character mc)` | [CashShopPackets.java:85](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet getFindResult(Character target, byte type, int fieldOrChannel, byte flag)` | [SocialPackets.java:443](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet getWhisperResult(String target, boolean success)` | [SocialPackets.java:458](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet getWhisperReceive(String sender, int channel, boolean fromAdmin, String message)` | [SocialPackets.java:465](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet sendAutoHpPot(int itemId)` | [PacketHelper.java:790](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet sendAutoMpPot(int itemId)` | [PacketHelper.java:795](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet showOXQuiz(int questionSet, int questionId, boolean askQuestion)` | [PacketHelper.java:854](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet updateGender(Character chr)` | [LoginPackets.java:348](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet enableReport()` | [LoginPackets.java:342](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet giveFinalAttack(int skillid, int time)` | [MiscPackets.java:284](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet loadFamily(Character player)` | [SocialPackets.java:300](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet sendFamilyMessage(int type, int mesos)` | [SocialPackets.java:333](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet getFamilyInfo(FamilyEntry f)` | [SocialPackets.java:339](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet getEmptyFamilyInfo()` | [SocialPackets.java:358](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet showPedigree(FamilyEntry entry)` | [SocialPackets.java:371](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `void addPedigreeEntry(OutPacket p, FamilyEntry entry)` | [PacketHelper.java:640](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet updateAreaInfo(int area, String info)` | [MiscPackets.java:365](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet getGPMessage(int gpChange)` | [MiscPackets.java:373](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet getItemMessage(int itemid)` | [InventoryPackets.java:227](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet addCard(boolean full, int cardid, int level)` | [MiscPackets.java:379](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet showGainCard()` | [MiscPackets.java:386](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet showForeignCardEffect(int id)` | [MiscPackets.java:391](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet changeCover(int cardid)` | [MiscPackets.java:397](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet aranGodlyStats()` | [MiscPackets.java:357](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet showIntro(String path)` | [FieldPackets.java:527](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet showInfo(String path)` | [FieldPackets.java:520](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet showForeignInfo(int cid, String path)` | [FieldPackets.java:512](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet openUI(byte ui)` | [MiscPackets.java:328](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet lockUI(boolean enable)` | [MiscPackets.java:333](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet disableUI(boolean enable)` | [MiscPackets.java:338](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet itemMegaphone(String msg, boolean whisper, int channel, Item item)` | [SocialPackets.java:117](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet removeNPC(int objId)` | [NpcPackets.java:56](../src/main/java/org/gms/util/packets/NpcPackets.java) |
| `Packet removeNPCController(int objId)` | [NpcPackets.java:65](../src/main/java/org/gms/util/packets/NpcPackets.java) |
| `Packet reportResponse(byte mode)` | [LoginPackets.java:353](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet sendHammerData(int hammerUsed)` | [InventoryPackets.java:91](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet sendHammerMessage()` | [InventoryPackets.java:98](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet playPortalSound()` | [FieldPackets.java:293](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet showMonsterBookPickup()` | [FieldPackets.java:297](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet showEquipmentLevelUp()` | [FieldPackets.java:301](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet showItemLevelup()` | [FieldPackets.java:305](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet showSpecialEffect(int effect)` | [FieldPackets.java:288](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet showMakerEffect(boolean makerSucceeded)` | [MiscPackets.java:473](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet showForeignMakerEffect(int cid, boolean makerSucceeded)` | [MiscPackets.java:479](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet showForeignEffect(int effect)` | [FieldPackets.java:309](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet showForeignEffect(int chrId, int effect)` | [FieldPackets.java:313](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet showOwnRecovery(byte heal)` | [MiscPackets.java:492](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet showRecovery(int chrId, byte amount)` | [MiscPackets.java:485](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet showWheelsLeft(int left)` | [MiscPackets.java:498](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet updateQuestFinish(short quest, int npc, short nextquest)` | [MiscPackets.java:487](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet showInfoText(String text)` | [FieldPackets.java:534](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet questError(short quest)` | [MiscPackets.java:504](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet questFailure(byte type)` | [MiscPackets.java:510](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet questExpire(short quest)` | [MiscPackets.java:516](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet makerResult(boolean success, int itemMade, int itemCount, int mesos, List<Pair<Integer, Integer>> itemsLost, int catalystID, List<Integer> INCBuffGems)` | [MiscPackets.java:445](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet makerResultCrystal(int itemIdGained, int itemIdLost)` | [MiscPackets.java:467](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet makerResultDesynth(int itemId, int mesos, List<Pair<Integer, Integer>> itemsGained)` | [MiscPackets.java:475](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet makerEnableActions()` | [MiscPackets.java:487](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet getMultiMegaphone(String[] messages, int channel, boolean showEar)` | [SocialPackets.java:50](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet getGMEffect(int type, byte mode)` | [AdminPackets.java:23](../src/main/java/org/gms/util/packets/AdminPackets.java) |
| `Packet findMerchantResponse(boolean map, int extra)` | [AdminPackets.java:56](../src/main/java/org/gms/util/packets/AdminPackets.java) |
| `Packet disableMinimap()` | [AdminPackets.java:66](../src/main/java/org/gms/util/packets/AdminPackets.java) |
| `Packet sendFamilyInvite(int playerId, String inviter)` | [SocialPackets.java:423](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet sendFamilySummonRequest(String familyName, String from)` | [SocialPackets.java:429](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet sendFamilyLoginNotice(String name, boolean loggedIn)` | [SocialPackets.java:435](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet sendFamilyJoinResponse(boolean accepted, String added)` | [SocialPackets.java:441](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet getSeniorMessage(String name)` | [SocialPackets.java:447](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet sendGainRep(int gain, String from)` | [SocialPackets.java:453](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet showBoughtCashPackage(List<Item> cashPackage, int accountId)` | [CashShopPackets.java:110](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet showBoughtQuestItem(int itemId)` | [CashShopPackets.java:131](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet onCashItemGachaponOpenFailed()` | [CashShopPackets.java:221](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet onCashGachaponOpenSuccess(int accountid, long boxCashId, int remainingBoxes, Item reward, int rewardItemId, int rewardQuantity, boolean bJackpot)` | [CashShopPackets.java:226](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet sendMesoLimit()` | [LoginPackets.java:354](../src/main/java/org/gms/util/packets/LoginPackets.java) |
| `Packet removeItemFromDuey(boolean remove, int Package)` | [SocialPackets.java:488](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet sendDueyParcelReceived(String from, boolean quick)` | [SocialPackets.java:481](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet sendDueyParcelNotification(boolean quick)` | [SocialPackets.java:475](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet sendDueyMSG(byte operation)` | [SocialPackets.java:471](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet sendDuey(int operation, List<DueyPackage> packages)` | [SocialPackets.java:448](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet sendDojoAnimation(byte firstByte, String animation)` | [MiscPackets.java:417](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet getDojoInfo(String info)` | [MiscPackets.java:409](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet getDojoInfoMessage(String message)` | [MiscPackets.java:417](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet blockedMessage(int type)` | [FieldPackets.java:540](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet blockedMessage2(int type)` | [FieldPackets.java:553](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet updateDojoStats(Character chr, int belt)` | [MiscPackets.java:423](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet levelUpMessage(int type, int level, String charname)` | [SocialPackets.java:373](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet marriageMessage(int type, String charname)` | [SocialPackets.java:386](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet jobMessage(int type, int job, String charname)` | [SocialPackets.java:398](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet trembleEffect(int type, int delay)` | [FieldPackets.java:281](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet getEnergy(String info, int amount)` | [MiscPackets.java:435](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet dojoWarpUp()` | [MiscPackets.java:429](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet itemExpired(int itemid)` | [InventoryPackets.java:195](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `String getRightPaddedStr(String in, char padchar, int length)` | [PacketHelper.java:737](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet MobDamageMobFriendly(Monster mob, int damage, int remainingHp)` | [MobPackets.java:256](../src/main/java/org/gms/util/packets/MobPackets.java) |
| `Packet shopErrorMessage(int error, int type)` | [NpcPackets.java:201](../src/main/java/org/gms/util/packets/NpcPackets.java) |
| `void addRingInfo(OutPacket p, Character chr)` | [PacketHelper.java:745](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet finishedSort(int inv)` | [InventoryPackets.java:177](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet finishedSort2(int inv)` | [InventoryPackets.java:183](../src/main/java/org/gms/util/packets/InventoryPackets.java) |
| `Packet bunnyPacket()` | [MiscPackets.java:402](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet hpqMessage(String text)` | [MiscPackets.java:408](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet showEventInstructions()` | [MiscPackets.java:397](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet leftKnockBack()` | [PacketHelper.java:785](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet rollSnowBall(boolean entermap, int state, Snowball ball0, Snowball ball1)` | [MiscPackets.java:415](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet hitSnowBall(int what, int damage)` | [MiscPackets.java:428](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet snowballMessage(int team, int message)` | [MiscPackets.java:443](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet coconutScore(int team1, int team2)` | [MiscPackets.java:449](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet hitCoconut(boolean spawn, int id, int type)` | [MiscPackets.java:455](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet customPacket(String packet)` | [MiscPackets.java:526](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet customPacket(byte[] packet)` | [MiscPackets.java:531](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet spawnGuide(boolean spawn)` | [FieldPackets.java:405](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet talkGuide(String talk)` | [FieldPackets.java:410](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet guideHint(int hint)` | [FieldPackets.java:417](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `void addCashItemInformation(OutPacket p, Item item, int accountId)` | [PacketHelper.java:555](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `void addCashItemInformation(OutPacket p, Item item, int accountId, String giftMessage)` | [PacketHelper.java:559](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet showWishList(Character mc, boolean update)` | [CashShopPackets.java:194](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet showBoughtCashItem(Item item, int accountId)` | [CashShopPackets.java:98](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet showBoughtCashRing(Item ring, String recipient, int accountId)` | [CashShopPackets.java:122](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet showCashShopMessage(byte message)` | [CashShopPackets.java:188](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet showCashInventory(Client c)` | [CashShopPackets.java:89](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet showGifts(List<Pair<Item, String>> gifts)` | [CashShopPackets.java:157](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet showGiftSucceed(String to, ModifiedCashItemDO item)` | [CashShopPackets.java:147](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet showBoughtInventorySlots(int type, short slots)` | [CashShopPackets.java:139](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet showBoughtStorageSlots(short slots)` | [CashShopPackets.java:147](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet showBoughtCharacterSlot(short slots)` | [CashShopPackets.java:155](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet takeFromCashInventory(Item item)` | [CashShopPackets.java:167](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet deleteCashItem(Item item)` | [CashShopPackets.java:182](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet refundCashItem(Item item, int maplePoints)` | [CashShopPackets.java:188](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet putIntoCashInventory(Item item, int accountId)` | [CashShopPackets.java:175](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet openCashShop(Client c, boolean mts)` | [CashShopPackets.java:22](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `void writeModifiedCashItem(OutPacket p, ModifiedCashItemDO item)` | [PacketHelper.java:582](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet sendVegaScroll(int op)` | [PacketHelper.java:800](../src/main/java/org/gms/util/packets/PacketHelper.java) |
| `Packet resetForcedStats()` | [MiscPackets.java:353](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet showCombo(int count)` | [MiscPackets.java:349](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet earnTitleMessage(String msg)` | [MiscPackets.java:344](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet CPUpdate(boolean party, int curCP, int totalCP, int team)` | [MiscPackets.java:466](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet CPQMessage(byte message)` | [MiscPackets.java:476](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet playerSummoned(String name, int tab, int number)` | [MiscPackets.java:482](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet playerDiedMessage(String name, int lostCP, int team)` | [MiscPackets.java:489](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet startMonsterCarnival(Character chr, int team, int opposition)` | [MiscPackets.java:497](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet sheepRanchInfo(byte wolf, byte sheep)` | [MiscPackets.java:508](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet sheepRanchClothes(int id, byte clothes)` | [MiscPackets.java:515](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet incubatorResult()` | [MiscPackets.java:521](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet pyramidGauge(int gauge)` | [MiscPackets.java:526](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet pyramidScore(byte score, int exp)` | [MiscPackets.java:531](../src/main/java/org/gms/util/packets/MiscPackets.java) |
| `Packet spawnDragon(Dragon dragon)` | [FieldPackets.java:424](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet moveDragon(Dragon dragon, Point startPos, InPacket movementPacket, long movementDataLength)` | [FieldPackets.java:435](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet removeDragon(int chrId)` | [FieldPackets.java:442](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet changeBackgroundEffect(boolean remove, int layer, int transition)` | [FieldPackets.java:424](../src/main/java/org/gms/util/packets/FieldPackets.java) |
| `Packet setNPCScriptable(Map<Integer, String> scriptableNpcIds)` | [NpcPackets.java:261](../src/main/java/org/gms/util/packets/NpcPackets.java) |
| `Packet MassacreResult(byte nRank, int nIncExp)` | (未迁移) |
| `Packet Tournament__Tournament(byte nState, byte nSubState)` | (未迁移) |
| `Packet Tournament__MatchTable(byte nState, byte nSubState)` | (未迁移) |
| `Packet Tournament__SetPrize(byte bSetPrize, byte bHasPrize, int nItemID1, int nItemID2)` | (未迁移) |
| `Packet Tournament__UEW(byte nState)` | (未迁移) |
| `Packet familyBuff(int type, int buffnr, int amount, int time)` | [SocialPackets.java:459](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet cancelFamilyBuff()` | [SocialPackets.java:470](../src/main/java/org/gms/util/packets/SocialPackets.java) |
| `Packet UseTreasureBox(int type)` | [CashShopPackets.java:367](../src/main/java/org/gms/util/packets/CashShopPackets.java) |
| `Packet updateHpMpAlert(byte hp, byte mp)` | [LoginPackets.java:358](../src/main/java/org/gms/util/packets/LoginPackets.java) |
