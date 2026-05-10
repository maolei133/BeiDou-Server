# DAO 结构详细说明

本项目采用 MyBatis 作为持久层框架，DAO 层结构如下：

## 1. 结构概览

| 包名 | 说明 |
| :--- | :--- |
| `org.gms.dao.entity` | 存放数据库实体类 (DO)，与数据库表一一对应。 |
| `org.gms.dao.mapper` | 存放 MyBatis Mapper 接口，定义数据访问方法。 |

## 2. 实体类 (Entity) 与 Mapper 对照表

下表列出了当前系统中所有的实体类及其对应的 Mapper 接口，以及它们的作用。

| 实体类 (DO) | Mapper 接口 | 对应数据库表 | 作用描述 |
| :--- | :--- | :--- | :--- |
| `AccountsDO` | `AccountsMapper` | `accounts` | 账号信息，包括用户名、密码、封号状态等。 |
| `AllianceDO` | `AllianceMapper` | `alliance` | 家族联盟基础信息。 |
| `AllianceguildsDO` | `AllianceguildsMapper` | `allianceguilds` | 家族联盟成员（家族）关联表。 |
| `AreaInfoDO` | `AreaInfoMapper` | `areainfo` | 区域信息。 |
| `BbsRepliesDO` | `BbsRepliesMapper` | `bbs_replies` | 家族 BBS 回复。 |
| `BbsThreadsDO` | `BbsThreadsMapper` | `bbs_threads` | 家族 BBS 主题。 |
| `BosslogDailyDO` | `BosslogDailyMapper` | `bosslog_daily` | 每日 Boss 挑战记录。 |
| `BosslogWeeklyDO` | `BosslogWeeklyMapper` | `bosslog_weekly` | 每周 Boss 挑战记录。 |
| `BuddiesDO` | `BuddiesMapper` | `buddies` | 好友列表。 |
| `CharactersDO` | `CharactersMapper` | `characters` | 角色核心数据，包括属性、位置、外观等。 |
| `CommandInfoDO` | `CommandInfoMapper` | `command_info` | 指令信息。 |
| `CooldownsDO` | `CooldownsMapper` | `cooldowns` | 技能冷却时间记录。 |
| `DropDataDO` | `DropDataMapper` | `drop_data` | 掉落数据。 |
| `DropDataGlobalDO` | `DropDataGlobalMapper` | `drop_data_global` | 全局掉落数据。 |
| `DueyitemsDO` | `DueyitemsMapper` | `dueyitems` | 快递物品。 |
| `DueypackagesDO` | `DueypackagesMapper` | `dueypackages` | 快递包裹。 |
| `EventstatsDO` | `EventstatsMapper` | `eventstats` | 活动统计。 |
| `ExtendValueDO` | `ExtendValueMapper` | `extend_value` | 扩展数值记录。 |
| `FamelogDO` | `FamelogMapper` | `famelog` | 人气度操作日志。 |
| `FamilyCharacterDO` | `FamilyCharacterMapper` | `family_character` | 家族成员信息。 |
| `FamilyEntitlementDO` | `FamilyEntitlementMapper` | `family_entitlement` | 家族权益。 |
| `FlywaySchemaHistoryDO` | `FlywaySchemaHistoryMapper` | `flyway_schema_history` | 数据库版本迁移历史。 |
| `FredstorageDO` | `FredstorageMapper` | `fredstorage` | 弗雷德仓库。 |
| `GachaponRewardDO` | `GachaponRewardMapper` | `gachapon_reward` | 扭蛋机奖励。 |
| `GachaponRewardPoolDO` | `GachaponRewardPoolMapper` | `gachapon_reward_pool` | 扭蛋机奖池。 |
| `GameConfigDO` | `GameConfigMapper` | `game_config` | 游戏配置。 |
| `GiftsDO` | `GiftsMapper` | `gifts` | 礼物。 |
| `GuildsDO` | `GuildsMapper` | `guilds` | 家族基础信息。 |
| `HpMpAlertDO` | `HpMpAlertMapper` | `hp_mp_alert` | HP/MP 预警设置。 |
| `HwidaccountsDO` | `HwidaccountsMapper` | `hwidaccounts` | 硬件 ID 关联账号。 |
| `HwidbansDO` | `HwidbansMapper` | `hwidbans` | 硬件 ID 封禁记录。 |
| `InventoryequipmentDO` | `InventoryequipmentMapper` | `inventoryequipment` | 装备栏物品详情。 |
| `InventoryitemsDO` | `InventoryitemsMapper` | `inventoryitems` | 背包物品基础信息。 |
| `InventorymerchantDO` | `InventorymerchantMapper` | `inventorymerchant` | 雇佣商店物品。 |
| `IpbansDO` | `IpbansMapper` | `ipbans` | IP 封禁记录。 |
| `KeymapDO` | `KeymapMapper` | `keymap` | 按键映射设置。 |
| `LangResourcesDO` | `LangResourcesMapper` | `lang_resources` | 语言资源。 |
| `MacbansDO` | `MacbansMapper` | `macbans` | MAC 地址封禁记录。 |
| `MacfiltersDO` | `MacfiltersMapper` | `macfilters` | MAC 地址过滤。 |
| `MakercreatedataDO` | `MakercreatedataMapper` | `makercreatedata` | 制作技能-生成数据。 |
| `MakerreagentdataDO` | `MakerreagentdataMapper` | `makerreagentdata` | 制作技能-试剂数据。 |
| `MakerrecipedataDO` | `MakerrecipedataMapper` | `makerrecipedata` | 制作技能-配方数据。 |
| `MakerrewarddataDO` | `MakerrewarddataMapper` | `makerrewarddata` | 制作技能-奖励数据。 |
| `MarriagesDO` | `MarriagesMapper` | `marriages` | 婚姻关系。 |
| `MedalmapsDO` | `MedalmapsMapper` | `medalmaps` | 勋章地图记录。 |
| `ModifiedCashItemDO` | `ModifiedCashItemMapper` | `modified_cash_item` | 修改过的现金物品。 |
| `MonsterbookDO` | `MonsterbookMapper` | `monsterbook` | 怪物图鉴。 |
| `MonstercarddataDO` | `MonstercarddataMapper` | `monstercarddata` | 怪物卡片数据。 |
| `MtsCartDO` | `MtsCartMapper` | `mts_cart` | MTS 购物车。 |
| `MtsItemsDO` | `MtsItemsMapper` | `mts_items` | MTS 物品。 |
| `NamechangesDO` | `NamechangesMapper` | `namechanges` | 改名记录。 |
| `NewyearDO` | `NewyearMapper` | `newyear` | 新年活动记录。 |
| `NotesDO` | `NotesMapper` | `notes` | 笔记/便签。 |
| `NxcodeDO` | `NxcodeMapper` | `nxcode` | 点券兑换码。 |
| `NxcodeItemsDO` | `NxcodeItemsMapper` | `nxcode_items` | 点券兑换码关联物品。 |
| `NxcouponsDO` | `NxcouponsMapper` | `nxcoupons` | 点券优惠券。 |
| `PetignoresDO` | `PetignoresMapper` | `petignores` | 宠物拾取过滤。 |
| `PetsDO` | `PetsMapper` | `pets` | 宠物信息。 |
| `PlayerdiseasesDO` | `PlayerdiseasesMapper` | `playerdiseases` | 玩家疾病状态。 |
| `PlayernpcsDO` | `PlayernpcsMapper` | `playernpcs` | 玩家 NPC 基础信息。 |
| `PlayernpcsEquipDO` | `PlayernpcsEquipMapper` | `playernpcs_equip` | 玩家 NPC 装备。 |
| `PlayernpcsFieldDO` | `PlayernpcsFieldMapper` | `playernpcs_field` | 玩家 NPC 所在地图。 |
| `PlifeDO` | `PlifeMapper` | `plife` | 个人生活记录 (Project Life)。 |
| `QuestactionsDO` | `QuestactionsMapper` | `questactions` | 任务动作。 |
| `QuestprogressDO` | `QuestprogressMapper` | `questprogress` | 任务进度。 |
| `QuestrequirementsDO` | `QuestrequirementsMapper` | `questrequirements` | 任务要求。 |
| `QueststatusDO` | `QueststatusMapper` | `queststatus` | 任务状态。 |
| `QuickslotkeymappedDO` | `QuickslotkeymappedMapper` | `quickslotkeymapped` | 快捷键映射。 |
| `ReactordropsDO` | `ReactordropsMapper` | `reactordrops` | 反应堆掉落。 |
| `ReportsDO` | `ReportsMapper` | `reports` | 举报记录。 |
| `ResponsesDO` | `ResponsesMapper` | `responses` | 问卷/调查响应。 |
| `RingsDO` | `RingsMapper` | `rings` | 戒指信息（结婚戒指、友谊戒指等）。 |
| `SavedlocationsDO` | `SavedlocationsMapper` | `savedlocations` | 保存的地图位置（如自由市场返回点）。 |
| `ServerQueueDO` | `ServerQueueMapper` | `server_queue` | 服务器排队信息。 |
| `ShopitemsDO` | `ShopitemsMapper` | `shopitems` | 商店物品。 |
| `ShopsDO` | `ShopsMapper` | `shops` | 商店基础信息。 |
| `SkillmacrosDO` | `SkillmacrosMapper` | `skillmacros` | 技能宏。 |
| `SkillsDO` | `SkillsMapper` | `skills` | 角色技能信息。 |
| `SpecialcashitemsDO` | `SpecialcashitemsMapper` | `specialcashitems` | 特殊现金物品。 |
| `StoragesDO` | `StoragesMapper` | `storages` | 仓库信息。 |
| `TrocklocationsDO` | `TrocklocationsMapper` | `trocklocations` | 缩地石/瞬移石记录位置。 |
| `WishlistsDO` | `WishlistsMapper` | `wishlists` | 愿望清单。 |
| `WorldtransfersDO` | `WorldtransfersMapper` | `worldtransfers` | 转区记录。 |

## 3. 待改造模块评估

通过代码扫描，发现以下模块仍在使用 `PreparedStatement`，建议优先改造：

| 模块/文件 | 涉及表 | 建议 |
| :--- | :--- | :--- |
| `Guild.java` | `guilds`, `characters` | `GuildsDO` 已存在，需完善 Mapper 方法以替代手写 SQL。 |
| `Alliance.java` | `alliance`, `allianceguilds` | `AllianceDO`, `AllianceguildsDO` 已存在，建议迁移。 |
| `MTSHandler.java` | `mts_items`, `mts_cart` | `MTSItemsDO`, `MTSCartDO` 已存在，建议迁移。 |
| `Ring.java` | `rings`, `inventoryequipment` | `RingsDO` 已存在，建议迁移。 |
| `BuddyList.java` | `buddies`, `characters` | `BuddiesDO` 已存在，建议迁移。 |
| `NewYearCardRecord.java` | `newyear` | `NewyearDO` 已存在，建议迁移。 |
| `MacFilterHelper.java` | `macfilters` | `MacfiltersDO` 已存在，建议迁移。 |
| `CouponCodeHandler.java` | `nxcode`, `nxcode_items` | `NxcodeDO`, `NxcodeItemsDO` 已存在，建议迁移。 |
| `ReportHandler.java` | `reports` | `ReportsDO` 已存在，建议迁移。 |
| `TransferNameHandler.java` | `namechanges` | `NamechangesDO` 已存在，建议迁移。 |
| `TransferWorldHandler.java` | `worldtransfers` | `WorldtransfersDO` 已存在，建议迁移。 |

## 4. 改造建议
1.  **优先处理**: 优先处理 `Guild` 和 `Alliance` 相关逻辑，因为涉及表较少且逻辑相对集中。
2.  **复杂查询**: 对于涉及多表联查的 SQL（如 `Guild` 中查询角色名），可以在 Mapper XML 中定义 ResultMap 或使用 `@Select` 注解编写复杂 SQL，保持 DAO 接口简洁。
3.  **事务管理**: 迁移过程中注意事务的一致性，MyBatis 与 Spring 集成后通常能更好地管理事务。
