-- 物品找回系统相关配置
INSERT INTO `game_config`(`config_type`, `config_sub_type`, `config_clazz`, `config_code`, `config_value`, `config_desc`)
VALUES
    ('server', 'Game Mechanics', 'java.lang.Boolean', 'item_recovery_enabled', 'true', 'item_recovery_enabled'),
    ('server', 'Game Mechanics', 'java.lang.Integer', 'item_recovery_cost_type', '0', 'item_recovery_cost_type'),
    ('server', 'Game Mechanics', 'java.lang.Long', 'item_recovery_base_fee_meso', '1000000', 'item_recovery_base_fee_meso'),
    ('server', 'Game Mechanics', 'java.lang.Long', 'item_recovery_base_fee_nx', '100000', 'item_recovery_base_fee_nx'),
    ('server', 'Game Mechanics', 'java.lang.Double', 'item_recovery_valuation_rate', '1.5', 'item_recovery_valuation_rate'),
    ('server', 'Game Mechanics', 'java.lang.Integer', 'item_recovery_hours', '72', 'item_recovery_hours'),
    ('server', 'Game Mechanics', 'java.lang.Integer', 'item_recovery_expiration_days', '7', 'item_recovery_expiration_days'),
    ('server', 'Game Mechanics', 'java.lang.Integer', 'trace_log_retention_days', '30', 'trace_log_retention_days'),
    ('server', 'Game Mechanics', 'java.lang.Integer', 'trace_log_short_retention_days', '1', 'trace_log_short_retention_days');

-- 多语言资源表 - 中文描述
INSERT INTO `lang_resources`(`lang_type`, `lang_base`, `lang_code`, `lang_value`)
VALUES
    ('zh-CN', 'game_config', 'item_recovery_enabled', '是否开启物品找回系统。true=开启，false=关闭。开启后，玩家出售给NPC或丢弃的有价值物品会被记录，可通过NPC找回。'),
    ('zh-CN', 'game_config', 'item_recovery_cost_type', '找回费用类型。0=金币，1=点券，2=金币+点券。'),
    ('zh-CN', 'game_config', 'item_recovery_base_fee_meso', '找回物品的基础金币费用。无论物品价值多少，都需要支付此基础费用。'),
    ('zh-CN', 'game_config', 'item_recovery_base_fee_nx', '找回物品的基础点券费用。无论物品价值多少，都需要支付此基础费用。'),
    ('zh-CN', 'game_config', 'item_recovery_valuation_rate', '物品价值评估倍率。找回费用 = 基础费用 + (物品商店售价 × 数量 × 倍率)。设为0则不根据物品价值浮动，仅收取基础费用。'),
    ('zh-CN', 'game_config', 'item_recovery_hours', '物品可找回的时限（小时）。玩家只能找回在此时间内出售或丢弃的物品。默认72小时。'),
    ('zh-CN', 'game_config', 'item_recovery_expiration_days', '物品找回记录的保留天数。超过此天数的记录将被系统自动清理。默认7天。'),
    ('zh-CN', 'game_config', 'trace_log_retention_days', '物品溯源日志保留天数。超过此天数的常规日志将被物理删除。默认30天。'),
    ('zh-CN', 'game_config', 'trace_log_short_retention_days', '短期物品溯源日志保留天数。用于清理低价值或自然消失的物品日志（如怪物掉落未拾取、地图物品超限清除）。默认1天。');


-- 多语言资源表 - 英文描述
INSERT INTO `lang_resources`(`lang_type`, `lang_base`, `lang_code`, `lang_value`)
VALUES
    ('en-US', 'game_config', 'item_recovery_enabled', 'Whether to enable the item recovery system. true=enabled, false=disabled. When enabled, valuable items sold to NPCs or dropped by players will be recorded and can be recovered via NPC.'),
    ('en-US', 'game_config', 'item_recovery_cost_type', 'Recovery cost type. 0=Meso, 1=NX, 2=Meso+NX.'),
    ('en-US', 'game_config', 'item_recovery_base_fee_meso', 'Base Meso fee for recovering items. This fee is required regardless of the item value.'),
    ('en-US', 'game_config', 'item_recovery_base_fee_nx', 'Base NX fee for recovering items. This fee is required regardless of the item value.'),
    ('en-US', 'game_config', 'item_recovery_valuation_rate', 'Item valuation rate. Recovery fee = Base fee + (Item shop price × Quantity × Rate). Set to 0 to charge only the base fee regardless of item value.'),
    ('en-US', 'game_config', 'item_recovery_hours', 'Time limit (in hours) for item recovery. Players can only recover items sold or dropped within this time frame. Default is 24 hours.'),
    ('en-US', 'game_config', 'item_recovery_expiration_days', 'Retention days for item recovery records. Records older than this will be automatically cleaned up by the system. Default is 7 days.'),
    ('en-US', 'game_config', 'trace_log_retention_days', 'Retention days for item trace logs. Regular logs older than this will be physically deleted. Default is 30 days.'),
    ('en-US', 'game_config', 'trace_log_short_retention_days', 'Retention days for short-term item trace logs. Used for cleaning up low-value or naturally disappearing item logs (e.g., monster drops not picked up, map item limit exceeded). Default is 3 days.');