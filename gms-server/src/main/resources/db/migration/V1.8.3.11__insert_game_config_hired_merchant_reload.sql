-- 雇佣商店主表
CREATE TABLE IF NOT EXISTS `hired_merchants` (
                                                 `id` int(11) NOT NULL AUTO_INCREMENT COMMENT '商店唯一标识',
    `owner_id` int(11) NOT NULL COMMENT '店主角色ID',
    `channel` int(11) NOT NULL COMMENT '所在频道',
    `world_id` int(11) NOT NULL DEFAULT 0 COMMENT '所在世界ID',
    `map_id` int(11) NOT NULL COMMENT '所在地图ID',
    `x` int(11) DEFAULT NULL COMMENT 'X坐标',
    `y` int(11) DEFAULT NULL COMMENT 'Y坐标',
    `description` varchar(255) DEFAULT NULL COMMENT '商店描述',
    `item_id` int(11) NOT NULL COMMENT '雇佣商人道具ID (用于区分外观)',
    `status` varchar(20) NOT NULL DEFAULT 'ACTIVE' COMMENT '状态 (ACTIVE:活跃, CLOSED:已关闭, EXPIRED:已过期, MAINTAINED:维护中)',
    `start_time` bigint(20) NOT NULL COMMENT '开店时间',
    `close_time` bigint(20) DEFAULT NULL COMMENT '关闭时间',
    `mesos` bigint(20) NOT NULL DEFAULT '0' COMMENT '当前商店内累积的金币 (未取回)',
    PRIMARY KEY (`id`),
    KEY `idx_owner_status` (`owner_id`,`status`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='雇佣商店主表';

-- 雇佣商店物品表
CREATE TABLE IF NOT EXISTS `hired_merchant_items` (
    `id` int(11) NOT NULL AUTO_INCREMENT COMMENT '物品唯一标识',
    `merchant_id` int(11) NOT NULL COMMENT '关联 hired_merchants 表ID',
    `inventory_item_id` bigint(20) DEFAULT NULL COMMENT '关联原始 inventoryitems 表的ID (用于追溯)',
    `item_id` int(11) NOT NULL COMMENT '物品模板ID',
    `quantity` smallint(6) NOT NULL COMMENT '初始数量',
    `sold_quantity` smallint(6) NOT NULL DEFAULT '0' COMMENT '已售数量',
    `price` int(11) NOT NULL COMMENT '单价',
    `bundles` smallint(6) NOT NULL COMMENT '组数',
    `status` varchar(20) NOT NULL DEFAULT 'ON_SALE' COMMENT '状态 (ON_SALE:在售, SOLD_OUT:售罄, RETURNED:已取回)',
    `item_data` text COMMENT '物品详细属性 (JSON格式)',
    `settled_time` bigint(20) DEFAULT NULL COMMENT '结算(取款)时间',
    PRIMARY KEY (`id`),
    KEY `idx_merchant_id` (`merchant_id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='雇佣商店物品表';

-- 雇佣商店交易记录表
CREATE TABLE IF NOT EXISTS `hired_merchant_transactions` (
    `id` int(11) NOT NULL AUTO_INCREMENT COMMENT '交易记录唯一标识',
    `merchant_id` int(11) NOT NULL COMMENT '关联 hired_merchants 表ID',
    `item_id` int(11) DEFAULT NULL COMMENT '物品模板ID',
    `buyer_id` int(11) DEFAULT NULL COMMENT '购买者角色ID (上架/下架时可为空或店主ID)',
    `type` varchar(20) NOT NULL COMMENT '操作类型 (BUY:购买, ADD:上架, REMOVE:下架, RETURN:取回)',
    `quantity` smallint(6) NOT NULL COMMENT '操作数量',
    `price` int(11) DEFAULT NULL COMMENT '交易单价 (仅 BUY 类型有效)',
    `total_price` bigint(20) DEFAULT NULL COMMENT '总价',
    `timestamp` bigint(20) NOT NULL COMMENT '操作时间',
    PRIMARY KEY (`id`),
    KEY `idx_merchant_id` (`merchant_id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='雇佣商店交易记录表';

-- 插入配置参数
INSERT INTO `game_config` (`config_type`, `config_sub_type`, `config_clazz`, `config_code`, `config_value`, `config_desc`)
VALUES
    ('server', 'Game Mechanics', 'java.lang.Boolean', 'hired_merchant_reload_on_restart', 'true', 'hired_merchant_reload_on_restart'),
    ('server', 'Game Mechanics', 'java.lang.Integer', 'hired_merchant_duration', '1440', 'hired_merchant_duration'),
    ('server', 'Game Mechanics', 'java.lang.Integer', 'hired_merchant_keep_days', '7', 'hired_merchant_keep_days'),
    ('server', 'Game Mechanics', 'java.lang.Integer', 'hired_merchant_max_items', '16', 'hired_merchant_max_items'),
    ('server', 'Game Mechanics', 'java.lang.Integer', 'hired_merchant_tax_rate', '0', 'hired_merchant_tax_rate'),
    ('server', 'Game Mechanics', 'java.lang.Boolean', 'hired_merchant_allow_remote', 'true', 'hired_merchant_allow_remote'),
    ('server', 'Game Mechanics', 'java.lang.Long', 'hired_merchant_price_limit', '2147483647', 'hired_merchant_price_limit'),
    ('server', 'Game Mechanics', 'java.lang.Long', 'hired_merchant_meso_limit', '2147483647', 'hired_merchant_meso_limit');

INSERT INTO `lang_resources` (`lang_type`, `lang_base`, `lang_code`, `lang_value`, `lang_extend`)
VALUES
    ('zh-CN', 'game_config', 'hired_merchant_reload_on_restart', '重启服务端时是否重载雇佣商店', null),
    ('en-US', 'game_config', 'hired_merchant_reload_on_restart', 'Reload Hired Merchants on Server Restart', null),
    ('zh-CN', 'game_config', 'hired_merchant_duration', '雇佣商店持续时长(分钟)', null),
    ('en-US', 'game_config', 'hired_merchant_duration', 'Hired Merchant Duration (minutes)', null),
    ('zh-CN', 'game_config', 'hired_merchant_keep_days', '雇佣商店数据保留天数', null),
    ('en-US', 'game_config', 'hired_merchant_keep_days', 'Hired Merchant Data Retention Days', null),
    ('zh-CN', 'game_config', 'hired_merchant_max_items', '雇佣商店最大上架物品数（默认16格）', null),
    ('en-US', 'game_config', 'hired_merchant_max_items', 'Hired Merchant Max Items (default 16 slots)', null),
    ('zh-CN', 'game_config', 'hired_merchant_tax_rate', '雇佣商店交易税率(%)', null),
    ('en-US', 'game_config', 'hired_merchant_tax_rate', 'Hired Merchant Tax Rate (%)', null),
    ('zh-CN', 'game_config', 'hired_merchant_allow_remote', '是否允许远程打开雇佣商店', null),
    ('en-US', 'game_config', 'hired_merchant_allow_remote', 'Allow Remote Open Hired Merchant', null),
    ('zh-CN', 'game_config', 'hired_merchant_price_limit', '雇佣商店物品价格上限', null),
    ('en-US', 'game_config', 'hired_merchant_price_limit', 'Hired Merchant Item Price Limit', null),
    ('zh-CN', 'game_config', 'hired_merchant_meso_limit', '雇佣商店金币上限', null),
    ('en-US', 'game_config', 'hired_merchant_meso_limit', 'Hired Merchant Meso Limit', null);
