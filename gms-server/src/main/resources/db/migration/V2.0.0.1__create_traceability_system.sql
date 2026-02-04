/*
 * 物品流转溯源系统数据库迁移脚本
 * 包含：
 * 1. 物品溯源日志表 (item_trace_logs)
 * 2. 物品找回日志表 (item_recovery_logs)
 * 3. 仓库物品表 (storage_items)
 * 4. 关联表改造 (inventoryitems, hired_merchant_items, hired_merchant_transactions, dueypackages)
 */

-- 1. 创建物品溯源日志表
CREATE TABLE IF NOT EXISTS `item_trace_logs` (
  `id` BIGINT NOT NULL AUTO_INCREMENT COMMENT '自增主键',
  `uid` BIGINT NOT NULL COMMENT '物品唯一ID',
  `account_id` INT NOT NULL COMMENT '操作者账号ID',
  `character_id` INT NOT NULL COMMENT '操作者角色ID',
  `action_type` VARCHAR(32) NOT NULL COMMENT '行为类型 (CREATE, DROP, SELL, TRADE, STORAGE_IN, etc.)',
  `action_source` VARCHAR(32) DEFAULT NULL COMMENT '行为来源 (e.g., "NPC商店", "玩家交易", "怪物掉落")',
  `map_id` INT DEFAULT NULL COMMENT '发生地点',
  `item_id` INT NOT NULL COMMENT '物品模板ID',
  `quantity_change` INT DEFAULT NULL COMMENT '数量变化 (+/-)',
  `target_info` VARCHAR(255) DEFAULT NULL COMMENT '交互对象信息 (如交易对手角色名)',
  `item_snapshot` JSON DEFAULT NULL COMMENT '操作发生时物品的完整属性快照',
  `timestamp` BIGINT NOT NULL COMMENT '发生时间戳',
  `memo` VARCHAR(255) DEFAULT NULL COMMENT '备注 (如异常原因)',
  PRIMARY KEY (`id`),
  KEY `idx_uid` (`uid`),
  KEY `idx_account_id` (`account_id`),
  KEY `idx_character_id` (`character_id`),
  KEY `idx_action_type` (`action_type`),
  KEY `idx_item_id` (`item_id`),
  KEY `idx_timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='物品溯源日志表';

-- 2. 创建物品找回日志表
CREATE TABLE IF NOT EXISTS `item_recovery_logs` (
  `id` BIGINT NOT NULL AUTO_INCREMENT COMMENT '自增主键',
  `uid` BIGINT NOT NULL COMMENT '物品唯一ID',
  `character_id` INT NOT NULL COMMENT '所属角色ID',
  `item_id` INT NOT NULL COMMENT '物品模板ID',
  `item_data` JSON NOT NULL COMMENT '物品被处理时的完整属性快照',
  `disposal_type` VARCHAR(16) NOT NULL COMMENT '处理方式: SELL (出售), DROP (丢弃)',
  `disposal_time` BIGINT NOT NULL COMMENT '处理时间戳',
  `recovery_deadline` BIGINT NOT NULL COMMENT '可找回的截止时间戳',
  `status` VARCHAR(16) NOT NULL COMMENT 'RECOVERABLE, RECOVERED, EXPIRED',
  PRIMARY KEY (`id`),
  KEY `idx_character_id` (`character_id`),
  KEY `idx_recovery_deadline` (`recovery_deadline`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='物品找回日志表';

-- 3. 创建仓库物品表
CREATE TABLE IF NOT EXISTS `storage_items` (
  `id` BIGINT NOT NULL AUTO_INCREMENT COMMENT '自增主键',
  `uid` BIGINT NOT NULL COMMENT '物品唯一溯源ID',
  `storage_id` INT NOT NULL COMMENT '关联 storages.storageid',
  `item_id` INT NOT NULL COMMENT '物品模板ID',
  `quantity` SMALLINT NOT NULL DEFAULT 1 COMMENT '数量',
  `position` SMALLINT NOT NULL COMMENT '排序槽位',
  `item_data` TEXT NOT NULL COMMENT 'JSON 格式存储物品完整属性 (含潜能、有效期、制作者等)',
  `create_time` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '存入时间',
  PRIMARY KEY (`id`),
  KEY `idx_storage_id` (`storage_id`),
  KEY `idx_uid` (`uid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='仓库物品表';

-- 4. 关联表改造

-- 4.1 inventoryitems 表新增 uid 字段
-- 检查字段是否存在，不存在则添加 (MySQL 5.7+ 支持 IF NOT EXISTS 语法，但在 ALTER TABLE 中通常需要存储过程或忽略错误)
-- 这里直接使用 ALTER TABLE，如果已存在会报错，但在 migration 场景下通常是全新的环境或顺序执行
SET @dbname = DATABASE();
SET @tablename = "inventoryitems";
SET @columnname = "uid";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (column_name = @columnname)
  ) > 0,
  "SELECT 1",
  CONCAT("ALTER TABLE ", @tablename, " ADD ", @columnname, " BIGINT DEFAULT NULL COMMENT '物品唯一ID' AFTER `inventoryitemid`;")
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- 为 inventoryitems.uid 添加索引
SET @indexname = "idx_uid";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (index_name = @indexname)
  ) > 0,
  "SELECT 1",
  CONCAT("CREATE INDEX ", @indexname, " ON ", @tablename, " (", @columnname, ");")
));
PREPARE createIndexIfNotExists FROM @preparedStatement;
EXECUTE createIndexIfNotExists;
DEALLOCATE PREPARE createIndexIfNotExists;


-- 4.2 hired_merchant_items 表新增 uid 字段
SET @tablename = "hired_merchant_items";
SET @columnname = "uid";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (column_name = @columnname)
  ) > 0,
  "SELECT 1",
  CONCAT("ALTER TABLE ", @tablename, " ADD ", @columnname, " BIGINT DEFAULT NULL COMMENT '物品唯一ID' AFTER `id`;")
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- 为 hired_merchant_items.uid 添加索引
SET @indexname = "idx_uid";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (index_name = @indexname)
  ) > 0,
  "SELECT 1",
  CONCAT("CREATE INDEX ", @indexname, " ON ", @tablename, " (", @columnname, ");")
));
PREPARE createIndexIfNotExists FROM @preparedStatement;
EXECUTE createIndexIfNotExists;
DEALLOCATE PREPARE createIndexIfNotExists;


-- 4.3 hired_merchant_transactions 表新增 uid 字段
SET @tablename = "hired_merchant_transactions";
SET @columnname = "uid";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (column_name = @columnname)
  ) > 0,
  "SELECT 1",
  CONCAT("ALTER TABLE ", @tablename, " ADD ", @columnname, " BIGINT DEFAULT NULL COMMENT '物品唯一ID' AFTER `id`;")
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- 为 hired_merchant_transactions.uid 添加索引
SET @indexname = "idx_uid";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (index_name = @indexname)
  ) > 0,
  "SELECT 1",
  CONCAT("CREATE INDEX ", @indexname, " ON ", @tablename, " (", @columnname, ");")
));
PREPARE createIndexIfNotExists FROM @preparedStatement;
EXECUTE createIndexIfNotExists;
DEALLOCATE PREPARE createIndexIfNotExists;


-- 4.4 dueypackages 表新增 uid 字段
SET @tablename = "dueypackages";
SET @columnname = "uid";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (column_name = @columnname)
  ) > 0,
  "SELECT 1",
  CONCAT("ALTER TABLE ", @tablename, " ADD ", @columnname, " BIGINT DEFAULT NULL COMMENT '物品唯一ID' AFTER `PackageId`;")
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- 为 dueypackages.uid 添加索引
SET @indexname = "idx_uid";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (index_name = @indexname)
  ) > 0,
  "SELECT 1",
  CONCAT("CREATE INDEX ", @indexname, " ON ", @tablename, " (", @columnname, ");")
));
PREPARE createIndexIfNotExists FROM @preparedStatement;
EXECUTE createIndexIfNotExists;
DEALLOCATE PREPARE createIndexIfNotExists;
