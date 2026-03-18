-- 迁移目的:
-- 1. 为了支持未来更复杂的JSON配置（如物品溯源系统的详细规则），将 game_config 表的 config_value 字段从 VARCHAR(256) 扩展为 TEXT 类型。
-- 2. TEXT类型可以存储长达65,535个字符，足够应对各种复杂的配置场景，同时保持对现有简单值的兼容。
ALTER TABLE `game_config`
    MODIFY COLUMN `config_value` TEXT COMMENT '参数的值 (字符串或JSON)';

-- 为溯源系统表增加 is_valuable 字段，用于清理任务和快速区分物品价值
ALTER TABLE `item_trace_logs`
    ADD COLUMN `is_valuable` TINYINT(1) DEFAULT 0 COMMENT '是否有价值(1:是, 0:否)';
