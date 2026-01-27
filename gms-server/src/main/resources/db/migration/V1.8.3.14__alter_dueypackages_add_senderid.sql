ALTER TABLE `dueypackages` ADD COLUMN `senderid` bigint(20) DEFAULT -1 COMMENT '发件人ID' AFTER `packageid`;

-- 新增 status_time 字段，用于记录包裹状态变更（领取、删除、退回）的时间
-- 原有的 expire_date 字段将恢复其原本用途：记录包裹的过期时间
ALTER TABLE `dueypackages` ADD COLUMN `status_time` timestamp NULL DEFAULT NULL COMMENT '状态变更时间';

-- 新增 delivery_time 字段，用于记录包裹的预计送达时间
ALTER TABLE `dueypackages` ADD COLUMN `delivery_time` timestamp NULL DEFAULT NULL COMMENT '送达时间' AFTER `TIMESTAMP`;
