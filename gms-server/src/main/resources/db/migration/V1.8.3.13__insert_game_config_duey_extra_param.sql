insert into game_config (config_type, config_sub_type, config_clazz, config_code, config_value, config_desc)
values ('server', 'Game Mechanics', 'java.lang.Long', 'duey_retention_days', '30', 'duey_retention_days'),
       ('server', 'Game Mechanics', 'java.lang.Integer', 'duey_normal_fee', '5000', 'duey_normal_fee');

-- Update existing configs to use minutes instead of milliseconds
UPDATE game_config SET config_clazz = 'java.lang.Integer', config_value = '43200' WHERE config_code = 'duey_expire_time'; -- 30 days in minutes
UPDATE game_config SET config_clazz = 'java.lang.Integer', config_value = '1440' WHERE config_code = 'duey_normal_delivery_time'; -- 1 day in minutes

insert into lang_resources (lang_type, lang_base, lang_code, lang_value, lang_extend)
values ('zh-CN', 'game_config', 'duey_retention_days', '快递记录保留天数(已过期/已领取/已删除)', null),
       ('zh-CN', 'game_config', 'duey_normal_fee', '普通快递基础费用', null),
       ('en-US', 'game_config', 'duey_retention_days', 'Duey Package Retention Days (Expired/Claimed/Deleted)', null),
       ('en-US', 'game_config', 'duey_normal_fee', 'Duey Normal Delivery Fee', null);

-- Update lang resources for time configs
UPDATE lang_resources SET lang_value = '快递过期时间(分钟)' WHERE lang_code = 'duey_expire_time' AND lang_type = 'zh-CN';
UPDATE lang_resources SET lang_value = '普通快递送达时间(分钟)' WHERE lang_code = 'duey_normal_delivery_time' AND lang_type = 'zh-CN';
UPDATE lang_resources SET lang_value = 'Duey Package Expiration Time (min)' WHERE lang_code = 'duey_expire_time' AND lang_type = 'en-US';
UPDATE lang_resources SET lang_value = 'Duey Normal Delivery Time (min)' WHERE lang_code = 'duey_normal_delivery_time' AND lang_type = 'en-US';
