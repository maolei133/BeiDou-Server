insert into game_config (config_type, config_sub_type, config_clazz, config_code, config_value, config_desc)
values ('server', 'Game Mechanics', 'java.lang.Boolean', 'enable_duey_quick_delivery', 'true', 'enable_duey_quick_delivery'),
       ('server', 'Game Mechanics', 'java.lang.Boolean', 'enable_duey_normal_delivery', 'true', 'enable_duey_normal_delivery'),
       ('server', 'Game Mechanics', 'java.lang.Integer', 'duey_min_level', '10', 'duey_min_level'),
       ('server', 'Game Mechanics', 'java.lang.Long', 'duey_expire_time', '2592000000', 'duey_expire_time'),
       ('server', 'Game Mechanics', 'java.lang.Long', 'duey_normal_delivery_time', '86400000', 'duey_normal_delivery_time');

insert into lang_resources (lang_type, lang_base, lang_code, lang_value, lang_extend)
values ('zh-CN', 'game_config', 'enable_duey_quick_delivery', '是否启用快递快速配送', null),
       ('zh-CN', 'game_config', 'enable_duey_normal_delivery', '是否启用快递普通配送', null),
       ('zh-CN', 'game_config', 'duey_min_level', '使用快递的最低等级（非GM）', null),
       ('zh-CN', 'game_config', 'duey_expire_time', '快递过期时间(毫秒)', null),
       ('zh-CN', 'game_config', 'duey_normal_delivery_time', '普通快递送达时间(毫秒)', null),
       ('en-US', 'game_config', 'enable_duey_quick_delivery', 'Enable Duey Quick Delivery', null),
       ('en-US', 'game_config', 'enable_duey_normal_delivery', 'Enable Duey Normal Delivery', null),
       ('en-US', 'game_config', 'duey_min_level', 'Minimum Level to Use Duey (Non-GM)', null),
       ('en-US', 'game_config', 'duey_expire_time', 'Duey Package Expiration Time (ms)', null),
       ('en-US', 'game_config', 'duey_normal_delivery_time', 'Duey Normal Delivery Time (ms)', null);
