-- 插入mobvac命令数据
INSERT INTO command_info (syntax, level, enabled, clazz, default_level)
SELECT 'mobvac', 4, 1, 'MobVacCommand', 4
FROM dual
WHERE NOT EXISTS (
    SELECT 1 FROM command_info WHERE syntax = 'mobvac'
);

-- 游戏配置表
INSERT INTO `game_config`(`config_type`, `config_sub_type`, `config_clazz`, `config_code`, `config_value`, `config_desc`)
VALUES
    ('server', 'CheatSystem', 'java.lang.Boolean', 'cheat_mob_vac_switch', 'true', 'cheat_mob_vac_switch'),
    ('server', 'CheatSystem', 'java.lang.Integer', 'cheat_mob_vac_daily_limit', '10', 'cheat_mob_vac_daily_limit'),
    ('server', 'CheatSystem', 'java.lang.Integer', 'cheat_mob_vac_duration', '30', 'cheat_mob_vac_duration'),
    ('server', 'CheatSystem', 'java.lang.Double', 'cheat_mob_vac_radius', '-1', 'cheat_mob_vac_radius');

-- 多语言资源表
INSERT INTO `lang_resources`(`lang_type`, `lang_base`, `lang_code`, `lang_value`)
VALUES
    ('zh-CN', 'game_config', 'cheat_mob_vac_switch', '吸怪功能总开关，控制是否启用吸怪功能'),
    ('en-US', 'game_config', 'cheat_mob_vac_switch', 'Mob Vacuum Feature Switch, controls whether to enable the mob vacuum feature'),
    ('zh-CN', 'game_config', 'cheat_mob_vac_daily_limit', '每日吸怪功能使用次数限制，0为无限制'),
    ('en-US', 'game_config', 'cheat_mob_vac_daily_limit', 'Daily Mob Vacuum Feature Usage Limit, 0 for unlimited'),
    ('zh-CN', 'game_config', 'cheat_mob_vac_duration', '单次使用吸怪功能的时长（分钟）'),
    ('en-US', 'game_config', 'cheat_mob_vac_duration', 'Duration of Single Use of Mob Vacuum Feature (minutes)'),
    ('zh-CN', 'game_config', 'cheat_mob_vac_radius', '吸怪范围半径，设为-1为全图吸怪'),
    ('en-US', 'game_config', 'cheat_mob_vac_radius', 'Mob Vacuum Radius, Set to -1 for Full Map');