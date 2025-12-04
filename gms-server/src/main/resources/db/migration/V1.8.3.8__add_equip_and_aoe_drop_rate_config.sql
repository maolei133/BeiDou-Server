-- 添加装备掉落率调整和群攻掉率调整相关配置项
INSERT INTO `game_config`(`config_type`, `config_sub_type`, `config_clazz`, `config_code`, `config_value`, `config_desc`)
VALUES
    ('server', 'Game Mechanics', 'java.lang.Double', 'equip_drop_rate_multiplier', '1.0', 'equip_drop_rate_multiplier'),
    ('server', 'Game Mechanics', 'java.lang.Boolean', 'aoe_drop_rate_adjustment_enabled', 'false', 'aoe_drop_rate_adjustment_enabled'),
    ('server', 'Game Mechanics', 'java.lang.Boolean', 'use_skill_max_target_count', 'false', 'use_skill_max_target_count'),
    ('server', 'Game Mechanics', 'java.lang.Double', 'aoe_drop_rate_penalty_factor', '0.1', 'aoe_drop_rate_penalty_factor'),
    ('server', 'Game Mechanics', 'java.lang.Boolean', 'allow_event_monster_global_drops', 'false', 'allow_event_monster_global_drops'),
    ('server', 'Game Mechanics', 'java.lang.Boolean', 'offline_pendant_of_spirit_enabled', 'false', 'offline_pendant_of_spirit_enabled'),
    ('server', 'Game Mechanics', 'java.lang.Double', 'party_active_member_exp_bonus', '0.0', 'party_active_member_exp_bonus'),
    ('server', 'Game Mechanics', 'java.lang.Integer', 'party_active_member_timeout_seconds', '60', 'party_active_member_timeout_seconds'),
    ('server', 'Game Mechanics', 'java.lang.Boolean', 'party_active_member_enforcement_enabled', 'false', 'party_active_member_enforcement_enabled'),
    ('server', 'Game Mechanics', 'java.lang.Boolean', 'party_active_member_dynamic_bonus_enabled', 'false', 'party_active_member_dynamic_bonus_enabled');

-- 多语言资源表 - 中文描述
INSERT INTO `lang_resources`(`lang_type`, `lang_base`, `lang_code`, `lang_value`)
VALUES
    ('zh-CN', 'game_config', 'equip_drop_rate_multiplier', '装备掉率调整 = 基础掉率 × 调整系数。默认值：1.0（即原始掉率），设为0.5表示装备掉率为原值的50%。仅对非BOSS怪物生效。'),
    ('zh-CN', 'game_config', 'aoe_drop_rate_adjustment_enabled', '群攻技能掉率调整开关。启用后，非BOSS怪物的物品原始掉率会根据技能目标数量动态调整：目标越多掉率越低，最低不低于原始掉率的10%。禁用时掉率不受目标数影响。仅对非BOSS怪物生效。'),
    ('zh-CN', 'game_config', 'use_skill_max_target_count', '群攻技能掉率使用技能目标数。true=使用技能定义的最大目标数，false=使用实际击杀的怪物数量，以实现动态掉率调整。设为false时，普攻同时击杀多个怪物也能根据衰减系数动态调整掉率'),
    ('zh-CN', 'game_config', 'aoe_drop_rate_penalty_factor', '群攻技能掉率衰减系数，控制目标数量对掉率的影响。计算公式：掉率系数 = 1.0 / [1.0 + (目标数-1) × 衰减系数]。数值越高，建议值0.1 ~ 0.9，目标数越多掉率越低，目标数为1时保持原始掉率。仅对非BOSS怪物生效，不影响金币和任务道具掉率。'),
    ('zh-CN', 'game_config', 'allow_event_monster_global_drops', '是否允许事件地图中的怪物掉落全局物品。true=允许事件怪物掉落全局物品，false=事件地图中的怪物不掉落全局物品'),
    ('zh-CN', 'game_config', 'offline_pendant_of_spirit_enabled', '精灵吊坠时长按天计算，true = 满足时长时自动保存，下线重登不用重新累计，当天有效；false = 离线立即清空时长，上线后需要重新累计在线时长。'),
    ('zh-CN', 'game_config', 'party_active_member_exp_bonus', '组队活跃成员经验加成。值为0时不增加，值为0.1时每多1个参与战斗的活跃成员，组队经验 = 组队基础经验 + 组队基础经验 × 10% × 活跃成员数。用于鼓励队伍成员共同参与战斗。'),
    ('zh-CN', 'game_config', 'party_active_member_timeout_seconds', '组队活跃成员超时时间（秒）。超过此时间没有新的伤害输出的成员，不计入活跃成员。例如：设置为60，表示60秒内有伤害输出的成员算是活跃成员。'),
    ('zh-CN', 'game_config', 'party_active_member_enforcement_enabled', '是否启用活跃成员强制模式。true = 启用，不活跃的成员无法获得经验；false = 禁用，所有队会成员都能获得经验。配合party_active_member_timeout_seconds使用。'),
    ('zh-CN', 'game_config', 'party_active_member_dynamic_bonus_enabled', '是否启用活跃人数动态加成模式。true = 启用，根据活跃人数动态调整经验。组队所有成员分割活跃成员和挂机成员两组，活跃成员获得经验加成，挂机成员获得经验减成。配合party_active_member_timeout_seconds使用。');

-- 多语言资源表 - 英文描述（根据中文描述重新翻译）
INSERT INTO `lang_resources`(`lang_type`, `lang_base`, `lang_code`, `lang_value`)
VALUES
    ('en-US', 'game_config', 'equip_drop_rate_multiplier', 'Equipment drop rate adjustment = Base drop rate × Adjustment coefficient. Default value: 1.0 (i.e., original drop rate). Set to 0.5 means equipment drop rate is 50% of the original value. Only applies to non-BOSS monsters.'),
    ('en-US', 'game_config', 'aoe_drop_rate_adjustment_enabled', 'AOE skill drop rate adjustment switch. When enabled, the original drop rate of items from non-BOSS monsters will be dynamically adjusted based on the skill target count: the more targets, the lower the drop rate, with a minimum of 10% of the original drop rate. When disabled, the drop rate is not affected by the target count. Only applies to non-BOSS monsters.'),
    ('en-US', 'game_config', 'use_skill_max_target_count', 'Whether to use skill maximum target count for drop rate calculation. true = use the skill-defined maximum target count; false = use the actual number of monsters killed, enabling dynamic drop rate adjustment. When set to false, basic attacks that kill multiple monsters also adjust drop rates based on decay coefficient.'),
    ('en-US', 'game_config', 'aoe_drop_rate_penalty_factor', 'AOE skill drop rate decay coefficient, controlling the impact of target count on drop rate. Formula: Drop rate coefficient = 1.0 / [1.0 + (Target count - 1) × Decay coefficient]. Set to 0.1 means the drop rate decreases as target count increases, maintaining original rate when target count is 1. Only applies to non-BOSS monsters; does not affect gold and quest item drop rates.'),
    ('en-US', 'game_config', 'allow_event_monster_global_drops', 'Whether to allow monsters in event maps to drop global items. true = monsters in event maps can drop global items; false = monsters in event maps do not drop global items'),
    ('en-US', 'game_config', 'offline_pendant_of_spirit_enabled', 'Pendant of Spirit duration is calculated by day. true = duration is automatically saved when requirements are met, no need to re-accumulate after relogging, valid for the current day; false = duration is cleared immediately when offline, requires re-accumulating online time after logging in.'),
    ('en-US', 'game_config', 'party_active_member_exp_bonus', 'Party active member experience bonus. When set to 0, no bonus is added. When set to 0.1, for each additional active party member participating in combat, party experience = base party experience + base party experience × 10% × number of active members. Encourages all party members to participate in combat.'),
    ('en-US', 'game_config', 'party_active_member_timeout_seconds', 'Party active member timeout in seconds. Members without damage output within this time window are not counted as active members. For example: setting to 60 means members who dealt damage within the last 60 seconds are considered active.'),
    ('en-US', 'game_config', 'party_active_member_enforcement_enabled', 'Whether to enable active member enforcement mode. true = enabled, inactive members cannot earn experience; false = disabled, all party members can earn experience. Use together with party_active_member_timeout_seconds.'),
    ('en-US', 'game_config', 'party_active_member_dynamic_bonus_enabled', 'Whether to enable active member dynamic bonus mode. true = enabled, experience is dynamically adjusted based on active member count. All party members are divided into two groups: active members and idle members. Active members gain experience bonus, idle members suffer experience penalty. Use together with party_active_member_timeout_seconds.');

-- 更新 use_autosave 中文描述
UPDATE `lang_resources`
SET `lang_value` = '开启自动存档，30分钟保存一次'
WHERE `lang_type` = 'zh-CN' AND `lang_base` = 'game_config' AND `lang_code` = 'use_autosave';

-- 更新 use_autosave 英文描述
UPDATE `lang_resources`
SET `lang_value` = 'Enable automatic save, saves every 30 minutes.'
WHERE `lang_type` = 'en-US' AND `lang_base` = 'game_config' AND `lang_code` = 'use_autosave';