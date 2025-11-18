export default {
  'log.manager.breadcrumb.game': '游戏管理',
  'log.manager.breadcrumb.log': '日志管理',
  'log.manager.query.button': '查询',
  'log.manager.form.majorCategory.label': '大类',
  'log.manager.form.majorCategory.placeholder': '请选择日志大类',
  'log.manager.form.minorCategory.label': '小类',
  'log.manager.form.minorCategory.placeholder': '请选择日志小类',
  'log.manager.form.keyword.label': '关键词',
  'log.manager.form.keyword.placeholder': '请输入关键词',
  'log.manager.form.startDate.label': '开始日期',
  'log.manager.form.startDate.placeholder': '请选择开始日期',
  'log.manager.form.endDate.label': '结束日期',
  'log.manager.form.endDate.placeholder': '请选择结束日期',
  'log.manager.form.ip.label': 'IP地址',
  'log.manager.form.ip.placeholder': '请选择或输入IP地址',
  'log.manager.form.mac.label': 'MAC地址',
  'log.manager.form.mac.placeholder': '请选择或输入MAC地址',
  'log.manager.form.hwid.label': '硬件ID',
  'log.manager.form.hwid.placeholder': '请选择或输入硬件ID',
  'log.manager.form.account.label': '账号',
  'log.manager.form.account.placeholder': '请选择或输入账号',
  'log.manager.form.character.label': '角色名',
  'log.manager.form.character.placeholder': '请输入角色名',
  'log.manager.table.column.content': '日志内容',
  'log.manager.message.selectCategoryFirst': '请先选择日志大类和小类',
  'log.manager.message.fetchError': '获取日志数据失败',
  'log.manager.message.fetchMajorCategoriesError': '获取日志大类失败',
  'log.manager.message.fetchMinorCategoriesError': '获取日志小类失败',
  'log.manager.message.fetchUniqueValuesError': '获取筛选选项失败',
  'log.manager.export.button': '导出日志',

  // 日志大类翻译
  'log.category.major.player': '玩家相关',
  'log.category.major.item': '物品相关',
  'log.category.major.economy': '经济相关',
  'log.category.major.system': '系统相关',
  'log.category.major.chat': '聊天相关',
  'log.category.major.battle': '战斗相关',
  'log.category.major.quest': '任务相关',
  'log.category.major.shop': '商城相关',
  'log.category.major.social': '社交相关',
  'log.category.major.gm_command': 'GM命令',
  'log.category.major.error': '错误相关',
  'log.category.major.security': '安全相关',
  'log.category.major.cheat': '辅助系统',

  // 日志小类翻译 - 按照前端getMinorCategoryLabel方法的结构构造
  // 格式: log.category.minor.[大类].[小类]

  // player 大类下的小类
  'log.category.minor.player.login': '登录',
  'log.category.minor.player.logout': '登出',
  'log.category.minor.player.level_up': '升级',
  'log.category.minor.player.job_change': '转职',

  // item 大类下的小类
  'log.category.minor.item.obtain': '获得',
  'log.category.minor.item.consume': '消耗',
  'log.category.minor.item.drop': '丢弃',
  'log.category.minor.item.pickup': '拾取',

  // economy 大类下的小类
  'log.category.minor.economy.trade': '交易',
  'log.category.minor.economy.auction': '拍卖',
  'log.category.minor.economy.meso_transaction': '金币交易',

  // system 大类下的小类
  'log.category.minor.system.startup': '启动',
  'log.category.minor.system.shutdown': '关闭',
  'log.category.minor.system.config_change': '配置变更',

  // chat 大类下的小类
  'log.category.minor.chat.general': '一般聊天',
  'log.category.minor.chat.whisper': '私聊',
  'log.category.minor.chat.party': '组队聊天',
  'log.category.minor.chat.guild': '公会聊天',

  // battle 大类下的小类
  'log.category.minor.battle.damage': '伤害',
  'log.category.minor.battle.skill_use': '技能使用',
  'log.category.minor.battle.monster_kill': '击杀怪物',

  // quest 大类下的小类
  'log.category.minor.quest.accept': '接受',
  'log.category.minor.quest.complete': '完成',
  'log.category.minor.quest.forfeit': '放弃',

  // shop 大类下的小类
  'log.category.minor.shop.buy': '购买',
  'log.category.minor.shop.sell': '出售',
  'log.category.minor.shop.recharge': '充值',

  // social 大类下的小类
  'log.category.minor.social.friend': '好友',
  'log.category.minor.social.guild': '公会',
  'log.category.minor.social.party': '组队',

  // gm_command 大类下的小类
  'log.category.minor.gm_command.execution': '命令执行',
  'log.category.minor.gm_command.punishment': '玩家惩罚',

  // error 大类下的小类
  'log.category.minor.error.exception': '异常',
  'log.category.minor.error.warning': '警告',

  // security 大类下的小类
  'log.category.minor.security.hack_detection': '外挂检测',
  'log.category.minor.security.account_security': '账号安全',

  // cheat 大类下的小类
  'log.category.minor.cheat.plugin_activation': '插件激活',
  'log.category.minor.cheat.plugin_operation': '插件操作',
  'log.category.minor.cheat.plugin_system': '插件系统',
};
