export default {
  'log.manager.breadcrumb.game': 'Game Management',
  'log.manager.breadcrumb.log': 'Log Management',
  'log.manager.query.button': 'Query',
  'log.manager.form.majorCategory.label': 'Major Category',
  'log.manager.form.majorCategory.placeholder': 'Please select major category',
  'log.manager.form.minorCategory.label': 'Minor Category',
  'log.manager.form.minorCategory.placeholder': 'Please select minor category',
  'log.manager.form.keyword.label': 'Keyword',
  'log.manager.form.keyword.placeholder': 'Please enter keyword',
  'log.manager.form.startDate.label': 'Start Date',
  'log.manager.form.startDate.placeholder': 'Please select start date',
  'log.manager.form.endDate.label': 'End Date',
  'log.manager.form.endDate.placeholder': 'Please select end date',
  'log.manager.form.ip.label': 'IP Address',
  'log.manager.form.ip.placeholder': 'Please select or enter IP address',
  'log.manager.form.mac.label': 'MAC Address',
  'log.manager.form.mac.placeholder': 'Please select or enter MAC address',
  'log.manager.form.hwid.label': 'Hardware ID',
  'log.manager.form.hwid.placeholder': 'Please select or enter hardware ID',
  'log.manager.form.account.label': 'Account',
  'log.manager.form.account.placeholder': 'Please select or enter account',
  'log.manager.form.character.label': 'Character',
  'log.manager.form.character.placeholder': 'Please enter character name',
  'log.manager.table.column.content': 'Log Content',
  'log.manager.message.selectCategoryFirst':
    'Please select major and minor category first',
  'log.manager.message.fetchError': 'Failed to fetch log data',
  'log.manager.message.fetchMajorCategoriesError':
    'Failed to fetch major categories',
  'log.manager.message.fetchMinorCategoriesError':
    'Failed to fetch minor categories',
  'log.manager.message.fetchUniqueValuesError':
    'Failed to fetch filter options',
  'log.manager.export.button': 'Export Logs',

  // Log major categories
  'log.category.major.player': 'Player Related',
  'log.category.major.item': 'Item Related',
  'log.category.major.economy': 'Economy Related',
  'log.category.major.system': 'System Related',
  'log.category.major.chat': 'Chat Related',
  'log.category.major.battle': 'Battle Related',
  'log.category.major.quest': 'Quest Related',
  'log.category.major.shop': 'Shop Related',
  'log.category.major.social': 'Social Related',
  'log.category.major.gm_command': 'GM Command',
  'log.category.major.error': 'Error Related',
  'log.category.major.security': 'Security Related',
  'log.category.major.cheat': 'Cheat System',

  // Log minor categories - structured according to frontend getMinorCategoryLabel method
  // Format: log.category.minor.[major].[minor]

  // player major category minors
  'log.category.minor.player.login': 'Login',
  'log.category.minor.player.logout': 'Logout',
  'log.category.minor.player.level_up': 'Level Up',
  'log.category.minor.player.job_change': 'Job Change',

  // item major category minors
  'log.category.minor.item.obtain': 'Obtain',
  'log.category.minor.item.consume': 'Consume',
  'log.category.minor.item.drop': 'Drop',
  'log.category.minor.item.pickup': 'Pickup',

  // economy major category minors
  'log.category.minor.economy.trade': 'Trade',
  'log.category.minor.economy.auction': 'Auction',
  'log.category.minor.economy.meso_transaction': 'Meso Transaction',

  // system major category minors
  'log.category.minor.system.startup': 'Startup',
  'log.category.minor.system.shutdown': 'Shutdown',
  'log.category.minor.system.config_change': 'Config Change',

  // chat major category minors
  'log.category.minor.chat.general': 'General Chat',
  'log.category.minor.chat.whisper': 'Whisper',
  'log.category.minor.chat.party': 'Party Chat',
  'log.category.minor.chat.guild': 'Guild Chat',

  // battle major category minors
  'log.category.minor.battle.damage': 'Damage',
  'log.category.minor.battle.skill_use': 'Skill Use',
  'log.category.minor.battle.monster_kill': 'Monster Kill',

  // quest major category minors
  'log.category.minor.quest.accept': 'Accept',
  'log.category.minor.quest.complete': 'Complete',
  'log.category.minor.quest.forfeit': 'Forfeit',

  // shop major category minors
  'log.category.minor.shop.buy': 'Buy',
  'log.category.minor.shop.sell': 'Sell',
  'log.category.minor.shop.recharge': 'Recharge',

  // social major category minors
  'log.category.minor.social.friend': 'Friend',
  'log.category.minor.social.guild': 'Guild',
  'log.category.minor.social.party': 'Party',

  // gm_command major category minors
  'log.category.minor.gm_command.execution': 'Command Execution',
  'log.category.minor.gm_command.punishment': 'Player Punishment',

  // error major category minors
  'log.category.minor.error.exception': 'Exception',
  'log.category.minor.error.warning': 'Warning',

  // security major category minors
  'log.category.minor.security.hack_detection': 'Hack Detection',
  'log.category.minor.security.account_security': 'Account Security',

  // cheat major category minors
  'log.category.minor.cheat.plugin_activation': 'Plugin Activation',
  'log.category.minor.cheat.plugin_operation': 'Plugin Operation',
  'log.category.minor.cheat.plugin_system': 'Plugin System',
};
