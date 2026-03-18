export default {
  // Common
  'common.button.search': 'Search',
  'common.button.view': 'View',
  'common.button.save': 'Save Config',
  'common.button.resetToDefault': 'Reset to Default',
  'common.button.add': 'Add',
  'common.button.delete': 'Delete',
  'common.table.operations': 'Operations',
  'common.message.save.success': 'Configuration saved successfully',
  'common.modal.title.confirmReset': 'Confirm Reset to Default?',
  'common.modal.content.unsavedWillBeLost': 'All unsaved changes will be lost.',
  'common.placeholder.select': 'Please select',
  'common.placeholder.input': 'Please enter',

  // Traceability Dashboard Page
  'traceability.dashboard.stats.totalRecords': 'Total Records',
  'traceability.dashboard.stats.todayAdded': 'Today Added',
  'traceability.dashboard.stats.avgPerHour': 'Avg Records/Hour',
  'traceability.dashboard.stats.dbTableSizeMB': 'DB Table Size',

  // Traceability Config Page
  'traceability.config.card.global': 'Global Controls',
  'traceability.config.card.logActionSwitches': 'Log Action Switches',
  'traceability.config.card.valueConditions': 'Value Conditions',
  'traceability.config.card.retention': 'Recording Targets & Retention',
  'traceability.config.card.performance': 'Performance Tuning',

  'traceability.config.form.enableDb': 'Record to Database',
  'traceability.config.form.enableLoki': 'Record to Loki',
  'traceability.config.alert.shareWarning':
    'The rules configured here are fully shared with the "Item Recovery System". Modifying these conditions will directly affect which items are eligible to be recorded for recovery. Please operate with caution.',

  'traceability.config.actions.trade': 'Player Trade (TRADE)',
  'traceability.config.actions.drop': 'Player Drop (DROP)',
  'traceability.config.actions.sell': 'Sell to NPC (SELL)',
  'traceability.config.actions.storageIn': 'Storage In (STORAGE_IN)',
  'traceability.config.actions.storageOut': 'Storage Out (STORAGE_OUT)',
  'traceability.config.actions.gmCreate': 'GM Create (GM_CREATE)',

  'traceability.config.tabs.equip': 'Equips',
  'traceability.config.tabs.item': 'Items',

  'traceability.config.equip.minLevel': 'Min Level',
  'traceability.config.equip.minUpgradeSlotsUsed': 'Min Upgrades Used',
  'traceability.config.equip.minGrowthLevel': 'Min Growth Level',
  'traceability.config.equip.minViciousHammerUsed': 'Min Hammer Used',
  'traceability.config.equip.minStatsAboveBase': 'Min Stats Above Base',

  'traceability.config.item.scrolls': 'Record All Scrolls',
  'traceability.config.item.skillBooks': 'Record All Skill Books',
  'traceability.config.item.masteryBooks': 'Record All Mastery Books',
  'traceability.config.item.specificItemIdsTitle':
    'Force Record Specific Item IDs',
  'traceability.config.item.specificItemIds': 'Item ID',
  'traceability.config.item.itemTypesTitle': 'Record Item Types by ID Prefix',
  'traceability.config.item.itemTypes.t': 'ID Prefix (t)',
  'traceability.config.item.itemTypes.d': 'Description (d)',

  'traceability.config.retention.valuable': 'Valuable Items',
  'traceability.config.retention.nonValuable': 'Non-Valuable Items',
  'traceability.config.retention.recordToDb': 'Record to DB',
  'traceability.config.retention.recordToLoki': 'Record to Loki',
  'traceability.config.retention.days': 'Retention Days',
  'traceability.config.retention.maxCount': 'Max Record Count',

  'traceability.config.performance.ignoredMapIdsTitle':
    'Ignored Map IDs for Tracing',
  'traceability.config.performance.ignoredMapIds': 'Map ID',
  'traceability.config.performance.ignoredMapIdsColumn': 'Map ID',

  'traceability.message.loadDefault.success':
    'Default configuration has been loaded. Please click "Save Config" to apply.',

  // Traceability Query Page
  'traceability.query.form.uid': 'Item UID',
  'traceability.query.form.itemId': 'Item ID',
  'traceability.query.form.characterId': 'Character ID',
  'traceability.query.form.actionType': 'Action Type',
  'traceability.query.form.actionSource': 'Action Source',
  'traceability.query.form.dateRange': 'Date Range',
  'traceability.query.columns.timestamp': 'Timestamp',
  'traceability.query.columns.item': 'Item',
  'traceability.query.columns.character': 'Character',
  'traceability.query.columns.map': 'Map',
  'traceability.query.columns.uid': 'Item UID',
  'traceability.query.columns.action': 'Action',
  'traceability.query.columns.actionType': 'Type',
  'traceability.query.columns.actionSource': 'Source',
  'traceability.query.columns.quantityChange': 'Quantity',
  'traceability.query.columns.targetInfo': 'Target Info',
  'traceability.query.columns.memo': 'Memo',
};
