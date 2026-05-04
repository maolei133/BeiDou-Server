export default {
  // 通用
  'common.button.search': '查询',
  'common.button.view': '查看',
  'common.button.save': '保存配置',
  'common.button.resetToDefault': '恢复默认',
  'common.button.add': '新增',
  'common.button.delete': '删除',
  'common.table.operations': '操作',
  'common.message.save.success': '配置保存成功',
  'common.modal.title.confirmReset': '确认恢复默认配置？',
  'common.modal.content.unsavedWillBeLost':
    '您当前所做的所有未保存修改都将丢失。',
  'common.placeholder.select': '请选择',
  'common.placeholder.input': '请输入',

  // 溯源看板页面
  'traceability.dashboard.stats.totalRecords': '数据库记录总数',
  'traceability.dashboard.stats.todayAdded': '今日新增',
  'traceability.dashboard.stats.avgPerHour': '平均每小时记录数',
  'traceability.dashboard.stats.dbTableSizeMB': '数据库表大小',

  // 溯源配置页面
  'traceability.config.card.global': '全局控制',
  'traceability.config.card.logActionSwitches': '行为开关',
  'traceability.config.card.valueConditions': '价值判断条件',
  'traceability.config.card.retention': '记录目标与保留期',
  'traceability.config.card.performance': '性能调优',

  'traceability.config.form.enableDb': '记录到数据库',
  'traceability.config.form.enableLoki': '记录到Loki日志',
  'traceability.config.alert.shareWarning':
    '此处的配置规则与“物品找回系统”完全共享。修改这里的条件会直接影响到哪些物品有资格被记录用于找回。请谨慎操作。',

  'traceability.config.actions.trade': '玩家交易 (TRADE)',
  'traceability.config.actions.drop': '玩家丢弃 (DROP)',
  'traceability.config.actions.sell': '出售给NPC (SELL)',
  'traceability.config.actions.storageIn': '存入仓库 (STORAGE_IN)',
  'traceability.config.actions.storageOut': '取出仓库 (STORAGE_OUT)',
  'traceability.config.actions.gmCreate': 'GM创造 (GM_CREATE)',

  'traceability.config.tabs.equip': '装备类',
  'traceability.config.tabs.item': '道具类',

  'traceability.config.equip.minLevel': '最低穿戴等级',
  'traceability.config.equip.minUpgradeSlotsUsed': '最低已砸卷次数',
  'traceability.config.equip.minGrowthLevel': '最低成长等级',
  'traceability.config.equip.minViciousHammerUsed': '最低金锤子次数',
  'traceability.config.equip.minStatsAboveBase': '属性总和超白板值',

  'traceability.config.item.throwingWeapons.title': '投掷武器',
  'traceability.config.item.throwingWeapons.enabled': '启用投掷武器判断',
  'traceability.config.item.throwingWeapons.minAttackPower': '飞镖最低攻击力',
  'traceability.config.item.throwingWeapons.minAttackPowerBullet':
    '子弹最低攻击力',

  'traceability.config.item.potions.title': '增益药水',
  'traceability.config.item.potions.enabled': '启用增益药水判断',
  'traceability.config.item.potions.minTotalStatBonus': '最低总属性加成',

  'traceability.config.item.itemTypesTitle': '按ID前缀记录的物品类型',
  'traceability.config.item.itemTypes.t': 'ID前缀',
  'traceability.config.item.itemTypes.d': '描述',
  'traceability.config.item.itemTypes.enabled': '启用',

  'traceability.config.item.specificItemIdsTitle': '强制记录的特定物品ID',
  'traceability.config.item.specificItemIds.id': '物品ID',
  'traceability.config.item.specificItemIds.d': '描述',
  'traceability.config.item.specificItemIds.enabled': '启用',

  'traceability.config.retention.valuable': '有价值物品',
  'traceability.config.retention.nonValuable': '无价值物品',
  'traceability.config.retention.recordToDb': '记录到数据库',
  'traceability.config.retention.recordToLoki': '记录到Loki',
  'traceability.config.retention.days': '保留天数',
  'traceability.config.retention.maxCount': '最大条数',

  'traceability.config.performance.ignoredMapIdsTitle': '忽略溯源记录的地图',
  'traceability.config.performance.ignoredMapIds.id': '地图ID',
  'traceability.config.performance.ignoredMapIds.d': '描述',
  'traceability.config.performance.ignoredMapIds.enabled': '启用',

  'traceability.message.loadDefault.success':
    '已加载默认配置，请点击“保存配置”以生效。',

  // 溯源查询页面
  'traceability.query.form.uid': '物品UID',
  'traceability.query.form.itemId': '物品ID',
  'traceability.query.form.characterId': '角色ID',
  'traceability.query.form.actionType': '行为类型',
  'traceability.query.form.actionSource': '行为来源',
  'traceability.query.form.dateRange': '日期范围',
  'traceability.query.columns.timestamp': '时间',
  'traceability.query.columns.item': '物品',
  'traceability.query.columns.character': '角色',
  'traceability.query.columns.map': '地图',
  'traceability.query.columns.uid': '物品UID',
  'traceability.query.columns.action': '行为',
  'traceability.query.columns.actionType': '类型',
  'traceability.query.columns.actionSource': '来源',
  'traceability.query.columns.quantityChange': '数量',
  'traceability.query.columns.targetInfo': '交互对象',
  'traceability.query.columns.memo': '备注',
};
