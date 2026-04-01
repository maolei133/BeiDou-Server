<template>
  <div class="container">
    <a-card :bordered="false" :title="$t('menu.traceability.config')">
      <!-- 加载骨架 -->
      <a-skeleton v-if="loading" :animation="true">
        <a-space direction="vertical" :style="{ width: '100%' }" size="large">
          <a-skeleton-line :rows="30" />
        </a-space>
      </a-skeleton>

      <!-- 表单内容 -->
      <a-form v-else :model="form" layout="vertical">
        <!-- 全局控制 -->
        <a-card :title="$t('traceability.config.card.global')">
          <a-row :gutter="20">
            <a-col :xs="24" :sm="12">
              <a-form-item :label="$t('traceability.config.form.enableDb')">
                <a-switch v-model="form.ENABLED.DATABASE" />
              </a-form-item>
            </a-col>
            <a-col :xs="24" :sm="12">
              <a-form-item :label="$t('traceability.config.form.enableLoki')">
                <a-switch v-model="form.ENABLED.LOKI" />
              </a-form-item>
            </a-col>
          </a-row>
        </a-card>

        <!-- 行为开关 -->
        <a-card
          :title="$t('traceability.config.card.logActionSwitches')"
          style="margin-top: 20px"
        >
          <a-row :gutter="20">
            <a-col :xs="24" :sm="12" :md="8">
              <a-form-item :label="$t('traceability.config.actions.trade')">
                <a-switch v-model="form.LOGACTIONSWITCHES.TRADE" />
              </a-form-item>
            </a-col>
            <a-col :xs="24" :sm="12" :md="8">
              <a-form-item :label="$t('traceability.config.actions.drop')">
                <a-switch v-model="form.LOGACTIONSWITCHES.DROP" />
              </a-form-item>
            </a-col>
            <a-col :xs="24" :sm="12" :md="8">
              <a-form-item :label="$t('traceability.config.actions.sell')">
                <a-switch v-model="form.LOGACTIONSWITCHES.SELL" />
              </a-form-item>
            </a-col>
            <a-col :xs="24" :sm="12" :md="8">
              <a-form-item :label="$t('traceability.config.actions.storageIn')">
                <a-switch v-model="form.LOGACTIONSWITCHES.STORAGE_IN" />
              </a-form-item>
            </a-col>
            <a-col :xs="24" :sm="12" :md="8">
              <a-form-item
                :label="$t('traceability.config.actions.storageOut')"
              >
                <a-switch v-model="form.LOGACTIONSWITCHES.STORAGE_OUT" />
              </a-form-item>
            </a-col>
            <a-col :xs="24" :sm="12" :md="8">
              <a-form-item :label="$t('traceability.config.actions.gmCreate')">
                <a-switch v-model="form.LOGACTIONSWITCHES.GM_CREATE" />
              </a-form-item>
            </a-col>
          </a-row>
        </a-card>

        <!-- 价值判断条件 -->
        <a-card
          :title="$t('traceability.config.card.valueConditions')"
          style="margin-top: 20px"
        >
          <a-alert type="warning" style="margin-bottom: 20px">
            {{ $t('traceability.config.alert.shareWarning') }}
          </a-alert>
          <a-tabs default-active-key="equip">
            <!-- 装备价值判断 -->
            <a-tab-pane
              key="equip"
              :title="$t('traceability.config.tabs.equip')"
            >
              <a-row :gutter="20">
                <a-col :xs="24" :sm="12" :md="8">
                  <a-form-item
                    :label="$t('traceability.config.equip.minLevel')"
                  >
                    <a-input-number
                      v-model="form.VALUECONDITIONS.EQUIP.MINLEVEL"
                    />
                  </a-form-item>
                </a-col>
                <a-col :xs="24" :sm="12" :md="8">
                  <a-form-item
                    :label="$t('traceability.config.equip.minUpgradeSlotsUsed')"
                  >
                    <a-input-number
                      v-model="form.VALUECONDITIONS.EQUIP.MINUPGRADESLOTSUSED"
                    />
                  </a-form-item>
                </a-col>
                <a-col :xs="24" :sm="12" :md="8">
                  <a-form-item
                    :label="$t('traceability.config.equip.minGrowthLevel')"
                  >
                    <a-input-number
                      v-model="form.VALUECONDITIONS.EQUIP.MINGROWTHLEVEL"
                    />
                  </a-form-item>
                </a-col>
                <a-col :xs="24" :sm="12" :md="8">
                  <a-form-item
                    :label="
                      $t('traceability.config.equip.minViciousHammerUsed')
                    "
                  >
                    <a-input-number
                      v-model="form.VALUECONDITIONS.EQUIP.MINVICIOUSHAMMERUSED"
                    />
                  </a-form-item>
                </a-col>
                <a-col :xs="24" :sm="12" :md="8">
                  <a-form-item
                    :label="$t('traceability.config.equip.minStatsAboveBase')"
                  >
                    <a-input-number
                      v-model="form.VALUECONDITIONS.EQUIP.MINSTATSABOVEBASE"
                    />
                  </a-form-item>
                </a-col>
              </a-row>
            </a-tab-pane>

            <!-- 物品价值判断 -->
            <a-tab-pane key="item" :title="$t('traceability.config.tabs.item')">
              <!-- 投掷武器 -->
              <a-card
                :title="$t('traceability.config.item.throwingWeapons.title')"
                size="small"
              >
                <a-row :gutter="20">
                  <a-col :xs="24" :sm="12" :md="8">
                    <a-form-item
                      :label="
                        $t('traceability.config.item.throwingWeapons.enabled')
                      "
                    >
                      <a-switch
                        v-model="
                          form.VALUECONDITIONS.ITEM.THROWINGWEAPONS.ENABLED
                        "
                      />
                    </a-form-item>
                  </a-col>
                  <a-col :xs="24" :sm="12" :md="8">
                    <a-form-item
                      :label="
                        $t(
                          'traceability.config.item.throwingWeapons.minAttackPower'
                        )
                      "
                    >
                      <a-input-number
                        v-model="
                          form.VALUECONDITIONS.ITEM.THROWINGWEAPONS
                            .MINATTACKPOWER
                        "
                        :disabled="
                          !form.VALUECONDITIONS.ITEM.THROWINGWEAPONS.ENABLED
                        "
                      />
                    </a-form-item>
                  </a-col>
                  <a-col :xs="24" :sm="12" :md="8">
                    <a-form-item
                      :label="
                        $t(
                          'traceability.config.item.throwingWeapons.minAttackPowerBullet'
                        )
                      "
                    >
                      <a-input-number
                        v-model="
                          form.VALUECONDITIONS.ITEM.THROWINGWEAPONS
                            .MINATTACKPOWER_BULLET
                        "
                        :disabled="
                          !form.VALUECONDITIONS.ITEM.THROWINGWEAPONS.ENABLED
                        "
                      />
                    </a-form-item>
                  </a-col>
                </a-row>
              </a-card>

              <!-- 增益药水 -->
              <a-card
                :title="$t('traceability.config.item.potions.title')"
                size="small"
                style="margin-top: 16px"
              >
                <a-row :gutter="20">
                  <a-col :xs="24" :sm="12">
                    <a-form-item
                      :label="$t('traceability.config.item.potions.enabled')"
                    >
                      <a-switch
                        v-model="form.VALUECONDITIONS.ITEM.POTIONS.ENABLED"
                      />
                    </a-form-item>
                  </a-col>
                  <a-col :xs="24" :sm="12">
                    <a-form-item
                      :label="
                        $t('traceability.config.item.potions.minTotalStatBonus')
                      "
                    >
                      <a-input-number
                        v-model="
                          form.VALUECONDITIONS.ITEM.POTIONS.MINTOTALSTATBONUS
                        "
                        :disabled="!form.VALUECONDITIONS.ITEM.POTIONS.ENABLED"
                      />
                    </a-form-item>
                  </a-col>
                </a-row>
              </a-card>

              <a-divider />

              <!-- 按ID前缀记录的物品类型 -->
              <a-typography-title :heading="6">{{
                $t('traceability.config.item.itemTypesTitle')
              }}</a-typography-title>
              <a-table
                :columns="itemTypesColumns"
                :data="form.VALUECONDITIONS.ITEM.ITEMTYPES"
                :pagination="false"
                :scroll="{ x: '100%' }"
                bordered
                size="small"
              >
                <template #t="{ record }">
                  <a-input-number v-model="record.T" placeholder="e.g. 204" />
                </template>
                <template #d="{ record }">
                  <a-input
                    v-model="record.D"
                    :placeholder="$t('common.placeholder.input')"
                  />
                </template>
                <template #enabled="{ record }">
                  <a-switch v-model="record.ENABLED" />
                </template>
                <template #operations="{ record }">
                  <a-button
                    type="primary"
                    status="danger"
                    size="mini"
                    @click="handleRemoveRow('ITEMTYPES', record.key)"
                    >{{ $t('common.button.delete') }}</a-button
                  >
                </template>
              </a-table>
              <a-button
                type="dashed"
                style="width: 100%; margin-top: 10px"
                @click="handleAddItemType"
                >{{ $t('common.button.add') }}</a-button
              >

              <a-divider />

              <!-- 特定物品ID列表 -->
              <a-typography-title :heading="6">{{
                $t('traceability.config.item.specificItemIdsTitle')
              }}</a-typography-title>
              <a-table
                :columns="specificItemIdsColumns"
                :data="form.VALUECONDITIONS.ITEM.SPECIFICITEMIDS"
                :pagination="false"
                :scroll="{ x: '100%' }"
                bordered
                size="small"
              >
                <template #id="{ record }">
                  <a-input-number
                    v-model="record.ID"
                    :placeholder="
                      $t('traceability.config.item.specificItemIds.id')
                    "
                  />
                </template>
                <template #d="{ record }">
                  <a-input
                    v-model="record.D"
                    :placeholder="$t('common.placeholder.input')"
                  />
                </template>
                <template #enabled="{ record }">
                  <a-switch v-model="record.ENABLED" />
                </template>
                <template #operations="{ record }">
                  <a-button
                    type="primary"
                    status="danger"
                    size="mini"
                    @click="handleRemoveRow('SPECIFICITEMIDS', record.key)"
                    >{{ $t('common.button.delete') }}</a-button
                  >
                </template>
              </a-table>
              <a-button
                type="dashed"
                style="width: 100%; margin-top: 10px"
                @click="handleAddSpecificItemId"
                >{{ $t('common.button.add') }}</a-button
              >
            </a-tab-pane>
          </a-tabs>
        </a-card>

        <!-- 记录目标与保留期 -->
        <a-card
          :title="$t('traceability.config.card.retention')"
          style="margin-top: 20px"
        >
          <a-row :gutter="20">
            <a-col :xs="24" :md="12">
              <a-divider orientation="center">{{
                $t('traceability.config.retention.valuable')
              }}</a-divider>
              <a-form-item
                :label="$t('traceability.config.retention.recordToDb')"
              >
                <a-switch v-model="form.RECORDINGTARGETS.VALUABLE.DATABASE" />
              </a-form-item>
              <a-form-item
                :label="$t('traceability.config.retention.recordToLoki')"
              >
                <a-switch v-model="form.RECORDINGTARGETS.VALUABLE.LOKI" />
              </a-form-item>
              <a-form-item :label="$t('traceability.config.retention.days')">
                <a-input-number v-model="form.RETENTION.VALUABLE.DAYS" />
              </a-form-item>
              <a-form-item
                :label="$t('traceability.config.retention.maxCount')"
              >
                <a-input-number v-model="form.RETENTION.VALUABLE.MAXCOUNT" />
              </a-form-item>
            </a-col>
            <a-col :xs="24" :md="12">
              <a-divider orientation="center">{{
                $t('traceability.config.retention.nonValuable')
              }}</a-divider>
              <a-form-item
                :label="$t('traceability.config.retention.recordToDb')"
              >
                <a-switch
                  v-model="form.RECORDINGTARGETS.NONVALUABLE.DATABASE"
                />
              </a-form-item>
              <a-form-item
                :label="$t('traceability.config.retention.recordToLoki')"
              >
                <a-switch v-model="form.RECORDINGTARGETS.NONVALUABLE.LOKI" />
              </a-form-item>
              <a-form-item :label="$t('traceability.config.retention.days')">
                <a-input-number v-model="form.RETENTION.NONVALUABLE.DAYS" />
              </a-form-item>
              <a-form-item
                :label="$t('traceability.config.retention.maxCount')"
              >
                <a-input-number v-model="form.RETENTION.NONVALUABLE.MAXCOUNT" />
              </a-form-item>
            </a-col>
          </a-row>
        </a-card>

        <!-- 性能调优 -->
        <a-card
          :title="$t('traceability.config.card.performance')"
          style="margin-top: 20px"
        >
          <a-typography-title :heading="6">{{
            $t('traceability.config.performance.ignoredMapIdsTitle')
          }}</a-typography-title>
          <a-table
            :columns="ignoredMapIdsColumns"
            :data="form.PERFORMANCE.IGNOREDMAPIDS"
            :pagination="false"
            :scroll="{ x: '100%' }"
            bordered
            size="small"
          >
            <template #id="{ record }">
              <a-input-number
                v-model="record.ID"
                :placeholder="
                  $t('traceability.config.performance.ignoredMapIds.id')
                "
              />
            </template>
            <template #d="{ record }">
              <a-input
                v-model="record.D"
                :placeholder="$t('common.placeholder.input')"
              />
            </template>
            <template #enabled="{ record }">
              <a-switch v-model="record.ENABLED" />
            </template>
            <template #operations="{ record }">
              <a-button
                type="primary"
                status="danger"
                size="mini"
                @click="handleRemoveRow('IGNOREDMAPIDS', record.key)"
                >{{ $t('common.button.delete') }}</a-button
              >
            </template>
          </a-table>
          <a-button
            type="dashed"
            style="width: 100%; margin-top: 10px"
            @click="handleAddIgnoredMapId"
            >{{ $t('common.button.add') }}</a-button
          >
        </a-card>

        <!-- 操作区 -->
        <div style="margin-top: 20px; text-align: right">
          <a-space>
            <a-button @click="handleReset">{{
              $t('common.button.resetToDefault')
            }}</a-button>
            <a-button type="primary" @click="handleSave">{{
              $t('common.button.save')
            }}</a-button>
          </a-space>
        </div>
      </a-form>
    </a-card>
  </div>
</template>

<script lang="ts" setup>
  import { onMounted, computed, reactive } from 'vue';
  import { useI18n } from 'vue-i18n';
  import {
    getTraceabilityConfig,
    updateTraceabilityConfig,
    TraceabilityRules,
  } from '@/api/traceability';
  import { Message, Modal } from '@arco-design/web-vue';
  import useLoading from '@/hooks/loading';
  import { cloneDeep, merge } from 'lodash';

  const { t } = useI18n();
  const { loading, setLoading } = useLoading(true);

  // 返回一个结构完整的、包含所有默认值的配置对象
  const createDefaultState = (): TraceabilityRules => ({
    ENABLED: { DATABASE: false, LOKI: false },
    LOGACTIONSWITCHES: {
      TRADE: false,
      DROP: false,
      SELL: false,
      STORAGE_IN: false,
      STORAGE_OUT: false,
      GM_CREATE: false,
    },
    VALUECONDITIONS: {
      EQUIP: {
        MINLEVEL: 0,
        MINUPGRADESLOTSUSED: 0,
        MINGROWTHLEVEL: 0,
        MINVICIOUSHAMMERUSED: 0,
        MINSTATSABOVEBASE: 0,
      },
      ITEM: {
        THROWINGWEAPONS: {
          ENABLED: false,
          MINATTACKPOWER: 0,
          MINATTACKPOWER_BULLET: 0,
        },
        POTIONS: { ENABLED: false, MINTOTALSTATBONUS: 0 },
        ITEMTYPES: [],
        SPECIFICITEMIDS: [],
      },
    },
    RECORDINGTARGETS: {
      VALUABLE: { DATABASE: false, LOKI: false },
      NONVALUABLE: { DATABASE: false, LOKI: false },
    },
    RETENTION: {
      VALUABLE: { DAYS: 0, MAXCOUNT: 0 },
      NONVALUABLE: { DAYS: 0, MAXCOUNT: 0 },
    },
    PERFORMANCE: {
      IGNOREDMAPIDS: [],
    },
  });

  const form = reactive(createDefaultState());

  // 为表格行添加唯一的key，以便Vue进行高效的DOM更新
  const addKeysToLists = (data: TraceabilityRules) => {
    const clonedData = cloneDeep(data);
    clonedData.VALUECONDITIONS.ITEM.ITEMTYPES?.forEach((item) => {
      item.key = item.key || Date.now() + Math.random();
    });
    clonedData.VALUECONDITIONS.ITEM.SPECIFICITEMIDS?.forEach((item) => {
      item.key = item.key || Date.now() + Math.random();
    });
    clonedData.PERFORMANCE.IGNOREDMAPIDS?.forEach((item) => {
      item.key = item.key || Date.now() + Math.random();
    });
    return clonedData;
  };

  // 表格列定义
  const itemTypesColumns = computed(() => [
    {
      title: t('traceability.config.item.itemTypes.t'),
      dataIndex: 'T',
      slotName: 't',
      width: 120,
    },
    {
      title: t('traceability.config.item.itemTypes.d'),
      dataIndex: 'D',
      slotName: 'd',
    },
    {
      title: t('traceability.config.item.itemTypes.enabled'),
      dataIndex: 'ENABLED',
      slotName: 'enabled',
      width: 100,
      align: 'center',
    },
    {
      title: t('common.table.operations'),
      slotName: 'operations',
      width: 100,
      align: 'center',
    },
  ]);

  const specificItemIdsColumns = computed(() => [
    {
      title: t('traceability.config.item.specificItemIds.id'),
      dataIndex: 'ID',
      slotName: 'id',
      width: 120,
    },
    {
      title: t('traceability.config.item.specificItemIds.d'),
      dataIndex: 'D',
      slotName: 'd',
    },
    {
      title: t('traceability.config.item.specificItemIds.enabled'),
      dataIndex: 'ENABLED',
      slotName: 'enabled',
      width: 100,
      align: 'center',
    },
    {
      title: t('common.table.operations'),
      slotName: 'operations',
      width: 100,
      align: 'center',
    },
  ]);

  const ignoredMapIdsColumns = computed(() => [
    {
      title: t('traceability.config.performance.ignoredMapIds.id'),
      dataIndex: 'ID',
      slotName: 'id',
      width: 120,
    },
    {
      title: t('traceability.config.performance.ignoredMapIds.d'),
      dataIndex: 'D',
      slotName: 'd',
    },
    {
      title: t('traceability.config.performance.ignoredMapIds.enabled'),
      dataIndex: 'ENABLED',
      slotName: 'enabled',
      width: 100,
      align: 'center',
    },
    {
      title: t('common.table.operations'),
      slotName: 'operations',
      width: 100,
      align: 'center',
    },
  ]);

  // 添加行逻辑
  const handleAddItemType = () => {
    form.VALUECONDITIONS.ITEM.ITEMTYPES.push({
      T: 0,
      D: '',
      ENABLED: true,
      key: Date.now(),
    });
  };

  const handleAddSpecificItemId = () => {
    form.VALUECONDITIONS.ITEM.SPECIFICITEMIDS.push({
      ID: 0,
      D: '',
      ENABLED: true,
      key: Date.now(),
    });
  };

  const handleAddIgnoredMapId = () => {
    form.PERFORMANCE.IGNOREDMAPIDS.push({
      ID: 0,
      D: '',
      ENABLED: true,
      key: Date.now(),
    });
  };

  // 删除行逻辑
  type RowType = 'ITEMTYPES' | 'SPECIFICITEMIDS' | 'IGNOREDMAPIDS';
  const handleRemoveRow = (type: RowType, key: number) => {
    let targetArray;
    if (type === 'ITEMTYPES') targetArray = form.VALUECONDITIONS.ITEM.ITEMTYPES;
    else if (type === 'SPECIFICITEMIDS')
      targetArray = form.VALUECONDITIONS.ITEM.SPECIFICITEMIDS;
    else targetArray = form.PERFORMANCE.IGNOREDMAPIDS;

    const index = targetArray.findIndex((item: any) => item.key === key);
    if (index !== -1) targetArray.splice(index, 1);
  };

  // 更新表单数据
  const updateForm = (data: Partial<TraceabilityRules>) => {
    const defaults = createDefaultState();
    const merged = merge(defaults, data);
    const finalState = addKeysToLists(merged);
    Object.assign(form, finalState);
  };

  // 从API获取配置
  const fetchConfig = async () => {
    setLoading(true);
    try {
      const { data } = await getTraceabilityConfig();
      updateForm(data);
    } finally {
      setLoading(false);
    }
  };

  // 保存配置
  const handleSave = async () => {
    setLoading(true);
    try {
      const configToSave = cloneDeep(form);
      configToSave.VALUECONDITIONS.ITEM.ITEMTYPES?.forEach((e: any) => {
        delete e.key;
      });
      configToSave.VALUECONDITIONS.ITEM.SPECIFICITEMIDS?.forEach((e: any) => {
        delete e.key;
      });
      configToSave.PERFORMANCE.IGNOREDMAPIDS?.forEach((e: any) => {
        delete e.key;
      });

      await updateTraceabilityConfig(configToSave);
      Message.success(t('common.message.save.success'));
      await fetchConfig();
    } finally {
      setLoading(false);
    }
  };

  // 恢复默认配置
  const handleReset = () => {
    Modal.confirm({
      title: t('common.modal.title.confirmReset'),
      content: t('common.modal.content.unsavedWillBeLost'),
      onOk: async () => {
        setLoading(true);
        try {
          const { data } = await getTraceabilityConfig({ useDefault: true });
          updateForm(data);
          Message.info(t('traceability.message.loadDefault.success'));
        } finally {
          setLoading(false);
        }
      },
    });
  };

  onMounted(fetchConfig);
</script>
