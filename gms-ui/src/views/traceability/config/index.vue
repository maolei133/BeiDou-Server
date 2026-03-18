<template>
  <div class="container">
    <a-card :bordered="false" :title="$t('menu.traceability.config')">
      <a-skeleton v-if="loading" :animation="true">
        <a-space direction="vertical" :style="{ width: '100%' }" size="large">
          <a-skeleton-line :rows="30" />
        </a-space>
      </a-skeleton>
      <a-form v-else :model="form" layout="vertical">
        <!-- 全局控制 -->
        <a-card :title="$t('traceability.config.card.global')">
          <a-row :gutter="20">
            <a-col :span="12">
              <a-form-item :label="$t('traceability.config.form.enableDb')">
                <a-switch v-model="form.ENABLED.DATABASE" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
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
            <a-col :span="8">
              <a-form-item :label="$t('traceability.config.actions.trade')">
                <a-switch v-model="form.LOGACTIONSWITCHES.TRADE" />
              </a-form-item>
            </a-col>
            <a-col :span="8">
              <a-form-item :label="$t('traceability.config.actions.drop')">
                <a-switch v-model="form.LOGACTIONSWITCHES.DROP" />
              </a-form-item>
            </a-col>
            <a-col :span="8">
              <a-form-item :label="$t('traceability.config.actions.sell')">
                <a-switch v-model="form.LOGACTIONSWITCHES.SELL" />
              </a-form-item>
            </a-col>
            <a-col :span="8">
              <a-form-item :label="$t('traceability.config.actions.storageIn')">
                <a-switch v-model="form.LOGACTIONSWITCHES.STORAGE_IN" />
              </a-form-item>
            </a-col>
            <a-col :span="8">
              <a-form-item
                :label="$t('traceability.config.actions.storageOut')"
              >
                <a-switch v-model="form.LOGACTIONSWITCHES.STORAGE_OUT" />
              </a-form-item>
            </a-col>
            <a-col :span="8">
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
          <a-tabs>
            <a-tab-pane
              key="equip"
              :title="$t('traceability.config.tabs.equip')"
            >
              <a-row :gutter="20">
                <a-col :span="8">
                  <a-form-item
                    :label="$t('traceability.config.equip.minLevel')"
                  >
                    <a-input-number
                      v-model="form.VALUECONDITIONS.EQUIP.MINLEVEL"
                    />
                  </a-form-item>
                </a-col>
                <a-col :span="8">
                  <a-form-item
                    :label="$t('traceability.config.equip.minUpgradeSlotsUsed')"
                  >
                    <a-input-number
                      v-model="form.VALUECONDITIONS.EQUIP.MINUPGRADESLOTSUSED"
                    />
                  </a-form-item>
                </a-col>
                <a-col :span="8">
                  <a-form-item
                    :label="$t('traceability.config.equip.minGrowthLevel')"
                  >
                    <a-input-number
                      v-model="form.VALUECONDITIONS.EQUIP.MINGROWTHLEVEL"
                    />
                  </a-form-item>
                </a-col>
                <a-col :span="8">
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
                <a-col :span="8">
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
            <a-tab-pane key="item" :title="$t('traceability.config.tabs.item')">
              <a-row :gutter="20">
                <a-col :span="8">
                  <a-form-item :label="$t('traceability.config.item.scrolls')">
                    <a-switch v-model="form.VALUECONDITIONS.ITEM.SCROLLS" />
                  </a-form-item>
                </a-col>
                <a-col :span="8">
                  <a-form-item
                    :label="$t('traceability.config.item.skillBooks')"
                  >
                    <a-switch v-model="form.VALUECONDITIONS.ITEM.SKILLBOOKS" />
                  </a-form-item>
                </a-col>
                <a-col :span="8">
                  <a-form-item
                    :label="$t('traceability.config.item.masteryBooks')"
                  >
                    <a-switch
                      v-model="form.VALUECONDITIONS.ITEM.MASTERYBOOKS"
                    />
                  </a-form-item>
                </a-col>
              </a-row>
              <a-divider />
              <!-- 特定物品ID列表 -->
              <a-typography-title :heading="6">{{
                $t('traceability.config.item.specificItemIdsTitle')
              }}</a-typography-title>
              <a-table
                :columns="specificItemIdsColumns"
                :data="form.VALUECONDITIONS.ITEM.SPECIFICITEMIDS"
                :pagination="false"
              >
                <template #id="{ rowIndex }">
                  <a-input-number
                    v-model="
                      form.VALUECONDITIONS.ITEM.SPECIFICITEMIDS[rowIndex]
                    "
                  />
                </template>
                <template #operations="{ rowIndex }">
                  <a-button
                    type="primary"
                    status="danger"
                    size="mini"
                    @click="handleRemoveSpecificItemId(rowIndex)"
                    >{{ $t('common.button.delete') }}</a-button
                  >
                </template>
              </a-table>
              <a-button
                type="primary"
                style="margin-top: 10px"
                @click="handleAddSpecificItemId"
                >{{ $t('common.button.add') }}</a-button
              >

              <a-divider />
              <!-- 按ID前缀记录的物品类型 -->
              <a-typography-title :heading="6">{{
                $t('traceability.config.item.itemTypesTitle')
              }}</a-typography-title>
              <a-table
                :columns="itemTypesColumns"
                :data="form.VALUECONDITIONS.ITEM.ITEMTYPES"
                :pagination="false"
              >
                <template #t="{ rowIndex }">
                  <a-input-number
                    v-model="form.VALUECONDITIONS.ITEM.ITEMTYPES[rowIndex].T"
                  />
                </template>
                <template #d="{ rowIndex }">
                  <a-input
                    v-model="form.VALUECONDITIONS.ITEM.ITEMTYPES[rowIndex].D"
                  />
                </template>
                <template #operations="{ rowIndex }">
                  <a-button
                    type="primary"
                    status="danger"
                    size="mini"
                    @click="handleRemoveItemType(rowIndex)"
                    >{{ $t('common.button.delete') }}</a-button
                  >
                </template>
              </a-table>
              <a-button
                type="primary"
                style="margin-top: 10px"
                @click="handleAddItemType"
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
            <a-col :span="12">
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
            <a-col :span="12">
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
          >
            <template #id="{ rowIndex }">
              <a-input-number
                v-model="form.PERFORMANCE.IGNOREDMAPIDS[rowIndex]"
              />
            </template>
            <template #operations="{ rowIndex }">
              <a-button
                type="primary"
                status="danger"
                size="mini"
                @click="handleRemoveIgnoredMapId(rowIndex)"
                >{{ $t('common.button.delete') }}</a-button
              >
            </template>
          </a-table>
          <a-button
            type="primary"
            style="margin-top: 10px"
            @click="handleAddIgnoredMapId"
            >{{ $t('common.button.add') }}</a-button
          >
        </a-card>

        <!-- 操作区 -->
        <div style="margin-top: 20px; text-align: right">
          <a-button type="primary" @click="handleSave">{{
            $t('common.button.save')
          }}</a-button>
          <a-button style="margin-left: 10px" @click="handleReset">{{
            $t('common.button.resetToDefault')
          }}</a-button>
        </div>
      </a-form>
    </a-card>
  </div>
</template>

<script lang="ts" setup>
  import { ref, onMounted, computed } from 'vue';
  import { useI18n } from 'vue-i18n';
  import {
    getTraceabilityConfig,
    updateTraceabilityConfig,
    TraceabilityRules,
  } from '@/api/traceability';
  import { Message, Modal } from '@arco-design/web-vue';
  import useLoading from '@/hooks/loading';

  const { t } = useI18n();
  const { loading, setLoading } = useLoading(true);
  const form = ref<Partial<TraceabilityRules>>({
    ENABLED: {},
    LOGACTIONSWITCHES: {},
    VALUECONDITIONS: {
      EQUIP: {},
      ITEM: {
        ITEMTYPES: [],
        SPECIFICITEMIDS: [],
      },
    },
    RECORDINGTARGETS: {
      VALUABLE: {},
      NONVALUABLE: {},
    },
    RETENTION: {
      VALUABLE: {},
      NONVALUABLE: {},
    },
    PERFORMANCE: {
      IGNOREDMAPIDS: [],
    },
  });

  const itemTypesColumns = computed(() => [
    {
      title: t('traceability.config.item.itemTypes.t'),
      dataIndex: 'T',
      slotName: 't',
    },
    {
      title: t('traceability.config.item.itemTypes.d'),
      dataIndex: 'D',
      slotName: 'd',
    },
    {
      title: t('common.table.operations'),
      slotName: 'operations',
    },
  ]);

  const specificItemIdsColumns = computed(() => [
    {
      title: t('traceability.config.item.specificItemIds'),
      dataIndex: 'id',
      slotName: 'id',
    },
    {
      title: t('common.table.operations'),
      slotName: 'operations',
    },
  ]);

  const ignoredMapIdsColumns = computed(() => [
    {
      title: t('traceability.config.performance.ignoredMapIds'),
      dataIndex: 'id',
      slotName: 'id',
    },
    {
      title: t('common.table.operations'),
      slotName: 'operations',
    },
  ]);

  const handleAddItemType = () => {
    form.value.VALUECONDITIONS.ITEM.ITEMTYPES.push({ T: 0, D: '' });
  };

  const handleRemoveItemType = (index: number) => {
    form.value.VALUECONDITIONS.ITEM.ITEMTYPES.splice(index, 1);
  };

  const handleAddSpecificItemId = () => {
    form.value.VALUECONDITIONS.ITEM.SPECIFICITEMIDS.push(0);
  };

  const handleRemoveSpecificItemId = (index: number) => {
    form.value.VALUECONDITIONS.ITEM.SPECIFICITEMIDS.splice(index, 1);
  };

  const handleAddIgnoredMapId = () => {
    form.value.PERFORMANCE.IGNOREDMAPIDS.push(0);
  };

  const handleRemoveIgnoredMapId = (index: number) => {
    form.value.PERFORMANCE.IGNOREDMAPIDS.splice(index, 1);
  };

  const fetchConfig = async () => {
    setLoading(true);
    try {
      const { data } = await getTraceabilityConfig();
      form.value = data;
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    setLoading(true);
    try {
      await updateTraceabilityConfig(form.value);
      Message.success(t('common.message.save.success'));
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    Modal.confirm({
      title: t('common.modal.title.confirmReset'),
      content: t('common.modal.content.unsavedWillBeLost'),
      onOk: async () => {
        setLoading(true);
        try {
          const { data } = await getTraceabilityConfig({ useDefault: true });
          form.value = data;
          Message.info(t('traceability.config.message.loadDefault.success'));
        } finally {
          setLoading(false);
        }
      },
    });
  };

  onMounted(fetchConfig);
</script>
