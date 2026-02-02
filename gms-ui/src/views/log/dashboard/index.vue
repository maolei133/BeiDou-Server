<template>
  <div class="container">
    <Breadcrumb :items="['menu.log', 'menu.log.dashboard']" />

    <!-- 1. 系统状态区域 -->
    <a-card class="general-card" :title="$t('log.dashboard.status.title')">
      <a-row :gutter="16">
        <a-col :span="12">
          <div class="stat-card">
            <div class="stat-label">Loki</div>
            <div
              class="stat-content"
              :class="{ active: status.loki, loading: initialLoading }"
            >
              <template v-if="initialLoading">
                <icon-loading class="stat-icon spin" />
                <span class="stat-value">{{ $t('common.loading') }}</span>
              </template>
              <template v-else>
                <icon-check-circle v-if="status.loki" class="stat-icon" />
                <icon-close-circle v-else class="stat-icon" />
                <span class="stat-value">
                  {{
                    status.loki
                      ? $t('log.dashboard.status.running')
                      : $t('log.dashboard.status.stopped')
                  }}
                </span>
                <span v-if="status.loki" class="stat-uptime">
                  ({{ formatUptime(status.loki) }})
                </span>
              </template>
            </div>
          </div>
        </a-col>
        <a-col :span="12">
          <div class="stat-card">
            <div class="stat-label">Promtail</div>
            <div
              class="stat-content"
              :class="{ active: status.promtail, loading: initialLoading }"
            >
              <template v-if="initialLoading">
                <icon-loading class="stat-icon spin" />
                <span class="stat-value">{{ $t('common.loading') }}</span>
              </template>
              <template v-else>
                <icon-check-circle v-if="status.promtail" class="stat-icon" />
                <icon-close-circle v-else class="stat-icon" />
                <span class="stat-value">
                  {{
                    status.promtail
                      ? $t('log.dashboard.status.running')
                      : $t('log.dashboard.status.stopped')
                  }}
                </span>
                <span v-if="status.promtail" class="stat-uptime">
                  ({{ formatUptime(status.promtail) }})
                </span>
              </template>
            </div>
          </div>
        </a-col>
      </a-row>
      <a-divider />
      <a-space>
        <a-button type="primary" :loading="loading" @click="handleStart">
          <template #icon><icon-play-arrow /></template>
          {{ $t('log.dashboard.action.start') }}
        </a-button>
        <a-button
          type="primary"
          status="danger"
          :loading="loading"
          @click="handleStop"
        >
          <template #icon><icon-stop /></template>
          {{ $t('log.dashboard.action.stop') }}
        </a-button>
        <a-button :loading="loading" @click="handleRestart">
          <template #icon><icon-refresh /></template>
          {{ $t('log.dashboard.action.restart') }}
        </a-button>
        <a-button :loading="loading" @click="handleReset">
          <template #icon><icon-eraser /></template>
          {{ $t('log.dashboard.action.reset') }}
        </a-button>
        <a-button @click="fetchStatus">
          <template #icon><icon-sync /></template>
          {{ $t('log.dashboard.action.refresh') }}
        </a-button>
        <a-button @click="resetToDefault">
          <template #icon><icon-undo /></template>
          {{ $t('log.dashboard.action.resetDefault') }}
        </a-button>
      </a-space>
    </a-card>

    <!-- 2. 自定义仪表盘区域 -->
    <div class="dashboard-header">
      <div class="dashboard-title">{{ $t('log.dashboard.custom.title') }}</div>
      <a-space>
        <a-button type="primary" size="small" @click="openAddModal">
          <template #icon><icon-plus /></template>
          {{ $t('log.dashboard.custom.add') }}
        </a-button>
        <a-button size="small" :loading="savingLayout" @click="saveLayout">
          <template #icon><icon-save /></template>
          {{ $t('log.dashboard.custom.save') }}
        </a-button>
      </a-space>
    </div>

    <!-- 拖拽排序区域 -->
    <div ref="sortableRef" class="chart-grid-container">
      <a-row :gutter="16" class="chart-grid">
        <a-col
          v-for="(chart, index) in charts"
          :key="chart.id"
          :span="chart.width"
          class="sortable-item"
          :data-id="chart.id"
        >
          <LogChart
            :id="chart.id"
            v-model:title="chart.title"
            v-model:height="chart.height"
            v-model:width="chart.width"
            :type="chart.type"
            :query="chart.query"
            :range="chart.range"
            @remove="removeChart(index)"
            @config="openEditModal(index)"
          />
        </a-col>
      </a-row>
    </div>

    <!-- 添加/编辑图表弹窗 -->
    <a-modal
      v-model:visible="showAddModal"
      :title="
        isEditMode
          ? $t('log.dashboard.custom.modal.edit')
          : $t('log.dashboard.custom.modal.title')
      "
      width="600px"
      :top="50"
      @ok="handleSaveChart"
    >
      <a-form :model="addForm" layout="vertical" size="small">
        <a-row :gutter="16">
          <a-col :span="16">
            <a-form-item
              :label="$t('log.dashboard.custom.form.title')"
              field="title"
            >
              <a-input
                v-model="addForm.title"
                :placeholder="$t('log.dashboard.custom.form.title.placeholder')"
              />
            </a-form-item>
          </a-col>
          <a-col :span="8">
            <a-form-item
              :label="$t('log.dashboard.custom.form.type')"
              field="type"
            >
              <a-select v-model="addForm.type">
                <a-option value="line">
                  {{ $t('log.dashboard.custom.form.type.line') }}
                </a-option>
                <a-option value="bar">
                  {{ $t('log.dashboard.custom.form.type.bar') }}
                </a-option>
                <a-option value="pie">
                  {{ $t('log.dashboard.custom.form.type.pie') }}
                </a-option>
                <a-option value="scatter">
                  {{ $t('log.dashboard.custom.form.type.scatter') }}
                </a-option>
                <a-option value="area">
                  {{ $t('log.dashboard.custom.form.type.area') }}
                </a-option>
                <a-option value="radar">
                  {{ $t('log.dashboard.custom.form.type.radar') }}
                </a-option>
                <a-option value="funnel">
                  {{ $t('log.dashboard.custom.form.type.funnel') }}
                </a-option>
                <a-option value="gauge">
                  {{ $t('log.dashboard.custom.form.type.gauge') }}
                </a-option>
                <a-option value="heatmap">
                  {{ $t('log.dashboard.custom.form.type.heatmap') }}
                </a-option>
                <a-option value="candlestick">
                  {{ $t('log.dashboard.custom.form.type.candlestick') }}
                </a-option>
              </a-select>
            </a-form-item>
          </a-col>
        </a-row>

        <a-divider orientation="left" style="margin: 10px 0">
          {{ $t('log.dashboard.custom.builder.title') }}
        </a-divider>

        <!-- 增强版可视化构建器 -->
        <div class="query-builder">
          <a-row :gutter="16">
            <a-col :span="8">
              <a-form-item :label="$t('log.dashboard.custom.form.logSource')">
                <a-select v-model="queryBuilder.logSource" @change="buildQuery">
                  <a-option value="gms-audit">{{
                    $t('log.dashboard.builder.source.audit')
                  }}</a-option>
                  <a-option value="gms-server">{{
                    $t('log.dashboard.builder.source.server')
                  }}</a-option>
                  <a-option value="gms-error">{{
                    $t('log.dashboard.builder.source.error')
                  }}</a-option>
                  <a-option value="gms-chat">{{
                    $t('log.dashboard.builder.source.chat')
                  }}</a-option>
                  <a-option value="gms-packet">{{
                    $t('log.dashboard.builder.source.packet')
                  }}</a-option>
                </a-select>
              </a-form-item>
            </a-col>
            <a-col :span="8">
              <a-form-item :label="$t('log.dashboard.custom.form.range')">
                <a-select v-model="addForm.range" @change="buildQuery">
                  <a-option value="1h">1h</a-option>
                  <a-option value="6h">6h</a-option>
                  <a-option value="12h">12h</a-option>
                  <a-option value="24h">24h (1d)</a-option>
                  <a-option value="168h">168h (7d)</a-option>
                  <a-option value="720h">720h (30d)</a-option>
                </a-select>
              </a-form-item>
            </a-col>
            <a-col :span="8">
              <a-form-item
                :label="$t('log.dashboard.custom.form.interval')"
                field="interval"
              >
                <a-select v-model="queryBuilder.interval" @change="buildQuery">
                  <a-option value="1m">1m</a-option>
                  <a-option value="5m">5m</a-option>
                  <a-option value="10m">10m</a-option>
                  <a-option value="30m">30m</a-option>
                  <a-option value="1h">1h</a-option>
                  <a-option value="6h">6h</a-option>
                  <a-option value="12h">12h</a-option>
                  <a-option value="24h">24h (1d)</a-option>
                  <a-option value="168h">168h (7d)</a-option>
                  <a-option value="720h">720h (30d)</a-option>
                </a-select>
              </a-form-item>
            </a-col>
          </a-row>

          <a-row :gutter="16">
            <a-col :span="8">
              <a-form-item :label="$t('log.dashboard.custom.form.filterKey')">
                <a-select
                  v-model="queryBuilder.filterKey"
                  placeholder="选择字段"
                  @change="handleFilterKeyChange"
                >
                  <a-option value="">{{
                    $t('log.dashboard.builder.filterKey.none')
                  }}</a-option>
                  <a-option value="mod">{{
                    $t('log.dashboard.builder.filterKey.mod')
                  }}</a-option>
                  <a-option value="act">{{
                    $t('log.dashboard.builder.filterKey.act')
                  }}</a-option>
                  <a-option value="acc">{{
                    $t('log.dashboard.builder.filterKey.acc')
                  }}</a-option>
                  <a-option value="chr">{{
                    $t('log.dashboard.builder.filterKey.chr')
                  }}</a-option>
                  <a-option value="map">{{
                    $t('log.dashboard.builder.filterKey.map')
                  }}</a-option>
                  <a-option value="itm">{{
                    $t('log.dashboard.builder.filterKey.itm')
                  }}</a-option>
                </a-select>
              </a-form-item>
            </a-col>
            <a-col :span="16">
              <a-form-item :label="$t('log.dashboard.custom.form.filterValue')">
                <a-select
                  v-if="
                    queryBuilder.filterKey === 'mod' ||
                    queryBuilder.filterKey === 'act'
                  "
                  v-model="queryBuilder.filterValue"
                  allow-search
                  allow-clear
                  placeholder="选择或搜索"
                  @search="handleSearch"
                  @focus="handleSearch('')"
                  @change="buildQuery"
                >
                  <a-option
                    v-for="item in autoCompleteData"
                    :key="item.value"
                    :value="item.value"
                  >
                    {{ item.label }}
                  </a-option>
                </a-select>
                <a-auto-complete
                  v-else
                  v-model="queryBuilder.filterValue"
                  :data="autoCompleteData.map((i) => i.value)"
                  placeholder="输入值 (支持自动搜索)"
                  allow-clear
                  @search="handleSearch"
                  @focus="handleSearch(queryBuilder.filterValue)"
                  @change="buildQuery"
                />
              </a-form-item>
            </a-col>
          </a-row>

          <a-row :gutter="16">
            <a-col :span="8">
              <a-form-item
                :label="$t('log.dashboard.custom.form.metric')"
                field="metric"
              >
                <a-select v-model="queryBuilder.metric" @change="buildQuery">
                  <a-option value="count">{{
                    $t('log.dashboard.builder.metric.count')
                  }}</a-option>
                  <a-option value="sum">{{
                    $t('log.dashboard.builder.metric.sum')
                  }}</a-option>
                  <a-option value="avg">{{
                    $t('log.dashboard.builder.metric.avg')
                  }}</a-option>
                  <a-option value="max">{{
                    $t('log.dashboard.builder.metric.max')
                  }}</a-option>
                  <a-option value="min">{{
                    $t('log.dashboard.builder.metric.min')
                  }}</a-option>
                </a-select>
              </a-form-item>
            </a-col>
            <a-col :span="8">
              <a-form-item
                :label="$t('log.dashboard.custom.form.field')"
                field="field"
              >
                <a-select
                  v-model="queryBuilder.field"
                  :disabled="queryBuilder.metric === 'count'"
                  placeholder="选择数值字段"
                  allow-create
                  @change="buildQuery"
                >
                  <a-option value="cnt">{{
                    $t('log.dashboard.builder.field.cnt')
                  }}</a-option>
                  <a-option value="cost">{{
                    $t('log.dashboard.builder.field.cost')
                  }}</a-option>
                  <a-option value="meso">{{
                    $t('log.dashboard.builder.field.meso')
                  }}</a-option>
                  <a-option value="exp">{{
                    $t('log.dashboard.builder.field.exp')
                  }}</a-option>
                  <a-option value="hp">{{
                    $t('log.dashboard.builder.field.hp')
                  }}</a-option>
                  <a-option value="mp">{{
                    $t('log.dashboard.builder.field.mp')
                  }}</a-option>
                </a-select>
              </a-form-item>
            </a-col>
            <a-col :span="8">
              <a-form-item
                :label="$t('log.dashboard.custom.form.dimension')"
                field="dimension"
              >
                <a-select v-model="queryBuilder.dimension" @change="buildQuery">
                  <a-option value="none">{{
                    $t('log.dashboard.builder.dimension.none')
                  }}</a-option>
                  <a-option value="mod">{{
                    $t('log.dashboard.builder.dimension.mod')
                  }}</a-option>
                  <a-option value="act">{{
                    $t('log.dashboard.builder.dimension.act')
                  }}</a-option>
                  <a-option value="jobName">{{
                    $t('log.dashboard.builder.dimension.job')
                  }}</a-option>
                  <a-option value="mapName">{{
                    $t('log.dashboard.builder.dimension.map')
                  }}</a-option>
                  <a-option value="acc">{{
                    $t('log.dashboard.builder.dimension.acc')
                  }}</a-option>
                  <a-option value="chr">{{
                    $t('log.dashboard.builder.dimension.chr')
                  }}</a-option>
                </a-select>
              </a-form-item>
            </a-col>
          </a-row>

          <a-row :gutter="16">
            <a-col :span="8">
              <a-form-item :label="$t('log.dashboard.custom.form.topk')">
                <a-input-number
                  v-model="queryBuilder.topk"
                  :min="0"
                  :max="100"
                  placeholder="0 表示不限制"
                  @change="buildQuery"
                />
              </a-form-item>
            </a-col>
          </a-row>
        </div>

        <a-form-item
          :label="$t('log.dashboard.custom.form.query')"
          field="query"
        >
          <a-textarea
            v-model="addForm.query"
            :placeholder="$t('log.dashboard.custom.form.query.placeholder')"
            :auto-size="{ minRows: 2, maxRows: 4 }"
            style="resize: vertical"
          />
          <template #help>
            {{ $t('log.dashboard.custom.form.query.help') }}
          </template>
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
  import { ref, onMounted, onUnmounted, reactive, nextTick } from 'vue';
  import { useI18n } from 'vue-i18n';
  import {
    getProcessStatus,
    startProcess,
    stopProcess,
    restartProcess,
    resetProcess,
    ProcessStatus,
    readConfigFile,
    saveConfigFile,
    searchLogs,
  } from '@/api/log';
  import { Message, Modal } from '@arco-design/web-vue';
  import dayjs from 'dayjs';
  import Sortable from 'sortablejs';
  import LogChart from './LogChart.vue';

  const { t, te, messages, locale } = useI18n();

  // --- Status Logic ---
  const loading = ref(false);
  const initialLoading = ref(true);
  const status = ref<ProcessStatus>({ loki: null, promtail: null });
  let timer: any = null;
  const now = ref(Date.now());

  const fetchStatus = async () => {
    try {
      const { data } = await getProcessStatus();
      status.value = data;
    } catch (err) {
      // ignore
    } finally {
      initialLoading.value = false;
    }
  };

  const formatUptime = (timestamp: number | null) => {
    if (!timestamp) return '';
    const start = dayjs(timestamp);
    if (!start.isValid()) return '';
    const diff = dayjs(now.value).diff(start, 'second');
    if (diff < 60) return `${diff}s`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ${diff % 60}s`;
    const hours = Math.floor(diff / 3600);
    const minutes = Math.floor((diff % 3600) / 60);
    return `${hours}h ${minutes}m`;
  };

  const handleStart = async () => {
    loading.value = true;
    try {
      await startProcess();
      Message.success(t('log.dashboard.message.start'));
      setTimeout(fetchStatus, 3000);
    } finally {
      loading.value = false;
    }
  };

  const handleStop = () => {
    Modal.warning({
      title: t('log.dashboard.action.stop'),
      content: t('log.dashboard.confirm.stop'),
      onOk: async () => {
        loading.value = true;
        try {
          await stopProcess();
          Message.success(t('log.dashboard.message.stop'));
          setTimeout(fetchStatus, 2000);
        } finally {
          loading.value = false;
        }
      },
    });
  };

  const handleRestart = () => {
    Modal.warning({
      title: t('log.dashboard.action.restart'),
      content: t('log.dashboard.confirm.restart'),
      onOk: async () => {
        loading.value = true;
        try {
          await restartProcess();
          Message.success(t('log.dashboard.message.restart'));
          setTimeout(fetchStatus, 5000);
        } finally {
          loading.value = false;
        }
      },
    });
  };

  const handleReset = () => {
    Modal.warning({
      title: t('log.dashboard.action.reset'),
      content: t('log.dashboard.confirm.reset'),
      onOk: async () => {
        loading.value = true;
        try {
          await resetProcess();
          Message.success(t('log.dashboard.message.reset'));
          setTimeout(fetchStatus, 5000);
        } finally {
          loading.value = false;
        }
      },
    });
  };

  // --- Dashboard Logic ---
  interface ChartConfig {
    id: string;
    title: string;
    type:
      | 'line'
      | 'bar'
      | 'pie'
      | 'scatter'
      | 'area'
      | 'radar'
      | 'funnel'
      | 'gauge'
      | 'heatmap'
      | 'candlestick';
    query: string;
    width: number;
    height: number;
    range?: string;
  }

  const charts = ref<ChartConfig[]>([]);
  const savingLayout = ref(false);
  const showAddModal = ref(false);
  const isEditMode = ref(false);
  const editingIndex = ref(-1);

  const addForm = reactive({
    title: '',
    type: 'line',
    query: '',
    width: 12,
    height: 300,
    range: '24h',
  });

  // Query Builder State
  const queryBuilder = reactive({
    metric: 'count',
    field: '', // for sum/avg
    dimension: 'none',
    interval: '1m',
    filterKey: '',
    filterValue: '',
    topk: 0,
    logSource: 'gms-audit',
  });

  // 修改 autoCompleteData 类型以支持 label/value
  const autoCompleteData = ref<{ label: string; value: string }[]>([]);

  // 自动填充搜索
  const handleSearch = async (value: string) => {
    if (!queryBuilder.filterKey) {
      autoCompleteData.value = [];
      return;
    }
    let type = '';
    if (queryBuilder.filterKey === 'acc') type = 'account';
    if (queryBuilder.filterKey === 'chr') type = 'character';
    if (queryBuilder.filterKey === 'ip') type = 'ip';
    if (queryBuilder.filterKey === 'hwid') type = 'hwid';
    if (queryBuilder.filterKey === 'mac') type = 'mac';
    if (queryBuilder.filterKey === 'mod') type = 'module';
    if (queryBuilder.filterKey === 'act') type = 'action';

    if (!type) return;

    // 如果是模块或动作，使用预定义列表
    if (type === 'module') {
      const modules = [
        'SYSTEM',
        'LOGIN',
        'CHARACTER',
        'ITEM',
        'SHOP',
        'TRADE',
        'PARTY',
        'GUILD',
        'FAMILY',
        'QUEST',
        'FIELD',
        'SCRIPT',
        'CASH_SHOP',
        'EVENT',
        'AUTOBAN',
        'PLUGIN',
      ];
      const keyword = (value || '').toLowerCase();
      autoCompleteData.value = modules
        .map((m) => {
          const key = `log.module.${m}`;
          // 优先使用 messages 直接查找，解决扁平键名问题
          const msgs = messages.value[locale.value];
          let label = m;
          if (msgs && msgs[key]) {
            label = msgs[key];
          } else if (te(key)) {
            label = t(key);
          }
          return {
            label,
            value: m,
          };
        })
        .filter(
          (item) =>
            item.value.toLowerCase().includes(keyword) ||
            item.label.toLowerCase().includes(keyword)
        );
      return;
    }

    if (type === 'action') {
      // 仅列出部分常用动作，完整列表太长
      const actions = [
        'LOGIN_SUCCESS',
        'LOGIN_FAIL',
        'LOGOUT',
        'LEVEL_UP',
        'DIE',
        'REVIVE',
        'ITEM_GAIN',
        'ITEM_LOST',
        'ITEM_USE',
        'SHOP_BUY',
        'SHOP_SELL',
        'TRADE_COMPLETE',
        'CHEAT_DETECTED',
      ];
      const keyword = (value || '').toLowerCase();
      autoCompleteData.value = actions
        .map((a) => {
          const key = `log.action.${a}`;
          // 优先使用 messages 直接查找，解决扁平键名问题
          const msgs = messages.value[locale.value];
          let label = a;
          if (msgs && msgs[key]) {
            label = msgs[key];
          } else if (te(key)) {
            label = t(key);
          }
          return {
            label,
            value: a,
          };
        })
        .filter(
          (item) =>
            item.value.toLowerCase().includes(keyword) ||
            item.label.toLowerCase().includes(keyword)
        );
      return;
    }

    try {
      const { data } = await searchLogs(type, value || '');
      // 后端返回的是字符串数组，转换为对象数组
      autoCompleteData.value = (data as string[]).map((item) => ({
        label: item,
        value: item,
      }));
    } catch (err) {
      // ignore
    }
  };

  const buildQuery = () => {
    let selector = `{job="${queryBuilder.logSource}"`;
    if (queryBuilder.filterKey && queryBuilder.filterValue) {
      selector += `, ${queryBuilder.filterKey}="${queryBuilder.filterValue}"`;
    }
    selector += '}';

    let rangeVector = '';
    if (queryBuilder.metric === 'count') {
      rangeVector = `${selector}[${queryBuilder.interval}]`;
    } else {
      if (!queryBuilder.field) return;
      rangeVector = `(${selector} | unwrap ${queryBuilder.field} | __error__="")[${queryBuilder.interval}]`;
    }

    let func = '';
    switch (queryBuilder.metric) {
      case 'count':
        func = `count_over_time(${rangeVector})`;
        break;
      case 'sum':
        func = `sum_over_time(${rangeVector})`;
        break;
      case 'avg':
        func = `avg_over_time(${rangeVector})`;
        break;
      case 'max':
        func = `max_over_time(${rangeVector})`;
        break;
      case 'min':
        func = `min_over_time(${rangeVector})`;
        break;
      default:
        func = `count_over_time(${rangeVector})`;
    }

    let q = '';
    if (queryBuilder.dimension !== 'none') {
      q = `sum by (${queryBuilder.dimension}) (${func})`;
      // TopK Logic
      if (queryBuilder.topk > 0) {
        q = `topk(${queryBuilder.topk}, ${q})`;
      }
    } else {
      q = `sum(${func})`;
    }

    addForm.query = q;
  };

  const handleFilterKeyChange = () => {
    // 当切换过滤键时，清空过滤值
    queryBuilder.filterValue = '';
    autoCompleteData.value = [];
    buildQuery();

    // 如果切换到 mod 或 act，自动加载列表
    if (queryBuilder.filterKey === 'mod' || queryBuilder.filterKey === 'act') {
      handleSearch('');
    }
  };

  // 默认预置图表
  const getDefaultCharts = (): ChartConfig[] => [
    {
      id: '1',
      title: '登录活跃度 (Login Activity)',
      type: 'line',
      query:
        'sum by (act) (count_over_time({job="gms-audit", mod="LOGIN"}[1h]))',
      width: 12,
      height: 300,
      range: '24h',
    },
    {
      id: '2',
      title: '商城消费热度 (Cash Shop Sales)',
      type: 'pie',
      query:
        'sum by (act) (count_over_time({job="gms-audit", mod="CASH_SHOP"}[1h]))',
      width: 12,
      height: 300,
      range: '24h',
    },
    {
      id: '3',
      title: '商店交易活跃度 (Shop Activity)',
      type: 'bar',
      query:
        'sum by (act) (count_over_time({job="gms-audit", mod="SHOP"}[1h]))',
      width: 12,
      height: 300,
      range: '24h',
    },
    {
      id: '4',
      title: '职业分布 (Job Distribution)',
      type: 'pie',
      query:
        'sum by (jobName) (count_over_time({job="gms-audit", mod="LOGIN", act="LOGIN_SUCCESS"}[24h]))',
      width: 12,
      height: 300,
      range: '24h',
    },
    {
      id: '5',
      title: '热门地图 Top 10 (Map Popularity)',
      type: 'bar',
      query:
        'topk(10, sum by (mapName) (count_over_time({job="gms-audit", mod="FIELD", act="CHANGE_MAP"}[1h])))',
      width: 24,
      height: 350,
      range: '24h',
    },
    {
      id: '6',
      title: '作弊检测告警 (Cheat Detection)',
      type: 'bar',
      query:
        'sum by (act) (count_over_time({job="gms-audit", mod="AUTOBAN"}[1h]))',
      width: 12,
      height: 300,
      range: '24h',
    },
    {
      id: '7',
      title: '系统错误监控 (System Errors)',
      type: 'line',
      query: 'count_over_time({job="gms-audit", level="ERROR"}[1m])',
      width: 12,
      height: 300,
      range: '24h',
    },
    {
      id: '8',
      title: '组队活跃度 (Party Activity)',
      type: 'line',
      query:
        'sum by (act) (count_over_time({job="gms-audit", mod="PARTY"}[1h]))',
      width: 12,
      height: 300,
      range: '24h',
    },
    {
      id: '9',
      title: '公会活动 (Guild Activity)',
      type: 'bar',
      query:
        'sum by (act) (count_over_time({job="gms-audit", mod="GUILD"}[1h]))',
      width: 12,
      height: 300,
      range: '24h',
    },
    {
      id: '10',
      title: '任务完成情况 (Quest Completion)',
      type: 'pie',
      query:
        'sum by (act) (count_over_time({job="gms-audit", mod="QUEST"}[24h]))',
      width: 12,
      height: 300,
      range: '24h',
    },
    {
      id: '11',
      title: '物品交易量 (Trade Volume)',
      type: 'line',
      query:
        'sum by (act) (count_over_time({job="gms-audit", mod="TRADE"}[1h]))',
      width: 12,
      height: 300,
      range: '24h',
    },
  ];

  const saveLayout = async () => {
    savingLayout.value = true;
    try {
      // 显式深拷贝，确保序列化纯数据
      const dataToSave = JSON.parse(JSON.stringify(charts.value));
      // eslint-disable-next-line no-console
      console.log('Saving layout data:', dataToSave);

      await saveConfigFile('dashboard-layout.json', JSON.stringify(dataToSave));
      Message.success(t('log.dashboard.custom.message.save.success'));
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('Save layout failed:', err);
      Message.error(t('log.dashboard.custom.message.save.fail'));
    } finally {
      savingLayout.value = false;
    }
  };

  const loadLayout = async () => {
    try {
      const { data } = await readConfigFile('dashboard-layout.json');
      if (data) {
        let parsed = typeof data === 'string' ? JSON.parse(data) : data;

        // 兼容处理：如果文件内容被错误地包装了（例如包含 requestId 和 data 字段）
        if (parsed && !Array.isArray(parsed) && parsed.data) {
          // 如果 data 字段是字符串（被二次序列化了），尝试解析它
          if (typeof parsed.data === 'string') {
            try {
              parsed = JSON.parse(parsed.data);
            } catch (e) {
              parsed = parsed.data;
            }
          } else {
            parsed = parsed.data;
          }
        }

        // 再次检查是否为字符串（处理可能的双重序列化）
        if (typeof parsed === 'string') {
          try {
            parsed = JSON.parse(parsed);
          } catch (e) {
            // ignore
          }
        }

        if (Array.isArray(parsed)) {
          charts.value = parsed;
          charts.value.forEach((c) => {
            if (!c.height) c.height = 300;
          });
        } else {
          // 如果解析结果不是数组，回退到默认图表
          charts.value = getDefaultCharts();
        }
      } else {
        charts.value = getDefaultCharts();
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn('Failed to load layout file, using default charts:', err);
      charts.value = getDefaultCharts();
    }
  };

  const resetToDefault = () => {
    Modal.confirm({
      title: t('log.dashboard.action.resetDefault'),
      content: '确定要重置为默认仪表盘吗？当前所有自定义图表将丢失。',
      onOk: () => {
        charts.value = getDefaultCharts();
        saveLayout();
      },
    });
  };

  const resetForm = () => {
    addForm.title = '';
    addForm.query = '';
    addForm.width = 12;
    addForm.height = 300;
    addForm.type = 'line';
    addForm.range = '24h';
    queryBuilder.metric = 'count';
    queryBuilder.field = '';
    queryBuilder.dimension = 'none';
    queryBuilder.filterKey = '';
    queryBuilder.filterValue = '';
    queryBuilder.interval = '1m';
    queryBuilder.topk = 0;
    queryBuilder.logSource = 'gms-audit';
    buildQuery();
  };

  const openAddModal = () => {
    isEditMode.value = false;
    resetForm();
    showAddModal.value = true;
  };

  const parseQuery = (query: string) => {
    // 简单的正则解析，用于反推参数
    // 示例: topk(10, sum by (mapName) (count_over_time({job="gms-audit", mod="FIELD", act="CHANGE_MAP"}[1h])))
    // 示例: sum by (act) (count_over_time({job="gms-audit", mod="SHOP"}[1h]))
    // 示例: count_over_time({job="gms-audit"}[1m])

    try {
      // 1. TopK
      const topkMatch = query.match(/topk\((\d+),/);
      if (topkMatch) {
        queryBuilder.topk = parseInt(topkMatch[1], 10);
      } else {
        queryBuilder.topk = 0;
      }

      // 2. Dimension (sum by (...))
      const dimMatch = query.match(/by\s*\(([^)]+)\)/);
      if (dimMatch) {
        queryBuilder.dimension = dimMatch[1].trim();
      } else {
        queryBuilder.dimension = 'none';
      }

      // 3. Metric & Interval & Selector
      // 匹配 count_over_time(...) 或 sum_over_time(...) 等
      const funcMatch = query.match(/(\w+)_over_time\(([^)]+)\)/);
      if (funcMatch) {
        // eslint-disable-next-line prefer-destructuring
        queryBuilder.metric = funcMatch[1]; // count, sum, avg...
        const inner = funcMatch[2]; // {job="...", ...}[1h] 或 ({...} | unwrap ...)[1h]

        // Interval
        const intervalMatch = inner.match(/\[([^\]]+)\]$/);
        if (intervalMatch) {
          // eslint-disable-next-line prefer-destructuring
          queryBuilder.interval = intervalMatch[1];
        }

        // Field (unwrap)
        const unwrapMatch = inner.match(/unwrap\s+([^\s|]+)/);
        if (unwrapMatch) {
          // eslint-disable-next-line prefer-destructuring
          queryBuilder.field = unwrapMatch[1];
        } else {
          queryBuilder.field = '';
        }

        // Selector {key="value", ...}
        const selectorMatch = inner.match(/\{([^}]+)\}/);
        if (selectorMatch) {
          const parts = selectorMatch[1].split(',');
          let logSource = 'gms-audit';
          let filterKey = '';
          let filterValue = '';

          parts.forEach((part) => {
            const [k, v] = part
              .split('=')
              .map((s) => s.trim().replace(/"/g, ''));
            if (k === 'job') {
              logSource = v;
            } else if (k !== '__error__') {
              // 假设只有一个额外的过滤条件
              filterKey = k;
              filterValue = v;
            }
          });

          queryBuilder.logSource = logSource;
          queryBuilder.filterKey = filterKey;
          queryBuilder.filterValue = filterValue;
        }
      }
    } catch (e) {
      // ignore
    }
  };

  const openEditModal = (index: number) => {
    isEditMode.value = true;
    editingIndex.value = index;
    const chart = charts.value[index];
    addForm.title = chart.title;
    addForm.type = chart.type;
    addForm.query = chart.query;
    addForm.width = chart.width;
    addForm.height = chart.height || 300;
    addForm.range = chart.range || '24h';

    // 反推参数
    parseQuery(chart.query);

    // 自动加载下拉选项，以便正确显示 Label
    if (queryBuilder.filterKey === 'mod' || queryBuilder.filterKey === 'act') {
      handleSearch('');
    } else {
      autoCompleteData.value = [];
    }

    showAddModal.value = true;
  };

  const handleSaveChart = () => {
    if (!addForm.title || !addForm.query) {
      Message.warning(t('log.dashboard.custom.validate.required'));
      return;
    }

    if (isEditMode.value && editingIndex.value !== -1) {
      const chart = charts.value[editingIndex.value];
      chart.title = addForm.title;
      chart.type = addForm.type as
        | 'line'
        | 'bar'
        | 'pie'
        | 'scatter'
        | 'area'
        | 'radar'
        | 'funnel'
        | 'gauge'
        | 'heatmap'
        | 'candlestick';
      chart.query = addForm.query;
      chart.width = addForm.width;
      chart.range = addForm.range;
    } else {
      const newChart: ChartConfig = {
        id: Date.now().toString(),
        title: addForm.title,
        type: addForm.type as
          | 'line'
          | 'bar'
          | 'pie'
          | 'scatter'
          | 'area'
          | 'radar'
          | 'funnel'
          | 'gauge'
          | 'heatmap'
          | 'candlestick',
        query: addForm.query,
        width: addForm.width,
        height: 300,
        range: addForm.range,
      };
      charts.value.push(newChart);
    }
    showAddModal.value = false;
  };

  const removeChart = (index: number) => {
    charts.value.splice(index, 1);
  };

  const sortableRef = ref<HTMLElement | null>(null);

  const initSortable = () => {
    if (sortableRef.value) {
      const el = sortableRef.value.querySelector('.chart-grid');
      if (el) {
        Sortable.create(el as HTMLElement, {
          handle: '.chart-header',
          animation: 150,
          onEnd: (evt) => {
            const { oldIndex, newIndex } = evt;
            if (
              oldIndex !== undefined &&
              newIndex !== undefined &&
              oldIndex !== newIndex
            ) {
              const item = charts.value.splice(oldIndex, 1)[0];
              charts.value.splice(newIndex, 0, item);
            }
          },
        });
      }
    }
  };

  onMounted(() => {
    fetchStatus();
    loadLayout();
    timer = setInterval(() => {
      now.value = Date.now();
    }, 1000);

    nextTick(() => {
      initSortable();
    });
  });

  onUnmounted(() => {
    if (timer) clearInterval(timer);
  });
</script>

<style scoped lang="less">
  .container {
    padding: 0 20px 20px 20px;
  }

  .stat-card {
    display: flex;
    flex-direction: column;
    padding: 4px 0;
  }

  .stat-label {
    font-size: 14px;
    font-weight: bold;
    color: var(--color-text-1);
    margin-bottom: 8px;
  }

  .stat-content {
    display: flex;
    align-items: center;
    font-size: 24px;
    font-weight: 500;
    color: #f53f3f;

    &.active {
      color: #0fbf60;
    }

    &.loading {
      color: var(--color-text-3);
      font-size: 16px;
    }
  }

  .stat-icon {
    margin-right: 8px;
    font-size: 24px;

    &.spin {
      animation: spin 1s linear infinite;
    }
  }

  @keyframes spin {
    from {
      transform: rotate(0deg);
    }
    to {
      transform: rotate(360deg);
    }
  }

  .stat-value {
    line-height: 1;
  }

  .stat-uptime {
    font-size: 14px;
    color: var(--color-text-3);
    margin-left: 8px;
    font-weight: normal;
    margin-top: 4px;
  }

  .dashboard-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 20px;
    margin-bottom: 16px;
  }

  .dashboard-title {
    font-size: 16px;
    font-weight: 500;
    color: var(--color-text-1);
  }

  .sortable-ghost {
    opacity: 0.5;
    background: #c8ebfb;
  }

  .query-builder {
    background: var(--color-bg-2);
    padding: 16px;
    border-radius: 4px;
    margin-bottom: 16px;
    border: 1px solid var(--color-border-2);
  }
</style>
