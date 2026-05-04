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
    <div
      ref="sortableRef"
      class="chart-grid-container"
      :class="{ resizing: isResizing }"
    >
      <a-row :gutter="0" class="chart-grid">
        <a-col
          v-for="(chart, index) in charts"
          :key="chart.id"
          :style="{
            width: chart.width + 'px',
            flex: '0 0 ' + chart.width + 'px',
          }"
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
            :all-options="allOptions"
            @remove="removeChart(index)"
            @config="openEditModal(index)"
            @resize-start="handleResizeStart"
            @resize-end="handleResizeEnd"
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
      @cancel="resetForm"
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
                <a-select v-model="queryBuilder.logSource">
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
                <a-select v-model="addForm.range">
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
                <a-select v-model="queryBuilder.interval">
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

          <!-- 动态过滤条件 -->
          <div
            v-for="(filter, index) in queryBuilder.filters"
            :key="index"
            class="filter-row"
          >
            <a-row :gutter="8">
              <a-col :span="8">
                <a-select
                  v-model="filter.key"
                  :placeholder="
                    $t('log.dashboard.builder.filter.placeholder.key')
                  "
                  allow-create
                  filterable
                >
                  <a-option
                    v-for="item in combinedDimensions"
                    :key="item.value"
                    :value="item.value"
                    >{{ item.label }}</a-option
                  >
                </a-select>
              </a-col>
              <a-col :span="4">
                <a-select v-model="filter.op">
                  <a-option value="=">=</a-option>
                  <a-option value="!=">!=</a-option>
                  <a-option value="=~">=~</a-option>
                  <a-option value="!~">!~</a-option>
                </a-select>
              </a-col>
              <a-col :span="10">
                <a-select
                  v-if="isSelectFilter(filter.key)"
                  v-model="filter.value"
                  :placeholder="
                    $t('log.dashboard.builder.filter.placeholder.value')
                  "
                  allow-search
                  allow-clear
                  :options="getOptionsForFilterKey(filter.key)"
                />
                <a-input
                  v-else
                  v-model="filter.value"
                  :placeholder="
                    $t('log.dashboard.builder.filter.placeholder.inputValue')
                  "
                  allow-clear
                />
              </a-col>
              <a-col :span="2">
                <a-button
                  type="text"
                  status="danger"
                  @click="removeFilter(index)"
                  ><icon-minus-circle
                /></a-button>
              </a-col>
            </a-row>
          </div>
          <a-button type="dashed" long @click="addFilter">
            <template #icon><icon-plus /></template>
            {{ $t('log.dashboard.builder.filter.add') }}
          </a-button>
          <a-divider />

          <a-row :gutter="16">
            <a-col :span="8">
              <a-form-item
                :label="$t('log.dashboard.custom.form.metric')"
                field="metric"
              >
                <a-select v-model="queryBuilder.metric">
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
                  :placeholder="
                    $t('log.dashboard.builder.field.placeholder.numeric')
                  "
                  allow-create
                  filterable
                >
                  <a-option
                    v-for="item in combinedNumericFields"
                    :key="item.value"
                    :value="item.value"
                    >{{ item.label }}</a-option
                  >
                </a-select>
              </a-form-item>
            </a-col>
            <a-col :span="8">
              <a-form-item
                :label="$t('log.dashboard.custom.form.dimension')"
                field="dimension"
              >
                <a-select
                  v-model="queryBuilder.dimension"
                  allow-create
                  filterable
                >
                  <a-option
                    v-for="item in combinedDimensions"
                    :key="item.value"
                    :value="item.value"
                    >{{ item.label }}</a-option
                  >
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
                  :placeholder="$t('log.dashboard.builder.topk.placeholder')"
                />
              </a-form-item>
            </a-col>
            <a-col :span="16">
              <a-form-item>
                <a-button
                  type="primary"
                  style="margin-top: 28px"
                  @click="buildQuery"
                >
                  <template #icon><icon-command /></template>
                  {{ $t('log.dashboard.builder.action.generate') }}
                </a-button>
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

        <!-- 新增：用于解析的原始日志查询 -->
        <a-form-item
          :label="$t('log.dashboard.custom.form.rawQueryForParse')"
          field="rawQueryForParse"
        >
          <div
            style="display: flex; align-items: center; gap: 8px; width: 100%"
          >
            <a-textarea
              :model-value="rawLogQueryForParsing"
              :placeholder="
                $t('log.dashboard.custom.form.rawQueryForParse.placeholder')
              "
              :auto-size="{ minRows: 1, maxRows: 3 }"
              readonly
              style="flex-grow: 1; resize: vertical"
            />
            <div class="raw-query-status-indicator">
              <a-tooltip :content="rawQueryStatusMessage">
                <template v-if="rawQueryStatus === 'loading'">
                  <icon-loading
                    class="spin"
                    style="color: var(--color-text-3)"
                  />
                </template>
                <template v-else-if="rawQueryStatus === 'valid'">
                  <icon-check-circle style="color: #0fbf60" />
                </template>
                <template
                  v-else-if="
                    rawQueryStatus === 'matrix' || rawQueryStatus === 'error'
                  "
                >
                  <icon-exclamation-circle style="color: #f53f3f" />
                </template>
                <template v-else>
                  <icon-question-circle style="color: var(--color-text-3)" />
                </template>
              </a-tooltip>
            </div>
          </div>
          <template #help>
            {{ $t('log.dashboard.custom.form.rawQueryForParse.help') }}
          </template>
        </a-form-item>

        <a-form-item>
          <a-space>
            <a-button :loading="testingQuery" @click="handleTestFullQuery">{{
              $t('log.dashboard.custom.action.testFullQuery')
            }}</a-button>
            <a-button :loading="testingRawQuery" @click="handleTestRawQuery">{{
              $t('log.dashboard.custom.action.testRawQuery')
            }}</a-button>
            <a-button
              :disabled="!isRawQueryParsable"
              @click="handleParseResult"
              >{{ $t('log.dashboard.custom.action.parse') }}</a-button
            >
          </a-space>
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 测试结果弹窗 -->
    <a-modal
      v-model:visible="showTestResultModal"
      :title="$t('log.dashboard.custom.testResult.title')"
      width="800px"
      :top="100"
      :footer="false"
    >
      <div class="test-result-content">
        <pre>{{ testResult }}</pre>
      </div>
    </a-modal>

    <!-- 解析字段弹窗 -->
    <a-modal
      v-model:visible="showParseModal"
      :title="$t('log.dashboard.custom.parseModal.title')"
      width="600px"
      @ok="confirmParseSelection"
    >
      <a-table
        :data="parsedFields"
        :pagination="false"
        row-key="name"
        size="small"
      >
        <template #columns>
          <a-table-column
            :title="$t('log.dashboard.custom.parseModal.field')"
            data-index="name"
          />
          <a-table-column
            :title="$t('log.dashboard.custom.parseModal.display')"
            data-index="translated"
          />
          <a-table-column
            :title="$t('log.dashboard.custom.parseModal.type')"
            data-index="type"
          />
          <a-table-column :title="$t('log.dashboard.custom.parseModal.add')">
            <template #cell="{ record }">
              <a-checkbox v-model="record.selected" />
            </template>
          </a-table-column>
        </template>
      </a-table>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
  import {
    ref,
    onMounted,
    onUnmounted,
    reactive,
    nextTick,
    computed,
    watch,
  } from 'vue';
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
    getAllOptions,
    LabelValue,
    queryLogs,
  } from '@/api/log';
  import { Message, Modal } from '@arco-design/web-vue';
  import dayjs from 'dayjs';
  import Sortable from 'sortablejs';
  import LogChart from './LogChart.vue';

  // --- Refactoring: Centralized static definitions ---
  const STATIC_DIMENSIONS_MAP = {
    none: 'log.dashboard.builder.dimension.none',
    mod: 'log.dashboard.builder.dimension.mod',
    act: 'log.dashboard.builder.dimension.act',
    actionType: 'log.query.form.actionType', // '行为'
    actsou: 'log.query.form.actionSource', // '来源'
    jobName: 'log.dashboard.builder.dimension.job',
    mapName: 'log.dashboard.builder.dimension.map',
    acc: 'log.dashboard.builder.dimension.acc',
    chr: 'log.dashboard.builder.dimension.chr',
  };

  const STATIC_NUMERIC_FIELDS_MAP = {
    cnt: 'log.dashboard.builder.field.cnt',
    cost: 'log.dashboard.builder.field.cost',
    meso: 'log.dashboard.builder.field.meso',
    exp: 'log.dashboard.builder.field.exp',
    hp: 'log.dashboard.builder.field.hp',
    mp: 'log.dashboard.builder.field.mp',
  };

  const { t } = useI18n();

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

  // --- LogQL Builder ---
  const LOKI_LABELS = ['job', 'mod', 'act'];

  interface LogQLFilter {
    key: string;
    op: string;
    value: string;
  }

  const createDefaultQueryBuilder = () => ({
    metric: 'count',
    field: '',
    dimension: 'none',
    interval: '1m',
    filters: [{ key: '', op: '=', value: '' }] as LogQLFilter[],
    topk: 0,
    logSource: 'gms-audit',
  });

  const queryBuilder = reactive(createDefaultQueryBuilder());

  // --- Dashboard Logic ---
  type ChartType =
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

  interface ChartConfig {
    id: string;
    title: string;
    type: ChartType;
    query: string;
    width: number;
    height: number;
    range?: string;
    builderState?: typeof queryBuilder;
  }

  const charts = ref<ChartConfig[]>([]);
  const savingLayout = ref(false);
  const showAddModal = ref(false);
  const isEditMode = ref(false);
  const editingIndex = ref(-1);
  const isResizing = ref(false);

  const createDefaultAddForm = () => ({
    title: '',
    type: 'line' as ChartType,
    query: '',
    width: 600,
    height: 300,
    range: '24h',
  });

  const addForm = reactive(createDefaultAddForm());

  const buildQuery = () => {
    const keyMapping = {
      actionType: 'act',
      actionSource: 'actsou',
    };

    const labels = [`job="${queryBuilder.logSource}"`];
    const lineFilters: string[] = [];

    queryBuilder.filters.forEach((filter) => {
      if (filter.key && filter.value) {
        const actualKey = keyMapping[filter.key] || filter.key;
        if (LOKI_LABELS.includes(actualKey)) {
          labels.push(`${actualKey}${filter.op}"${filter.value}"`);
        } else {
          lineFilters.push(`| ${actualKey}${filter.op}"${filter.value}"`);
        }
      }
    });

    const selector = `{${labels.join(',')}}`;
    const lineFilterPipe = lineFilters.join(' ');
    const actualDimension =
      keyMapping[queryBuilder.dimension] || queryBuilder.dimension;

    const needsJson =
      lineFilterPipe ||
      (actualDimension !== 'none' && !LOKI_LABELS.includes(actualDimension)) ||
      queryBuilder.metric !== 'count';

    let stream = selector;
    if (needsJson) {
      stream += ` | json`;
      if (lineFilterPipe) {
        stream += ` ${lineFilterPipe}`;
      }
    }

    let func = '';
    if (queryBuilder.metric === 'count') {
      func = `count_over_time(${stream} [${queryBuilder.interval}])`;
    } else {
      if (!queryBuilder.field) {
        Message.error(t('log.dashboard.custom.message.query.error'));
        return;
      }
      const unwrapStream = `${stream} | unwrap ${queryBuilder.field} | __error__=""`;
      func = `${queryBuilder.metric}_over_time(${unwrapStream} [${queryBuilder.interval}])`;
    }

    let q = '';
    if (queryBuilder.dimension && queryBuilder.dimension !== 'none') {
      q = `sum by (${actualDimension}) (${func})`;
      if (queryBuilder.topk > 0) {
        q = `topk(${queryBuilder.topk}, ${q})`;
      }
    } else {
      q = `sum(${func})`;
    }
    addForm.query = q;
  };

  const addFilter = () => {
    queryBuilder.filters.push({ key: '', op: '=', value: '' });
  };
  const removeFilter = (index: number) => {
    queryBuilder.filters.splice(index, 1);
  };

  const allOptions = ref({
    modules: [] as LabelValue[],
    actions: [] as LabelValue[],
    traceabilityActionTypes: [] as LabelValue[],
    traceabilityActionSourceTypes: [] as LabelValue[],
  });

  const isSelectFilter = (key: string) => {
    return ['mod', 'act', 'actionType', 'actsou'].includes(key);
  };

  const getOptionsForFilterKey = (key: string) => {
    if (key === 'mod') return allOptions.value.modules;
    if (key === 'act') return allOptions.value.actions;
    if (key === 'actionType') return allOptions.value.traceabilityActionTypes;
    if (key === 'actsou') return allOptions.value.traceabilityActionSourceTypes;
    return [];
  };

  // --- Test & Parse Logic ---
  const showTestResultModal = ref(false);
  const testResult = ref('');
  const testingQuery = ref(false); // For full query
  const testingRawQuery = ref(false); // For raw query for parsing

  // Data for parsing
  const lastParsableLogData = ref<any[]>([]);
  const rawQueryStatus = ref<'idle' | 'loading' | 'valid' | 'matrix' | 'error'>(
    'idle'
  );

  const rawQueryStatusMessage = computed(() => {
    switch (rawQueryStatus.value) {
      case 'idle':
        return '';
      case 'loading':
        return t('common.loading');
      case 'valid':
        return t('log.dashboard.custom.message.rawQuery.valid');
      case 'matrix':
        return t('log.dashboard.custom.message.rawQuery.matrix');
      case 'error':
        return t('log.dashboard.custom.message.rawQuery.failed');
      default:
        return '';
    }
  });

  const isRawQueryParsable = computed(() => rawQueryStatus.value === 'valid');

  const rawLogQueryForParsing = computed(() => {
    const { query } = addForm;
    // 尝试匹配最外层的流选择器 { ... }
    // 这是一个简化的匹配，假设一个查询中只有一个主要流选择器用于获取日志源
    const streamSelectorMatch = query.match(/\{[^{}]*}/);
    if (streamSelectorMatch && streamSelectorMatch[0]) {
      // 提取流选择器部分
      let baseQuery = streamSelectorMatch[0];
      // 确保后面有 | json 管道，这是解析日志的关键
      // 如果原始查询中流选择器后面已经有 | json，则不再重复添加
      const indexAfterSelector = query.indexOf(baseQuery) + baseQuery.length;
      const remaining = query.substring(indexAfterSelector).trim();
      if (!remaining.startsWith('| json')) {
        baseQuery += ' | json';
      } else {
        // 如果已经有 | json，则只保留到 | json 为止
        const jsonPipeEndIndex = remaining.indexOf('| json') + '| json'.length;
        baseQuery += remaining.substring(0, jsonPipeEndIndex);
      }
      return baseQuery.trim();
    }
    return '';
  });

  const dynamicDimensions = ref<LabelValue[]>([]);
  const dynamicNumericFields = ref<LabelValue[]>([]);
  const showParseModal = ref(false);
  const parsedFields = ref<
    { name: string; translated: string; type: string; selected: boolean }[]
  >([]);
  const i18nFieldMap = new Map<string, string>();

  const staticDimensions = computed(() =>
    Object.entries(STATIC_DIMENSIONS_MAP).map(([value, key]) => ({
      label: t(key),
      value,
    }))
  );

  const staticNumericFields = computed(() =>
    Object.entries(STATIC_NUMERIC_FIELDS_MAP).map(([value, key]) => ({
      label: t(key),
      value,
    }))
  );

  const combinedDimensions = computed(() => {
    const all = [...staticDimensions.value, ...dynamicDimensions.value];
    return all.filter(
      (item, index, self) =>
        index === self.findIndex((item2) => item2.value === item.value)
    );
  });

  const combinedNumericFields = computed(() => {
    const all = [...staticNumericFields.value, ...dynamicNumericFields.value];
    return all.filter(
      (item, index, self) =>
        index === self.findIndex((item2) => item2.value === item.value)
    );
  });

  const buildI18nMap = () => {
    i18nFieldMap.clear();
    Object.entries(STATIC_DIMENSIONS_MAP).forEach(([value, key]) => {
      if (value !== 'none') {
        i18nFieldMap.set(value, t(key));
      }
    });
    Object.entries(STATIC_NUMERIC_FIELDS_MAP).forEach(([value, key]) => {
      i18nFieldMap.set(value, t(key));
    });
  };

  const fetchAllOptions = async () => {
    try {
      const { data } = await getAllOptions();
      allOptions.value = data;
      buildI18nMap();
    } catch (err) {
      // ignore
    }
  };

  // Function to test the full query (for display in modal)
  const handleTestFullQuery = async () => {
    testingQuery.value = true;
    const testQuery = addForm.query;
    if (!testQuery) {
      Message.warning(t('log.dashboard.custom.validate.queryRequired'));
      testingQuery.value = false;
      return;
    }
    try {
      const response = await queryLogs({
        query: testQuery,
        limit: 10, // Limit for display purposes
        range: addForm.range,
      });
      testResult.value = JSON.stringify(response.data, null, 2);
      showTestResultModal.value = true;
    } catch (err: any) {
      Message.error(err.message || t('log.query.message.fail'));
      testResult.value = `${t('log.query.message.fail')}: ${err.message}\n\n${t(
        'log.dashboard.custom.form.query'
      )}:\n${testQuery}`;
      showTestResultModal.value = true;
    } finally {
      testingQuery.value = false;
    }
  };

  // Function to test the raw query for parsing
  const handleTestRawQuery = async () => {
    testingRawQuery.value = true;
    rawQueryStatus.value = 'loading';
    lastParsableLogData.value = []; // Clear previous data

    const queryToTest = rawLogQueryForParsing.value;
    if (!queryToTest) {
      Message.warning(t('log.dashboard.custom.message.rawQuery.failed'));
      rawQueryStatus.value = 'error';
      testingRawQuery.value = false;
      return;
    }

    try {
      const response = await queryLogs({
        query: queryToTest,
        limit: 10, // Only need a few logs to extract fields
        range: addForm.range,
      });

      const resultData = response.data?.data;
      const result = resultData?.result || [];
      const resultType = resultData?.resultType || '';

      if (resultType === 'streams') {
        const allLogs = result
          .map((item: any) => {
            return item.values.map((val: any[]) => {
              try {
                return JSON.parse(val[1].trim());
              } catch (e) {
                return { raw: val[1] }; // Fallback for non-JSON lines
              }
            });
          })
          .flat();

        if (allLogs.length > 0) {
          lastParsableLogData.value = allLogs;
          rawQueryStatus.value = 'valid';
        } else {
          rawQueryStatus.value = 'error'; // No parsable logs found
        }
      } else if (resultType === 'matrix') {
        rawQueryStatus.value = 'matrix';
      } else {
        rawQueryStatus.value = 'error';
      }
    } catch (err: any) {
      rawQueryStatus.value = 'error';
      Message.error(err.message || t('log.query.message.fail'));
    } finally {
      testingRawQuery.value = false;
    }
  };

  const handleParseResult = () => {
    if (!isRawQueryParsable.value || lastParsableLogData.value.length === 0) {
      Message.info(t('log.dashboard.custom.message.test.noParsableResult'));
      return;
    }
    const firstLog = lastParsableLogData.value[0];
    if (!firstLog || typeof firstLog !== 'object') {
      Message.error(t('log.dashboard.custom.message.test.invalidJson'));
      return;
    }

    parsedFields.value = Object.keys(firstLog).map((key) => {
      const value = firstLog[key];
      return {
        name: key,
        translated: i18nFieldMap.get(key) || key,
        type: typeof value,
        selected: true,
      };
    });
    showParseModal.value = true;
  };

  const confirmParseSelection = () => {
    let addedCount = 0;
    parsedFields.value.forEach((field) => {
      if (field.selected) {
        const existingDim = combinedDimensions.value.find(
          (d) => d.value === field.name
        );
        const existingNum = combinedNumericFields.value.find(
          (f) => f.value === field.name
        );

        if (field.type === 'string' && !existingDim) {
          dynamicDimensions.value.push({
            label: field.translated,
            value: field.name,
          });
          addedCount += 1;
        } else if (field.type === 'number' && !existingNum) {
          dynamicNumericFields.value.push({
            label: field.translated,
            value: field.name,
          });
          addedCount += 1;
        }
      }
    });

    if (addedCount > 0) {
      Message.success(
        t('log.dashboard.custom.message.parse.success', { count: addedCount })
      );
    } else {
      Message.info(t('log.dashboard.custom.message.parse.noNew'));
    }
    showParseModal.value = false;
  };

  const handleResizeStart = () => {
    isResizing.value = true;
  };

  const handleResizeEnd = () => {
    isResizing.value = false;
  };

  // 默认预置图表
  const getDefaultCharts = (): ChartConfig[] => [
    {
      id: '1',
      title: t('log.dashboard.defaultChart.loginActivity'),
      type: 'line',
      query:
        'sum by (act) (count_over_time({job="gms-audit",mod="ACCOUNT"} [30m]))',
      width: 600,
      height: 300,
      range: '24h',
    },
    {
      id: '2',
      title: t('log.dashboard.defaultChart.cashShopSales'),
      type: 'pie',
      query:
        'topk(10, sum by (itmName) (count_over_time({job="gms-audit",mod="ITEM_TRACEAB",act="CASH_SHOP"} | json | actsou="CS_BUY" [30m])))',
      width: 600,
      height: 300,
      range: '24h',
    },
    {
      id: '3',
      title: t('log.dashboard.defaultChart.shopActivity'),
      type: 'bar',
      query:
        'topk(10, sum by (itmName) (sum_over_time({job="gms-audit",mod="ITEM_TRACEAB",act="MERCHANT_SHOP"} | json | unwrap cnt | __error__="" [30m])))',
      width: 600,
      height: 300,
      range: '24h',
    },
    {
      id: '4',
      title: t('log.dashboard.defaultChart.jobDistribution'),
      type: 'pie',
      query:
        'sum by (jobName) (count_over_time({job="gms-audit",mod="ACCOUNT",act="CHR_SELECT"} | json [30m]))',
      width: 600,
      height: 300,
      range: '24h',
    },
    {
      id: '5',
      title: t('log.dashboard.defaultChart.mapPopularity'),
      type: 'bar',
      query:
        'topk(10, sum by (mapName) (count_over_time({job="gms-audit",act="MAP_CHANGE"} | json [30m])))',
      width: 1200,
      height: 350,
      range: '24h',
    },
    {
      id: '6',
      title: t('log.dashboard.defaultChart.cheatDetection'),
      type: 'bar',
      query:
        'sum by (type) (count_over_time({job="gms-audit",mod="AUTOBAN"} | json [30m]))',
      width: 600,
      height: 300,
      range: '24h',
    },
    {
      id: '7',
      title: t('log.dashboard.defaultChart.systemErrors'),
      type: 'line',
      query: 'sum(count_over_time({job="gms-error"} [30m]))',
      width: 600,
      height: 300,
      range: '24h',
    },
  ];

  const saveLayout = async () => {
    savingLayout.value = true;
    try {
      const dataToSave = JSON.parse(JSON.stringify(charts.value));
      await saveConfigFile('dashboard-layout.json', JSON.stringify(dataToSave));
      Message.success(t('log.dashboard.custom.message.save.success'));
    } catch (err) {
      Message.error(t('log.dashboard.custom.message.save.fail'));
    } finally {
      savingLayout.value = false;
    }
  };

  const loadLayout = async () => {
    try {
      const { data } = await readConfigFile('dashboard-layout.json');
      if (!data) {
        charts.value = getDefaultCharts();
        return;
      }

      let parsedData: any;
      if (typeof data === 'string') {
        try {
          parsedData = JSON.parse(data);
        } catch (e) {
          charts.value = getDefaultCharts();
          return;
        }
      } else {
        parsedData = data;
      }

      // 检查并解包可能存在的嵌套 'data' 属性
      if (
        parsedData &&
        typeof parsedData === 'object' &&
        !Array.isArray(parsedData) &&
        'data' in parsedData
      ) {
        if (typeof parsedData.data === 'string') {
          try {
            parsedData = JSON.parse(parsedData.data);
          } catch (e) {
            // 如果内部数据无法解析，则使用默认值
            charts.value = getDefaultCharts();
            return;
          }
        } else {
          parsedData = parsedData.data;
        }
      }

      if (Array.isArray(parsedData)) {
        charts.value = parsedData;
        charts.value.forEach((c) => {
          if (!c.height) c.height = 300;
          if (c.width <= 24) {
            c.width *= 50;
            if (c.width < 200) c.width = 600;
          }
        });
      } else {
        charts.value = getDefaultCharts();
      }
    } catch (err) {
      charts.value = getDefaultCharts();
    }
  };

  const resetToDefault = () => {
    Modal.confirm({
      title: t('log.dashboard.action.resetDefault'),
      content: t('log.dashboard.confirm.resetDefault'),
      onOk: async () => {
        charts.value = getDefaultCharts();
        await saveLayout();
      },
    });
  };

  const resetForm = () => {
    Object.assign(queryBuilder, createDefaultQueryBuilder());
    Object.assign(addForm, createDefaultAddForm());
    dynamicDimensions.value = [];
    dynamicNumericFields.value = [];
    rawQueryStatus.value = 'idle'; // Reset raw query status
    lastParsableLogData.value = []; // Clear parsable data
  };

  const openAddModal = () => {
    isEditMode.value = false;
    resetForm();
    showAddModal.value = true;
  };

  const openEditModal = (index: number) => {
    isEditMode.value = true;
    editingIndex.value = index;
    const chart = charts.value[index];

    resetForm(); // 先重置

    // 优先从保存的 builderState 恢复
    if (chart.builderState) {
      Object.assign(
        queryBuilder,
        JSON.parse(JSON.stringify(chart.builderState))
      );
    }

    addForm.title = chart.title;
    addForm.type = chart.type;
    addForm.query = chart.query;
    addForm.width = chart.width;
    addForm.height = chart.height || 300;
    addForm.range = chart.range || '24h';

    showAddModal.value = true;
  };

  const handleSaveChart = () => {
    if (!addForm.title || !addForm.query) {
      Message.warning(t('log.dashboard.custom.validate.required'));
      return;
    }

    const chartData: ChartConfig = {
      id: isEditMode.value
        ? charts.value[editingIndex.value].id
        : Date.now().toString(),
      title: addForm.title,
      type: addForm.type,
      query: addForm.query, // 直接使用文本框的查询
      width: addForm.width,
      height: addForm.height,
      range: addForm.range,
      builderState: JSON.parse(JSON.stringify(queryBuilder)), // 保存构建器状态
    };

    if (isEditMode.value) {
      charts.value[editingIndex.value] = chartData;
    } else {
      charts.value.push(chartData);
    }
    showAddModal.value = false;
    resetForm();
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

  onMounted(async () => {
    await fetchAllOptions(); // 确保在构建 i18n 映射和其他逻辑之前获取选项
    await fetchStatus();
    await loadLayout();
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

  // Watch for changes in the main query to reset raw query status
  watch(
    () => {
      const { query } = addForm; // 使用对象解构
      return query;
    },
    () => {
      rawQueryStatus.value = 'idle';
      lastParsableLogData.value = [];
    }
  );
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

  .filter-row {
    margin-bottom: 8px;
  }

  /* 网格背景样式 */
  .chart-grid-container {
    position: relative;
    border: 1px solid transparent; /* 默认透明边框，避免抖动 */
    min-height: 600px;
    transition: background-image 0.2s;
  }

  /* 仅在调整大小时显示网格 */
  .chart-grid-container.resizing {
    /* 垂直网格：16px 间隔 */
    /* 水平网格：16px 间隔 */
    background-image: linear-gradient(
        90deg,
        var(--color-neutral-3) 1px,
        transparent 1px
      ),
      linear-gradient(180deg, var(--color-neutral-3) 1px, transparent 1px);
    background-size: 16px 16px;
    background-position: 0 0;
    border-color: var(--color-neutral-3);
  }

  .test-result-content {
    max-height: 60vh;
    overflow: auto;
    background-color: var(--color-fill-2);
    padding: 10px;
    border-radius: 4px;
  }

  .raw-query-status-indicator {
    display: flex;
    align-items: center;
  }

  .raw-query-status-indicator .arco-icon {
    font-size: 18px;
  }
</style>
