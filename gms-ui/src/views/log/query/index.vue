<template>
  <div class="container">
    <Breadcrumb :items="['menu.log', 'menu.log.query']" />

    <!-- 1. 查询表单区域 -->
    <a-card class="general-card" :title="$t('log.query.title')">
      <a-row>
        <a-col :flex="1">
          <a-form :model="form" label-col-flex="70px" label-align="left">
            <a-row :gutter="12">
              <!-- 时间范围 -->
              <a-col :span="5">
                <a-form-item
                  field="timeRange"
                  :label="$t('log.query.form.time')"
                >
                  <a-range-picker
                    v-model="form.timeRange"
                    show-time
                    format="YYYY-MM-DD HH:mm:ss"
                    :time-picker-props="{
                      defaultValue: ['00:00:00', '23:59:59'],
                    }"
                    style="width: 100%"
                    @change="handleTimeRangeChange"
                  />
                </a-form-item>
              </a-col>
              <!-- 最近时间 -->
              <a-col :span="5">
                <a-form-item field="range" :label="$t('log.query.form.range')">
                  <a-select
                    v-model="form.range"
                    :placeholder="$t('log.query.form.placeholder.select')"
                    @change="handleRangeChange"
                  >
                    <a-option value="1h">{{
                      $t('log.query.form.range.1h')
                    }}</a-option>
                    <a-option value="6h">{{
                      $t('log.query.form.range.6h')
                    }}</a-option>
                    <a-option value="12h">{{
                      $t('log.query.form.range.12h')
                    }}</a-option>
                    <a-option value="24h">{{
                      $t('log.query.form.range.24h')
                    }}</a-option>
                    <a-option value="72h">{{
                      $t('log.query.form.range.72h')
                    }}</a-option>
                    <a-option value="168h">{{
                      $t('log.query.form.range.168h')
                    }}</a-option>
                    <a-option value="360h">{{
                      $t('log.query.form.range.360h')
                    }}</a-option>
                    <a-option value="720h">{{
                      $t('log.query.form.range.720h')
                    }}</a-option>
                  </a-select>
                </a-form-item>
              </a-col>
              <!-- 模块 -->
              <a-col :span="5">
                <a-form-item field="mod" :label="$t('log.query.form.mod')">
                  <a-select
                    v-model="form.mod"
                    :placeholder="$t('log.query.form.placeholder.all')"
                    allow-clear
                    allow-search
                  >
                    <a-option
                      v-for="mod in moduleOptions"
                      :key="mod"
                      :value="mod"
                    >
                      {{ $t(`log.module.${mod}`) }}
                    </a-option>
                  </a-select>
                </a-form-item>
              </a-col>
              <!-- 动作 -->
              <a-col :span="5">
                <a-form-item field="act" :label="$t('log.query.form.act')">
                  <a-auto-complete
                    v-model="form.act"
                    :data="actOptions"
                    :placeholder="$t('log.query.form.placeholder.all')"
                    allow-clear
                    @search="handleActSearch"
                  />
                </a-form-item>
              </a-col>
              <!-- 账号 -->
              <a-col :span="5">
                <a-form-item field="acc" :label="$t('log.query.form.acc')">
                  <a-select
                    v-model="form.acc"
                    :placeholder="
                      $t('log.query.form.placeholder.searchAccount')
                    "
                    allow-clear
                    allow-search
                    :loading="accountSearchLoading"
                    :filter-option="false"
                    @search="handleAccountSearch"
                  >
                    <a-option
                      v-for="item in accountOptions"
                      :key="item.id"
                      :value="String(item.id)"
                    >
                      [{{ item.id }}] {{ item.name }}
                    </a-option>
                  </a-select>
                </a-form-item>
              </a-col>
              <!-- 角色 -->
              <a-col :span="5">
                <a-form-item field="chr" :label="$t('log.query.form.chr')">
                  <a-select
                    v-model="form.chr"
                    :placeholder="
                      $t('log.query.form.placeholder.searchCharacter')
                    "
                    allow-clear
                    allow-search
                    :loading="characterSearchLoading"
                    :filter-option="false"
                    @search="handleCharacterSearch"
                  >
                    <a-option
                      v-for="item in characterOptions"
                      :key="item.id"
                      :value="String(item.id)"
                    >
                      [{{ item.id }}] {{ item.name }}
                    </a-option>
                  </a-select>
                </a-form-item>
              </a-col>

              <!-- IP -->
              <a-col :span="5">
                <a-form-item field="ip" :label="$t('log.query.form.ip')">
                  <a-select
                    v-model="form.ip"
                    :placeholder="$t('log.query.form.placeholder.searchIp')"
                    allow-clear
                    allow-search
                    :loading="ipSearchLoading"
                    :filter-option="false"
                    @search="handleIpSearch"
                  >
                    <a-option
                      v-for="item in ipOptions"
                      :key="item"
                      :value="item"
                    >
                      {{ item }}
                    </a-option>
                  </a-select>
                </a-form-item>
              </a-col>
              <!-- MAC -->
              <a-col :span="5">
                <a-form-item field="mac" :label="$t('log.query.form.mac')">
                  <a-select
                    v-model="form.mac"
                    :placeholder="$t('log.query.form.placeholder.searchMac')"
                    allow-clear
                    allow-search
                    :loading="macSearchLoading"
                    :filter-option="false"
                    @search="handleMacSearch"
                  >
                    <a-option
                      v-for="item in macOptions"
                      :key="item"
                      :value="item"
                    >
                      {{ item }}
                    </a-option>
                  </a-select>
                </a-form-item>
              </a-col>
              <!-- HWID -->
              <a-col :span="5">
                <a-form-item field="hwid" :label="$t('log.query.form.hwid')">
                  <a-select
                    v-model="form.hwid"
                    :placeholder="$t('log.query.form.placeholder.searchHwid')"
                    allow-clear
                    allow-search
                    :loading="hwidSearchLoading"
                    :filter-option="false"
                    @search="handleHwidSearch"
                  >
                    <a-option
                      v-for="item in hwidOptions"
                      :key="item"
                      :value="item"
                    >
                      {{ item }}
                    </a-option>
                  </a-select>
                </a-form-item>
              </a-col>
              <!-- 关键词 -->
              <a-col :span="5">
                <a-form-item field="msg" :label="$t('log.query.form.msg')">
                  <a-input
                    v-model="form.msg"
                    :placeholder="$t('log.query.form.msg.placeholder')"
                    allow-clear
                  />
                </a-form-item>
              </a-col>
            </a-row>
            <a-row style="margin-top: 10px">
              <a-col :span="24">
                <a-space :size="18">
                  <a-button type="primary" @click="search">
                    <template #icon><icon-search /></template>
                    {{ $t('log.query.action.search') }}
                  </a-button>
                  <a-button @click="reset">
                    <template #icon><icon-refresh /></template>
                    {{ $t('log.query.action.reset') }}
                  </a-button>
                </a-space>
              </a-col>
            </a-row>
          </a-form>
        </a-col>
      </a-row>
      <a-divider style="margin-top: 0; margin-bottom: 10px" />

      <!-- 自定义分页导航 -->
      <div class="pagination-controls">
        <a-space>
          <a-button
            type="primary"
            :disabled="!canGoNewer"
            @click="goToNewerPage"
          >
            <template #icon><icon-left /></template>
            {{ $t('log.query.pagination.newer') }}
          </a-button>
          <a-button
            type="primary"
            :disabled="!canGoOlder"
            @click="goToOlderPage"
          >
            {{ $t('log.query.pagination.older') }}
            <template #icon><icon-right /></template>
          </a-button>
          <span>{{
            $t('log.query.pagination.page', { page: currentPageIndex + 1 })
          }}</span>
        </a-space>
        <a-space>
          <span>{{ $t('log.query.pagination.limit') }}</span>
          <a-select
            v-model="form.limit"
            style="width: 100px"
            @change="handleLimitChange"
          >
            <a-option :value="50">50</a-option>
            <a-option :value="100">100</a-option>
            <a-option :value="200">200</a-option>
            <a-option :value="500">500</a-option>
          </a-select>
        </a-space>
      </div>

      <div ref="tableContainerRef" class="table-container">
        <a-table
          :data="data"
          :loading="loading"
          :pagination="false"
          :scroll="{ y: tableHeight }"
        >
          <template #columns>
            <a-table-column
              :title="$t('log.query.table.time')"
              data-index="ts"
              :width="200"
            >
              <template #cell="{ record }">
                {{ formatTime(record.ts) }}
              </template>
            </a-table-column>
            <a-table-column
              :title="$t('log.query.table.moduleAndAction')"
              data-index="mod"
              :width="220"
            >
              <template #cell="{ record }">
                <div v-if="record.mod && record.mod !== '-'">
                  <div class="info-row">
                    <span class="label">{{
                      $t('log.query.label.module')
                    }}</span>
                    <span class="separator"></span>
                    <span class="value">{{
                      $te(`log.module.${record.mod}`)
                        ? $t(`log.module.${record.mod}`)
                        : record.mod
                    }}</span>
                  </div>
                </div>
                <div v-if="record.act && record.act !== '-'">
                  <div class="info-row">
                    <span class="label">{{
                      $t('log.query.label.action')
                    }}</span>
                    <span class="separator"></span>
                    <span class="value">{{
                      $te(`log.action.${record.act}`)
                        ? $t(`log.action.${record.act}`)
                        : record.act
                    }}</span>
                  </div>
                </div>
              </template>
            </a-table-column>
            <a-table-column
              :title="$t('log.query.table.acc')"
              data-index="acc"
              :width="220"
            >
              <template #cell="{ record }">
                <div v-if="record.acc && record.acc !== '-'">
                  <div class="info-row">
                    <span class="label">{{
                      $t('log.query.label.account')
                    }}</span>
                    <span class="separator"></span>
                    <span class="value-id">{{ record.aid }}</span>
                    <span class="separator"></span>
                    <span class="value">{{ record.acc }}</span>
                  </div>
                </div>
                <div v-if="record.chr && record.chr !== '-'">
                  <div class="info-row">
                    <span class="label">{{
                      $t('log.query.label.character')
                    }}</span>
                    <span class="separator"></span>
                    <span class="value-id">{{ record.cid }}</span>
                    <span class="separator"></span>
                    <span class="value">{{ record.chr }}</span>
                  </div>
                </div>
                <div v-if="record.jobName && record.jobName !== '-'">
                  <div class="info-row">
                    <span class="label">{{ $t('log.query.label.job') }}</span>
                    <span class="separator"></span>
                    <span class="value-id">{{ record.job }}</span>
                    <span class="separator"></span>
                    <span class="value">{{ record.jobName }}</span>
                  </div>
                </div>
                <div
                  v-if="
                    (!record.acc || record.acc === '-') &&
                    (!record.chr || record.chr === '-')
                  "
                >
                  -
                </div>
              </template>
            </a-table-column>
            <a-table-column
              :title="$t('log.query.table.map')"
              data-index="mapName"
              :width="150"
            >
              <template #cell="{ record }">
                <div style="font-size: 13px">
                  <div>{{ record.mapName }}</div>
                </div>
                <div style="color: var(--color-text-3); font-size: 12px">
                  {{ record.map }}
                </div>
              </template>
            </a-table-column>
            <a-table-column
              :title="$t('log.query.table.ip')"
              data-index="ip"
              :width="175"
            >
              <template #cell="{ record }">
                <div class="info-row">
                  <span class="label">{{ $t('log.query.label.ip') }}</span>
                  <span class="separator"></span>
                  <span class="value">{{ record.ip }}</span>
                </div>
                <div class="info-row" v-if="record.hwid && record.hwid !== '-'">
                  <span class="label">{{ $t('log.query.label.hwid') }}</span>
                  <span class="separator"></span>
                  <a-tooltip :content="record.hwid">
                    <span class="value text-ellipsis">{{ record.hwid }}</span>
                  </a-tooltip>
                </div>
              </template>
            </a-table-column>
            <a-table-column
              :title="$t('log.query.table.mac')"
              data-index="macs"
              :width="180"
            >
              <template #cell="{ record }">
                <div v-if="record.macs">
                  <a-popover position="left">
                    <div>
                      <div
                        v-for="(mac, index) in parseMacs(record.macs).slice(
                          0,
                          3
                        )"
                        :key="index"
                      >
                        {{ mac }}
                      </div>
                      <div
                        v-if="parseMacs(record.macs).length > 3"
                        style="color: var(--color-text-3)"
                      >
                        ...
                      </div>
                    </div>
                    <template #content>
                      <div
                        v-for="(mac, index) in parseMacs(record.macs)"
                        :key="index"
                      >
                        {{ mac }}
                      </div>
                    </template>
                  </a-popover>
                </div>
                <div v-else>-</div>
              </template>
            </a-table-column>
            <a-table-column
              :title="$t('log.query.table.detail')"
              data-index="msg"
            >
              <template #cell="{ record }">
                <div>{{ record.msg }}</div>
                <!-- 显示额外信息 -->
                <div v-if="record.mobName" class="log-raw">
                  {{
                    $t('log.query.table.extra.monster', {
                      name: record.mobName,
                      id: record.mob,
                    })
                  }}
                </div>
              </template>
            </a-table-column>
          </template>
        </a-table>
      </div>
    </a-card>
  </div>
</template>

<script setup lang="ts">
  import {
    computed,
    nextTick,
    onMounted,
    onUnmounted,
    reactive,
    ref,
  } from 'vue';
  import { useI18n } from 'vue-i18n';
  import {
    getModuleConfig,
    queryLogs,
    searchAccount,
    searchCharacter,
    searchHwid,
    searchIp,
    searchLogs,
    searchMac,
  } from '@/api/log';
  import { Message } from '@arco-design/web-vue';
  import dayjs from 'dayjs';

  const { t } = useI18n();
  const loading = ref(false);
  const form = reactive({
    timeRange: [],
    range: '24h', // 默认最近 24 小时
    mod: '',
    act: '',
    acc: '',
    chr: '',
    ip: '',
    mac: '',
    hwid: '',
    msg: '',
    limit: 100, // 默认每页100条
  });
  const data = ref<any[]>([]);
  const moduleOptions = ref<string[]>([]);
  const actOptions = ref<string[]>([]);

  // --- 搜索下拉框选项 ---
  const accountOptions = ref<any[]>([]);
  const accountSearchLoading = ref(false);
  const characterOptions = ref<any[]>([]);
  const characterSearchLoading = ref(false);
  const ipOptions = ref<string[]>([]);
  const ipSearchLoading = ref(false);
  const macOptions = ref<string[]>([]);
  const macSearchLoading = ref(false);
  const hwidOptions = ref<string[]>([]);
  const hwidSearchLoading = ref(false);

  // --- 时间游标分页状态 ---
  const currentPageIndex = ref(0); // 当前页码索引，从0开始
  const timeCursors = ref<number[]>([]); // 存储每页的结束时间戳 (纳秒)
  const currentLogQL = ref(''); // 保存当前查询的LogQL，用于翻页
  const paginationStart = ref<number | undefined>(); // 保存整个分页生命周期的绝对开始时间

  const canGoNewer = computed(() => currentPageIndex.value > 0);
  const canGoOlder = computed(
    () => timeCursors.value[currentPageIndex.value + 1] !== undefined
  );

  // 表格高度自适应
  const tableContainerRef = ref<HTMLElement | null>(null);
  const tableHeight = ref(500);

  const updateTableHeight = () => {
    if (tableContainerRef.value) {
      const { top } = tableContainerRef.value.getBoundingClientRect();
      const windowHeight = window.innerHeight;
      tableHeight.value = windowHeight - top - 110; // 预留更多空间给分页器
    }
  };

  // 获取模块列表供下拉选择
  const fetchModules = async () => {
    try {
      const { data: modules } = await getModuleConfig();
      moduleOptions.value = Object.keys(modules);
    } catch (err) {
      // ignore
    }
  };

  // --- 各种搜索处理函数 (无变化) ---
  const handleActSearch = async (value: string) => {
    if (value) {
      try {
        const { data: res } = await searchLogs('act', value);
        actOptions.value = res;
      } catch (err) {
        // ignore
      }
    } else {
      actOptions.value = [];
    }
  };
  const handleAccountSearch = async (value: string) => {
    if (value) {
      accountSearchLoading.value = true;
      try {
        const { data: res } = await searchAccount(value);
        accountOptions.value = res;
      } catch (err) {
        // ignore
      } finally {
        accountSearchLoading.value = false;
      }
    } else {
      accountOptions.value = [];
    }
  };
  const handleCharacterSearch = async (value: string) => {
    if (value) {
      characterSearchLoading.value = true;
      try {
        const { data: res } = await searchCharacter(value);
        characterOptions.value = res;
      } catch (err) {
        // ignore
      } finally {
        characterSearchLoading.value = false;
      }
    } else {
      characterOptions.value = [];
    }
  };
  const handleIpSearch = async (value: string) => {
    if (value) {
      ipSearchLoading.value = true;
      try {
        const { data: res } = await searchIp(value);
        ipOptions.value = res;
      } catch (err) {
        // ignore
      } finally {
        ipSearchLoading.value = false;
      }
    } else {
      ipOptions.value = [];
    }
  };
  const handleMacSearch = async (value: string) => {
    if (value) {
      macSearchLoading.value = true;
      try {
        const { data: res } = await searchMac(value);
        macOptions.value = res;
      } catch (err) {
        // ignore
      } finally {
        macSearchLoading.value = false;
      }
    } else {
      macOptions.value = [];
    }
  };
  const handleHwidSearch = async (value: string) => {
    if (value) {
      hwidSearchLoading.value = true;
      try {
        const { data: res } = await searchHwid(value);
        hwidOptions.value = res;
      } catch (err) {
        // ignore
      } finally {
        hwidSearchLoading.value = false;
      }
    } else {
      hwidOptions.value = [];
    }
  };

  // 互斥逻辑：选择最近时间时，清空时间范围
  const handleRangeChange = (val: string) => {
    if (val) {
      form.timeRange = [];
    }
  };

  // 互斥逻辑：选择时间范围时，清空最近时间
  const handleTimeRangeChange = (val: any[]) => {
    if (val && val.length > 0) {
      form.range = '';
    }
  };

  // 核心查询函数
  const executeQuery = async (
    query: string,
    limit: number,
    start?: number,
    end?: number,
    range?: string
  ) => {
    loading.value = true;
    try {
      const res = await queryLogs({ query, limit, start, end, range });
      // @ts-ignore
      const lokiData = res.data;
      const result = lokiData?.data?.result || [];

      const allLogs = result
        .map((item: any) => {
          const streamData = item.stream || {};
          return item.values.map((val: any[]) => {
            let timestampMs: number;
            let rawLogObject: any = {};

            try {
              rawLogObject = JSON.parse(val[1]);
            } catch (e) {
              // ignore
            }

            if (
              rawLogObject.ts &&
              !Number.isNaN(parseInt(rawLogObject.ts, 10))
            ) {
              timestampMs = parseInt(rawLogObject.ts, 10);
            } else {
              const nanoTs = val[0];
              if (nanoTs && nanoTs.length >= 13) {
                timestampMs = parseInt(nanoTs.substring(0, 13), 10);
              } else {
                timestampMs = 0;
              }
            }

            return {
              ...streamData,
              ...rawLogObject,
              ts: timestampMs,
              msg: rawLogObject.msg || streamData.msg || val[1],
              raw: val[1],
            };
          });
        })
        .flat()
        .sort((a: any, b: any) => b.ts - a.ts);

      data.value = allLogs;

      if (allLogs.length === limit && allLogs.length > 0) {
        const lastLogTs = allLogs[allLogs.length - 1].ts;
        timeCursors.value[currentPageIndex.value + 1] = lastLogTs * 1000000;
      } else {
        timeCursors.value.splice(currentPageIndex.value + 1);
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(err);
      Message.error(t('log.query.message.fail'));
      data.value = [];
      timeCursors.value.splice(currentPageIndex.value + 1);
    } finally {
      loading.value = false;
    }
  };

  // 构建LogQL查询语句
  const buildLogQL = () => {
    let logql = '{job="gms-audit"}';

    // 关键词模糊搜索，使用 case-insensitive regex 作用于原始日志行
    if (form.msg) {
      // Escape special regex characters to treat user input as a literal string
      const escapedMsg = form.msg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      logql += ` |~ "(?i)${escapedMsg}"`;
    }

    // 先解析JSON，再进行字段过滤
    logql += ' | json';

    if (form.mod) logql += ` | mod="${form.mod}"`;
    if (form.act) logql += ` | act="${form.act}"`;
    if (form.acc) {
      if (/^\d+$/.test(form.acc)) {
        logql += ` | (acc="${form.acc}" or aid="${form.acc}")`;
      } else {
        logql += ` | acc="${form.acc}"`;
      }
    }
    if (form.chr) {
      if (/^\d+$/.test(form.chr)) {
        logql += ` | (chr="${form.chr}" or cid="${form.chr}")`;
      } else {
        logql += ` | chr="${form.chr}"`;
      }
    }
    if (form.ip) logql += ` | ip="${form.ip}"`;
    if (form.hwid) logql += ` | hwid="${form.hwid}"`;
    if (form.mac) {
      const macs = form.mac
        .split(/[,，]/)
        .map((m) => m.trim())
        .filter((m) => m);
      if (macs.length > 0) {
        const regex = macs.join('|');
        logql += ` | macs =~ ".*(${regex}).*"`;
      }
    }
    return logql;
  };

  // 点击“搜索”按钮，发起新查询
  const search = () => {
    currentLogQL.value = buildLogQL();

    let startForFirstQuery: number | undefined;
    let endForFirstQuery: number | undefined;
    let rangeForFirstQuery: string | undefined;
    let endForCursor: number;

    if (form.timeRange && form.timeRange.length === 2) {
      const start = dayjs(form.timeRange[0]);
      const end = dayjs(form.timeRange[1]);
      startForFirstQuery = start.valueOf() * 1000000;
      endForFirstQuery = end.valueOf() * 1000000;
      paginationStart.value = startForFirstQuery;
      endForCursor = endForFirstQuery;
    } else {
      rangeForFirstQuery = form.range || '24h';
      if (!form.range) form.range = '24h';

      const now = dayjs();
      const rangeValue = parseInt(rangeForFirstQuery, 10);
      const rangeUnit = rangeForFirstQuery.slice(-1);
      const start = now.subtract(rangeValue, rangeUnit as any);

      paginationStart.value = start.valueOf() * 1000000;
      endForCursor = now.valueOf() * 1000000;
    }

    timeCursors.value = [endForCursor];
    currentPageIndex.value = 0;
    data.value = [];

    executeQuery(
      currentLogQL.value,
      form.limit,
      startForFirstQuery,
      endForFirstQuery,
      rangeForFirstQuery
    );
  };

  // 切换每页条数
  const handleLimitChange = () => {
    search();
  };

  // 前往更旧的页面 (下一页)
  const goToOlderPage = () => {
    if (!canGoOlder.value) return;
    currentPageIndex.value += 1;
    const end = timeCursors.value[currentPageIndex.value];
    executeQuery(
      currentLogQL.value,
      form.limit,
      paginationStart.value,
      end,
      undefined
    );
  };

  // 前往较新的页面 (上一页)
  const goToNewerPage = () => {
    if (!canGoNewer.value) return;
    currentPageIndex.value -= 1;
    const end = timeCursors.value[currentPageIndex.value];
    executeQuery(
      currentLogQL.value,
      form.limit,
      paginationStart.value,
      end,
      undefined
    );
  };

  const reset = () => {
    form.timeRange = [];
    form.range = '24h';
    form.mod = '';
    form.act = '';
    form.acc = '';
    form.chr = '';
    form.ip = '';
    form.mac = '';
    form.hwid = '';
    form.msg = '';
    form.limit = 100;
    search();
  };

  const formatTime = (ts: number) => {
    if (!ts || ts === 0) return '-';
    return dayjs(ts).format('YYYY-MM-DD HH:mm:ss.SSS');
  };

  const parseMacs = (macsStr: string) => {
    if (!macsStr) return [];
    try {
      const parsed = JSON.parse(macsStr);
      if (Array.isArray(parsed)) return parsed;
    } catch (e) {
      // ignore
    }
    return macsStr
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s);
  };

  onMounted(() => {
    fetchModules();
    search();
    window.addEventListener('resize', updateTableHeight);
    nextTick(() => {
      updateTableHeight();
    });
  });

  onUnmounted(() => {
    window.removeEventListener('resize', updateTableHeight);
  });
</script>

<style scoped lang="less">
  .container {
    padding: 0 20px 20px 20px;
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .general-card {
    flex: 1;
    display: flex;
    flex-direction: column;

    :deep(.arco-card-body) {
      flex: 1;
      display: flex;
      flex-direction: column;
      padding-bottom: 0;
    }
  }

  .pagination-controls {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 0;
    margin-bottom: 8px;
  }

  .table-container {
    flex: 1;
    overflow: hidden;
  }

  .log-raw {
    font-size: 12px;
    color: #86909c;
    font-family: monospace;
    word-break: break-all;
  }
  .info-row {
    display: flex;
    align-items: center;
    font-size: 12px;
    line-height: 1.5;

    .label {
      color: var(--color-text-3);
      width: 35px;
      text-align: right;
      margin-right: 2px;
    }

    .separator {
      width: 1px;
      height: 10px;
      background-color: var(--color-border-3);
      margin: 0 4px;
    }

    .value-id {
      color: var(--color-text-2);
      width: 25px;
      text-align: right;
      font-family: monospace;
    }

    .value {
      color: var(--color-text-1);
      flex: 1;
      margin-left: 0;
    }

    .text-ellipsis {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      display: block;
      max-width: 100%;
    }
  }
</style>
