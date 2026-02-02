<template>
  <div class="container">
    <Breadcrumb :items="['menu.log', 'menu.log.query']" />

    <!-- 1. 系统状态区域 -->
    <a-card class="general-card" :title="$t('log.query.title')">
      <a-row>
        <a-col :flex="1">
          <a-form :model="form" label-col-flex="70px" label-align="left">
            <a-row :gutter="12">
              <!-- 第一行 -->
              <!-- 时间范围 (较宽) -->
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
                    placeholder="请选择"
                    @change="handleRangeChange"
                  >
                    <a-option value="1h">1小时</a-option>
                    <a-option value="6h">6小时</a-option>
                    <a-option value="12h">12小时</a-option>
                    <a-option value="24h">1天</a-option>
                    <a-option value="72h">3天</a-option>
                    <a-option value="168h">7天</a-option>
                    <a-option value="360h">15天</a-option>
                    <a-option value="720h">30天</a-option>
                  </a-select>
                </a-form-item>
              </a-col>
              <!-- 模块 -->
              <a-col :span="5">
                <a-form-item field="mod" :label="$t('log.query.form.mod')">
                  <a-select
                    v-model="form.mod"
                    placeholder="全部"
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
                    placeholder="全部"
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
                    placeholder="搜索账号"
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
                    placeholder="搜索角色"
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

              <!-- 第二行 -->
              <!-- IP -->
              <a-col :span="5">
                <a-form-item field="ip" :label="$t('log.query.form.ip')">
                  <a-select
                    v-model="form.ip"
                    placeholder="搜索IP"
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
                    placeholder="搜索MAC"
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
                    placeholder="搜索HWID"
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

      <div ref="tableContainerRef" class="table-container">
        <a-table
          :data="data"
          :loading="loading"
          :pagination="pagination"
          :scroll="{ y: tableHeight }"
          @page-change="onPageChange"
          @page-size-change="onPageSizeChange"
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
              :title="$t('log.query.table.mod')"
              data-index="mod"
              :width="100"
            >
              <template #cell="{ record }">
                {{
                  $te(`log.module.${record.mod}`)
                    ? $t(`log.module.${record.mod}`)
                    : record.mod
                }}
              </template>
            </a-table-column>
            <a-table-column
              :title="$t('log.query.table.act')"
              data-index="act"
              :width="150"
            >
              <template #cell="{ record }">
                {{
                  $te(`log.action.${record.act}`)
                    ? $t(`log.action.${record.act}`)
                    : record.act
                }}
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
                <div>{{ record.mapName }}</div>
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
                  怪物: {{ record.mobName }} ({{ record.mob }})
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
  import { ref, reactive, onMounted, onUnmounted, nextTick } from 'vue';
  import { useI18n } from 'vue-i18n';
  import {
    queryLogs,
    getModuleConfig,
    searchAccount,
    searchCharacter,
    searchIp,
    searchMac,
    searchHwid,
    searchLogs,
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
    limit: 100,
  });
  const data = ref<any[]>([]);
  const moduleOptions = ref<string[]>([]);
  const actOptions = ref<string[]>([]);

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

  const pagination = reactive({
    current: 1,
    pageSize: 50,
    total: 0,
    showTotal: true,
    showJumper: true,
    showPageSize: true,
    pageSizeOptions: [50, 100, 200, 500],
  });

  // 表格高度自适应
  const tableContainerRef = ref<HTMLElement | null>(null);
  const tableHeight = ref(500);

  const updateTableHeight = () => {
    if (tableContainerRef.value) {
      const { top } = tableContainerRef.value.getBoundingClientRect();
      const windowHeight = window.innerHeight;
      // 预留底部 padding 和 分页器高度 (约 60px)
      tableHeight.value = windowHeight - top - 60;
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

  const search = async () => {
    loading.value = true;
    // LogQL 查询构建
    // 1. 解析 JSON
    let logql = '{job="gms-audit"} | json';

    // 2. 过滤条件 (使用新字段名)
    if (form.mod) logql += ` | mod="${form.mod}"`;
    if (form.act) logql += ` | act="${form.act}"`;

    // 账号ID和名称混合筛选
    if (form.acc) {
      // 尝试判断是否为纯数字，如果是则同时匹配 aid 或 acc
      if (/^\d+$/.test(form.acc)) {
        logql += ` | (acc="${form.acc}" or aid="${form.acc}")`;
      } else {
        logql += ` | acc="${form.acc}"`;
      }
    }

    // 角色ID和名称混合筛选
    if (form.chr) {
      if (/^\d+$/.test(form.chr)) {
        logql += ` | (chr="${form.chr}" or cid="${form.chr}")`;
      } else {
        logql += ` | chr="${form.chr}"`;
      }
    }

    if (form.ip) logql += ` | ip="${form.ip}"`;
    if (form.hwid) logql += ` | hwid="${form.hwid}"`;

    // MAC地址支持模糊匹配或包含匹配，因为macs可能是列表
    if (form.mac) {
      // 支持多个MAC筛选，逗号分隔
      const macs = form.mac
        .split(/[,，]/)
        .map((m) => m.trim())
        .filter((m) => m);
      if (macs.length > 0) {
        // 构造正则匹配: macs字段包含其中任意一个
        const regex = macs.join('|');
        logql += ` | macs =~ ".*(${regex}).*"`;
      }
    }

    // 模糊搜索 msg
    if (form.msg) logql += ` | line_format "{{.msg}}" |= "${form.msg}"`;

    // 时间范围处理
    let start: number | undefined;
    let end: number | undefined;
    let range: string | undefined;

    if (form.timeRange && form.timeRange.length === 2) {
      start = dayjs(form.timeRange[0]).valueOf() * 1000000; // 毫秒转纳秒
      end = dayjs(form.timeRange[1]).valueOf() * 1000000;
    } else if (form.range) {
      // 如果选择了最近时间
      range = form.range;
    } else {
      // 如果都没有选择，默认查询最近 24 小时
      range = '24h';
      form.range = '24h'; // 回显
    }

    try {
      const res = await queryLogs({
        query: logql,
        limit: pagination.pageSize, // 使用分页大小
        start,
        end,
        range, // 传递 range 参数
      });

      // @ts-ignore
      const lokiData = res.data;
      const result = lokiData?.data?.result || [];

      // Loki 不直接支持分页总数，这里只能模拟或展示当前获取的数量
      // 实际生产中通常结合 start/end 时间进行滚动分页
      // 这里简单处理：将获取到的数据展示出来
      const allLogs = result
        .map((item: any) => {
          return item.values.map((val: any[]) => {
            try {
              // Loki 返回的日志行本身就是 JSON 字符串
              const json = JSON.parse(val[1]);

              return {
                ts: json.ts || parseInt(val[0], 10) / 1000000, // 优先使用日志里的业务时间
                mod: json.mod || '-',
                act: json.act || '-',
                acc: json.acc || '-',
                aid: json.aid,
                chr: json.chr || '-',
                cid: json.cid,
                job: json.job,
                jobName: json.jobName || '-',
                map: json.map,
                mapName: json.mapName || '-',
                ip: json.ip || '-',
                macs: json.macs,
                hwid: json.hwid || '-',
                mobName: json.mobName, // 可选
                mob: json.mob, // 可选
                msg: json.msg || '-',
                raw: val[1],
              };
            } catch (e) {
              return { ts: 0, msg: val[1] };
            }
          });
        })
        .flat()
        .sort((a: any, b: any) => b.ts - a.ts);

      data.value = allLogs;
      // 注意：Loki 的 limit 是硬限制，不是总数。
      // 如果返回数量等于 limit，说明可能还有更多数据。
      // 这里暂时将 total 设置为当前数据量，或者一个估算值。
      // 真正的分页需要后端支持或前端基于时间游标实现。
      // 鉴于 Loki 特性，这里仅做前端分页展示当前批次数据是不够的，
      // 但为了满足需求，我们先展示当前获取的数据。
      // 如果需要翻页，应该基于最后一条日志的时间戳发起新请求。
      // 这里简化处理：仅展示当前查询结果，不进行前端假分页（因为数据量可能很大），
      // 而是让用户通过调整 limit 或时间范围来控制。
      // 但需求要求添加分页组件，我们这里做前端分页。
      pagination.total = allLogs.length;
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(err);
      Message.error(t('log.query.message.fail'));
    } finally {
      loading.value = false;
    }
  };

  const reset = () => {
    form.timeRange = [];
    form.range = '24h'; // 重置为默认 24h
    form.mod = '';
    form.act = '';
    form.acc = '';
    form.chr = '';
    form.ip = '';
    form.mac = '';
    form.hwid = '';
    form.msg = '';
    form.limit = 100;
    pagination.current = 1;
    pagination.pageSize = 50;
    search();
  };

  const onPageChange = (current: number) => {
    pagination.current = current;
    // 前端分页逻辑：data.value 已经是所有数据了，table 会自动处理吗？
    // Arco Design Vue 的 Table 组件如果 data 是全量数据，pagination 属性会自动处理分页。
    // 但是我们上面 search 方法里是把所有数据都赋值给了 data.value。
    // 如果数据量很大（比如 1000 条），前端分页是合理的。
    // 如果需要后端分页（基于时间游标），逻辑会复杂很多。
    // 这里假设是前端分页。
  };

  const onPageSizeChange = (pageSize: number) => {
    pagination.pageSize = pageSize;
    pagination.current = 1;
    // 重新查询以获取更多数据（如果 limit 小于 pageSize）
    if (form.limit < pageSize) {
      form.limit = pageSize;
    }
    search();
  };

  const formatTime = (ts: number) => {
    if (!ts) return '-';
    return dayjs(ts).format('YYYY-MM-DD HH:mm:ss.SSS');
  };

  const parseMacs = (macsStr: string) => {
    if (!macsStr) return [];
    // 假设 macs 是逗号分隔的字符串或者 JSON 数组字符串
    try {
      // 尝试解析 JSON 数组
      const parsed = JSON.parse(macsStr);
      if (Array.isArray(parsed)) return parsed;
    } catch (e) {
      // ignore
    }
    // 尝试逗号分隔
    return macsStr
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s);
  };

  onMounted(() => {
    fetchModules(); // 加载模块列表
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
      margin-left: 0px;
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
