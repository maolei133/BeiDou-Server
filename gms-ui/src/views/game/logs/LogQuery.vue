<template>
  <div class="log-query-container">
    <a-card class="filter-card" :title="$t('logs.query.filter.title')">
      <a-form :model="queryForm" layout="inline">
        <a-form-item :label="$t('logs.query.filter.keyword')">
          <a-input
            v-model="queryForm.keyword"
            :placeholder="$t('logs.query.filter.keywordPlaceholder')"
            allow-clear
            style="width: 200px"
          />
        </a-form-item>
        <a-form-item :label="$t('logs.query.filter.timeRange')">
          <a-range-picker
            v-model="queryForm.timeRange"
            show-time
            format="YYYY-MM-DD HH:mm:ss"
            style="width: 380px"
          />
        </a-form-item>
        <a-form-item>
          <a-space>
            <a-button type="primary" @click="handleQuery">
              {{ $t('logs.query.filter.query') }}
            </a-button>
            <a-button @click="handleReset">
              {{ $t('logs.query.filter.reset') }}
            </a-button>
            <a-button @click="handleExport">
              {{ $t('logs.query.result.export') }}
            </a-button>
          </a-space>
        </a-form-item>
      </a-form>
    </a-card>

    <a-card class="result-card" :title="$t('logs.query.result.title')">
      <template #extra>
        <span>{{
          $t('logs.query.result.total', { count: pagination.total })
        }}</span>
      </template>
      <a-table
        :columns="columns"
        :data="logData"
        :loading="loading"
        :pagination="pagination"
        @page-change="handlePageChange"
        @page-size-change="handlePageSizeChange"
      >
        <template #timestamp="{ record }">
          {{ formatTimestamp(record.timestamp) }}
        </template>
        <template #action="{ record }">
          <a-button type="text" size="small" @click="handleViewDetail(record)">
            {{ $t('logs.query.result.action') }}
          </a-button>
        </template>
      </a-table>
    </a-card>

    <a-modal
      v-model:visible="detailVisible"
      :title="$t('logs.query.detail.title')"
      :width="800"
      :footer="false"
    >
      <a-descriptions v-if="currentLog" :column="2" bordered>
        <a-descriptions-item :label="$t('logs.query.detail.timestamp')">
          {{ formatTimestamp(currentLog.timestamp) }}
        </a-descriptions-item>
        <a-descriptions-item :label="$t('logs.query.detail.level')">
          {{ currentLog.level }}
        </a-descriptions-item>
        <a-descriptions-item :label="$t('logs.query.detail.category')">
          {{ currentLog.category }}
        </a-descriptions-item>
        <a-descriptions-item :label="$t('logs.query.detail.message')" :span="2">
          {{ currentLog.message }}
        </a-descriptions-item>
        <a-descriptions-item
          v-if="currentLog.details"
          :label="$t('logs.query.detail.customData')"
          :span="2"
        >
          <pre>{{ currentLog.details }}</pre>
        </a-descriptions-item>
      </a-descriptions>
    </a-modal>
  </div>
</template>

<script lang="ts">
  import { defineComponent, reactive, ref, computed } from 'vue';
  import { useI18n } from 'vue-i18n';
  import { Message } from '@arco-design/web-vue';
  import { logQueryApi, type LogRecord } from '@/api/logsystem';
  import dayjs from 'dayjs';

  export default defineComponent({
    name: 'LogQuery',
    setup() {
      const { t } = useI18n();
      const loading = ref(false);
      const detailVisible = ref(false);
      const currentLog = ref<LogRecord | null>(null);

      const queryForm = reactive({
        keyword: '',
        timeRange: [
          dayjs().subtract(7, 'day').format('YYYY-MM-DD HH:mm:ss'),
          dayjs().format('YYYY-MM-DD HH:mm:ss'),
        ],
      });

      const logData = ref<LogRecord[]>([]);
      const pagination = reactive({
        current: 1,
        pageSize: 20,
        total: 0,
        showTotal: true,
        showPageSize: true,
      });

      const columns = computed(() => [
        {
          title: t('logs.query.result.column.timestamp'),
          dataIndex: 'timestamp',
          slotName: 'timestamp',
          width: 180,
        },
        {
          title: t('logs.query.result.column.category'),
          dataIndex: 'category',
          width: 150,
        },
        {
          title: t('logs.query.result.column.level'),
          dataIndex: 'level',
          width: 100,
        },
        {
          title: t('logs.query.result.column.message'),
          dataIndex: 'message',
          ellipsis: true,
          tooltip: true,
        },
        {
          title: t('common.operations'),
          slotName: 'action',
          width: 100,
        },
      ]);

      const formatTimestamp = (timestamp: string) => {
        return dayjs(timestamp).format('YYYY-MM-DD HH:mm:ss');
      };

      const fetchLogs = async () => {
        loading.value = true;
        try {
          const [startDate, endDate] = queryForm.timeRange;
          const response = await logQueryApi.query({
            keyword: queryForm.keyword || undefined,
            startDate,
            endDate,
            pageNum: pagination.current,
            pageSize: pagination.pageSize,
            sortField: 'timestamp',
            sortOrder: 'desc',
          });

          if (response && response.data) {
            const result = response.data;
            logData.value = result.records || [];
            pagination.total = result.totalCount || 0;
          }
        } catch (error) {
          Message.error(t('logs.message.error'));
          console.error('查询日志失败:', error);
        } finally {
          loading.value = false;
        }
      };

      const handleQuery = () => {
        pagination.current = 1;
        fetchLogs();
      };

      const handleReset = () => {
        queryForm.keyword = '';
        queryForm.timeRange = [
          dayjs().subtract(7, 'day').format('YYYY-MM-DD HH:mm:ss'),
          dayjs().format('YYYY-MM-DD HH:mm:ss'),
        ];
        pagination.current = 1;
        fetchLogs();
      };

      const handleExport = async () => {
        try {
          const [startDate, endDate] = queryForm.timeRange;
          const response = await logQueryApi.exportCsv({
            keyword: queryForm.keyword || undefined,
            startDate,
            endDate,
          });

          if (response && response.data) {
            const blob = new Blob([response.data], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `logs_${dayjs().format('YYYYMMDDHHmmss')}.csv`;
            link.click();
            window.URL.revokeObjectURL(url);
            Message.success(t('logs.message.success'));
          }
        } catch (error) {
          Message.error(t('logs.message.error'));
          console.error('导出日志失败:', error);
        }
      };

      const handlePageChange = (page: number) => {
        pagination.current = page;
        fetchLogs();
      };

      const handlePageSizeChange = (pageSize: number) => {
        pagination.pageSize = pageSize;
        pagination.current = 1;
        fetchLogs();
      };

      const handleViewDetail = (record: LogRecord) => {
        currentLog.value = record;
        detailVisible.value = true;
      };

      // 初始化加载
      fetchLogs();

      return {
        loading,
        detailVisible,
        currentLog,
        queryForm,
        logData,
        pagination,
        columns,
        formatTimestamp,
        handleQuery,
        handleReset,
        handleExport,
        handlePageChange,
        handlePageSizeChange,
        handleViewDetail,
      };
    },
  });
</script>

<style scoped lang="less">
  .log-query-container {
    padding: 16px;

    .filter-card {
      margin-bottom: 16px;
    }

    .result-card {
      :deep(.arco-card-body) {
        padding: 16px;
      }
    }

    pre {
      background-color: #f5f5f5;
      padding: 12px;
      border-radius: 4px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-wrap: break-word;
    }
  }
</style>
