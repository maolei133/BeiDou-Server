<template>
  <div class="dashboard-container">
    <a-spin :loading="loading" style="width: 100%">
      <a-row :gutter="16" class="metrics-row">
        <a-col :span="6">
          <a-statistic
            :title="$t('logs.dashboard.metrics.totalLogs')"
            :value="overview?.metrics?.totalLogs || 0"
            show-group-separator
          />
        </a-col>
        <a-col :span="6">
          <a-statistic
            :title="$t('logs.dashboard.metrics.todayLogs')"
            :value="overview?.metrics?.todayLogs || 0"
            show-group-separator
          />
        </a-col>
        <a-col :span="6">
          <a-statistic
            :title="$t('logs.dashboard.metrics.avgLogs')"
            :value="overview?.metrics?.averageLogsPerSecond || 0"
            :precision="2"
          />
        </a-col>
        <a-col :span="6">
          <a-statistic
            :title="$t('logs.dashboard.metrics.alertsToday')"
            :value="overview?.metrics?.alertsToday || 0"
            :value-style="{ color: '#f53f3f' }"
          />
        </a-col>
      </a-row>

      <a-row :gutter="16" class="charts-row">
        <a-col :span="12">
          <a-card :title="$t('logs.dashboard.systemHealth')">
            <a-descriptions :column="2" bordered>
              <a-descriptions-item :label="$t('common.status')">
                <a-tag :color="healthStatusColor">
                  {{ overview?.systemHealth?.status || 'UNKNOWN' }}
                </a-tag>
              </a-descriptions-item>
              <a-descriptions-item label="CPU">
                {{ overview?.systemHealth?.cpuUsage || 'N/A' }}
              </a-descriptions-item>
              <a-descriptions-item label="Memory">
                {{ overview?.systemHealth?.memoryUsage || 'N/A' }}
              </a-descriptions-item>
              <a-descriptions-item label="Disk">
                {{ overview?.systemHealth?.diskUsage || 'N/A' }}
              </a-descriptions-item>
            </a-descriptions>
          </a-card>
        </a-col>

        <a-col :span="12">
          <a-card :title="$t('logs.dashboard.categoryStats')">
            <a-table
              :columns="categoryColumns"
              :data="categoryStatsData"
              :pagination="false"
              size="small"
            />
          </a-card>
        </a-col>
      </a-row>
    </a-spin>
  </div>
</template>

<script lang="ts">
  import { defineComponent, ref, computed, onMounted } from 'vue';
  import { useI18n } from 'vue-i18n';
  import { Message } from '@arco-design/web-vue';
  import { dashboardApi, type DashboardOverview } from '@/api/logsystem';

  export default defineComponent({
    name: 'Dashboard',
    setup() {
      const { t } = useI18n();
      const loading = ref(false);
      const overview = ref<DashboardOverview | null>(null);

      const healthStatusColor = computed(() => {
        const status = overview.value?.systemHealth?.status;
        if (status === 'HEALTHY') return 'green';
        if (status === 'WARNING') return 'orange';
        if (status === 'CRITICAL') return 'red';
        return 'gray';
      });

      const categoryStatsData = computed(() => {
        if (!overview.value?.categoryStats) return [];
        return Object.entries(overview.value.categoryStats).map(
          ([name, count]) => ({
            category: name,
            count,
          })
        );
      });

      const categoryColumns = [
        {
          title: t('logs.query.result.column.category'),
          dataIndex: 'category',
        },
        {
          title: t('logs.monitor.indicator.totalCount'),
          dataIndex: 'count',
        },
      ];

      const fetchDashboardData = async () => {
        loading.value = true;
        try {
          const response = await dashboardApi.getOverview();
          // 响应已经在 interceptor 中处理，成功时 response 就是 data
          if (response && response.data) {
            overview.value = response.data;
          }
        } catch (error) {
          Message.error(t('logs.message.error'));
          console.error('获取仪表板数据失败:', error);
        } finally {
          loading.value = false;
        }
      };

      onMounted(() => {
        fetchDashboardData();
      });

      return {
        loading,
        overview,
        healthStatusColor,
        categoryStatsData,
        categoryColumns,
      };
    },
  });
</script>

<style scoped lang="less">
  .dashboard-container {
    padding: 16px;

    .metrics-row {
      margin-bottom: 16px;

      :deep(.arco-statistic) {
        background: white;
        padding: 20px;
        border-radius: 4px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.06);
      }
    }

    .charts-row {
      :deep(.arco-card) {
        height: 100%;
      }
    }
  }
</style>
