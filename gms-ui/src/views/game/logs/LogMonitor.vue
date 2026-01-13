<template>
  <div class="log-monitor-container">
    <el-row :gutter="20" style="margin-bottom: 20px">
      <el-col :xs="24" :sm="12" :md="6">
        <el-statistic
          :title="$t('logs.monitor.indicator.qps')"
          :value="systemStats.qps"
          :value-style="{
            color: systemStats.qps > 1000 ? '#f56c6c' : '#67c23a',
          }"
        >
          <template #prefix>
            <i class="el-icon-data-analysis"></i>
          </template>
        </el-statistic>
      </el-col>
      <el-col :xs="24" :sm="12" :md="6">
        <el-statistic
          :title="$t('logs.monitor.indicator.successRate')"
          :value="`${systemStats.successRate}%`"
          :value-style="{
            color: systemStats.successRate >= 99 ? '#67c23a' : '#e6a23c',
          }"
        >
          <template #prefix>
            <i class="el-icon-success"></i>
          </template>
        </el-statistic>
      </el-col>
      <el-col :xs="24" :sm="12" :md="6">
        <el-statistic
          :title="$t('logs.monitor.indicator.avgLatency')"
          :value="`${systemStats.avgLatency}ms`"
          :value-style="{
            color: systemStats.avgLatency < 10 ? '#67c23a' : '#f56c6c',
          }"
        >
          <template #prefix>
            <i class="el-icon-timer"></i>
          </template>
        </el-statistic>
      </el-col>
      <el-col :xs="24" :sm="12" :md="6">
        <el-statistic
          :title="$t('logs.monitor.indicator.totalCount')"
          :value="systemStats.totalCount"
          :value-style="{ color: '#409eff' }"
        >
          <template #prefix>
            <i class="el-icon-tickets"></i>
          </template>
        </el-statistic>
      </el-col>
    </el-row>

    <el-row :gutter="20" style="margin-bottom: 20px">
      <el-col :xs="24" :md="12">
        <el-card class="monitor-card">
          <template #header>
            <div class="card-header">
              <span>{{ $t('logs.monitor.chart.categoryQps') }}</span>
              <el-button text bg size="small" @click="refreshCategoryStats"
                >刷新</el-button
              >
            </div>
          </template>
          <div id="categoryQpsChart" style="height: 300px"></div>
        </el-card>
      </el-col>
      <el-col :xs="24" :md="12">
        <el-card class="monitor-card">
          <template #header>
            <div class="card-header">
              <span>{{ $t('logs.monitor.chart.categorySuccessRate') }}</span>
              <el-button text bg size="small" @click="refreshCategoryStats"
                >刷新</el-button
              >
            </div>
          </template>
          <div id="categorySuccessRateChart" style="height: 300px"></div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" style="margin-bottom: 20px">
      <el-col :xs="24" :md="12">
        <el-card class="monitor-card">
          <template #header>
            <div class="card-header">
              <span>{{ $t('logs.monitor.chart.queueStats') }}</span>
              <el-button text bg size="small" @click="refreshQueueStats"
                >刷新</el-button
              >
            </div>
          </template>
          <div id="queueChart" style="height: 300px"></div>
        </el-card>
      </el-col>
      <el-col :xs="24" :md="12">
        <el-card class="monitor-card">
          <template #header>
            <div class="card-header">
              <span>{{ $t('logs.monitor.indicator.performanceMetrics') }}</span>
              <el-button text bg size="small" @click="refreshSystemStats"
                >刷新</el-button
              >
            </div>
          </template>
          <el-statistic-group>
            <el-row :gutter="30">
              <el-col :span="12">
                <el-statistic
                  :title="$t('logs.monitor.table.categoryStats.successCount')"
                  :value="systemStats.successCount"
                  :value-style="{ color: '#67c23a' }"
                >
                </el-statistic>
              </el-col>
              <el-col :span="12">
                <el-statistic
                  :title="$t('logs.monitor.table.categoryStats.failureCount')"
                  :value="systemStats.failureCount"
                  :value-style="{
                    color: systemStats.failureCount > 0 ? '#f56c6c' : '#67c23a',
                  }"
                >
                </el-statistic>
              </el-col>
            </el-row>
            <el-divider></el-divider>
            <el-row :gutter="30">
              <el-col :span="12">
                <el-statistic
                  :title="$t('logs.monitor.indicator.activeContext')"
                  :value="queueStats.activeContext"
                >
                </el-statistic>
              </el-col>
              <el-col :span="12">
                <el-statistic
                  :title="$t('logs.monitor.indicator.totalQueueDepth')"
                  :value="queueStats.totalQueueDepth"
                >
                </el-statistic>
              </el-col>
            </el-row>
          </el-statistic-group>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20">
      <el-col :span="24">
        <el-card class="monitor-card">
          <template #header>
            <div class="card-header">
              <span>{{ $t('logs.monitor.table.categoryStats') }}</span>
              <el-button text bg size="small" @click="refreshCategoryStats"
                >刷新</el-button
              >
            </div>
          </template>
          <el-table
            :data="categoryStatsTable"
            style="width: 100%"
            stripe
            max-height="600"
          >
            <el-table-column
              prop="categoryId"
              :label="$t('logs.monitor.table.categoryStats.category')"
              min-width="150"
            ></el-table-column>
            <el-table-column
              prop="totalCount"
              :label="$t('logs.monitor.table.categoryStats.totalCount')"
              width="80"
            ></el-table-column>
            <el-table-column
              prop="successCount"
              :label="$t('logs.monitor.table.categoryStats.successCount')"
              width="80"
            ></el-table-column>
            <el-table-column
              prop="failureCount"
              :label="$t('logs.monitor.table.categoryStats.failureCount')"
              width="80"
            ></el-table-column>
            <el-table-column
              :label="$t('logs.monitor.table.categoryStats.successRate')"
              width="100"
            >
              <template #default="scope">
                <el-progress
                  v-if="scope && scope.row"
                  :percentage="calculateSuccessRate(scope.row)"
                  :color="getSuccessRateColor(scope.row)"
                >
                </el-progress>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('logs.monitor.table.categoryStats.qps')"
              width="100"
            >
              <template #default="scope">
                <span v-if="scope && scope.row">{{
                  calculateQPS(scope.row)
                }}</span>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('logs.monitor.table.categoryStats.avgLatency')"
              width="120"
            >
              <template #default="scope">
                <span v-if="scope && scope.row">{{
                  calculateAvgLatency(scope.row)
                }}</span>
              </template>
            </el-table-column>
            <el-table-column
              prop="lastUpdateTime"
              :label="$t('logs.monitor.table.categoryStats.lastUpdate')"
              width="150"
            ></el-table-column>
          </el-table>
        </el-card>
      </el-col>
    </el-row>

    <div style="margin-top: 20px; text-align: right">
      <el-button
        v-if="!autoRefreshEnabled"
        type="primary"
        @click="startAutoRefresh"
      >
        {{ $t('logs.monitor.control.autoRefresh') }}
      </el-button>
      <el-button v-if="autoRefreshEnabled" @click="stopAutoRefresh">
        {{ $t('logs.monitor.control.stopAutoRefresh') }}
      </el-button>
      <el-button style="margin-left: 10px" @click="clearMonitorData">{{
        $t('logs.monitor.control.clearData')
      }}</el-button>
    </div>
  </div>
</template>

<script lang="ts">
  import logsApi from '@/api/logs';
  import * as echarts from 'echarts';

  export default {
    name: 'LogMonitor',
    data() {
      return {
        systemStats: {
          qps: 0,
          successRate: 0,
          avgLatency: 0,
          totalCount: 0,
          successCount: 0,
          failureCount: 0,
        },
        queueStats: {
          highQueueDepth: 0,
          mediumQueueDepth: 0,
          lowQueueDepth: 0,
          totalQueueDepth: 0,
          activeContext: 0,
        },
        categoryStats: [],
        categoryStatsTable: [],
        autoRefreshEnabled: false,
        autoRefreshTimer: null,
        charts: {
          categoryQps: null,
          categorySuccessRate: null,
          queue: null,
        },
      };
    },
    mounted() {
      this.refreshSystemStats();
      this.refreshCategoryStats();
      this.refreshQueueStats();
      this.refreshContextStats();
    },
    beforeUnmount() {
      if (this.autoRefreshTimer) {
        clearInterval(this.autoRefreshTimer);
      }
    },
    methods: {
      async refreshSystemStats() {
        try {
          const response = await logsApi.getSystemStats();
          if (response && response.code === 20000) {
            const stats = response.data;
            this.systemStats.totalCount = stats.totalCount;
            this.systemStats.successCount = stats.successCount;
            this.systemStats.failureCount = stats.failureCount;
            this.systemStats.successRate =
              stats.totalCount > 0
                ? Math.round((stats.successCount / stats.totalCount) * 100)
                : 0;

            // 计算QPS（这里需要实际的时间戳）
            this.systemStats.qps = Math.floor(stats.totalCount / 10);

            // 计算平均延迟
            this.systemStats.avgLatency =
              stats.totalTime > 0
                ? (stats.totalTime / stats.totalCount).toFixed(2)
                : 0;
          }
        } catch (error: unknown) {
          const msg = (error as any)?.message || 'Unknown error';
          this.$message.error(`获取系统统计失败: ${msg}`);
        }
      },
      async refreshCategoryStats() {
        try {
          const response = await logsApi.getCategoryStats();
          if (response && response.code === 20000) {
            this.categoryStats = response.data;
            this.categoryStatsTable = response.data;
            this.updateCategoryCharts();
          }
        } catch (error: unknown) {
          const msg = (error as any)?.message || 'Unknown error';
          this.$message.error(`获取分类统计失败: ${msg}`);
        }
      },
      async refreshQueueStats() {
        try {
          const response = await logsApi.getQueueStats();
          if (response && response.code === 20000) {
            // 解析队列统计信息
            const stats = response.data;
            const regex = /高频队列: (\d+), 中频队列: (\d+), 低频队列: (\d+)/;
            const match = stats.match(regex);
            if (match) {
              this.queueStats.highQueueDepth = parseInt(match[1], 10);
              this.queueStats.mediumQueueDepth = parseInt(match[2], 10);
              this.queueStats.lowQueueDepth = parseInt(match[3], 10);
              this.queueStats.totalQueueDepth =
                this.queueStats.highQueueDepth +
                this.queueStats.mediumQueueDepth +
                this.queueStats.lowQueueDepth;
            }
            this.updateQueueChart();
          }
        } catch (error: unknown) {
          const msg = (error as any)?.message || 'Unknown error';
          this.$message.error(`获取队列统计失败: ${msg}`);
        }
      },
      async refreshContextStats() {
        try {
          const response = await logsApi.getContextStats();
          if (response && response.code === 20000) {
            const stats = response.data;
            const match = stats.match(/活跃上下文: (\d+)/);
            if (match) {
              this.queueStats.activeContext = parseInt(match[1], 10);
            }
          }
        } catch (error: unknown) {
          const msg = (error as any)?.message || 'Unknown error';
          this.$message.error(`获取上下文统计失败: ${msg}`);
        }
      },
      updateCategoryCharts() {
        // 更新分类QPS图表
        const qpsData = this.categoryStats
          .sort((a, b) => this.calculateQPS(b) - this.calculateQPS(a))
          .slice(0, 10);

        const qpsCategoryNames = qpsData.map((d) => d.categoryId);
        const qpsValues = qpsData.map((d) => this.calculateQPS(d));

        const categoryQpsChart =
          echarts.getInstanceByDom(
            document.getElementById('categoryQpsChart')
          ) || echarts.init(document.getElementById('categoryQpsChart'));

        categoryQpsChart.setOption({
          xAxis: { type: 'category', data: qpsCategoryNames },
          yAxis: { type: 'value' },
          series: [
            {
              data: qpsValues,
              type: 'bar',
              itemStyle: { color: '#409eff' },
            },
          ],
          tooltip: { trigger: 'axis' },
        });

        // 更新分类成功率图表
        const successRateData = this.categoryStats
          .sort(
            (a, b) =>
              this.calculateSuccessRate(b) - this.calculateSuccessRate(a)
          )
          .slice(0, 10);

        const successRateCategoryNames = successRateData.map(
          (d) => d.categoryId
        );
        const successRateValues = successRateData.map((d) =>
          this.calculateSuccessRate(d)
        );

        const categorySuccessRateChart =
          echarts.getInstanceByDom(
            document.getElementById('categorySuccessRateChart')
          ) ||
          echarts.init(document.getElementById('categorySuccessRateChart'));

        categorySuccessRateChart.setOption({
          xAxis: { type: 'category', data: successRateCategoryNames },
          yAxis: { type: 'value', max: 100 },
          series: [
            {
              data: successRateValues,
              type: 'bar',
              itemStyle: { color: '#67c23a' },
            },
          ],
          tooltip: { trigger: 'axis' },
        });
      },
      updateQueueChart() {
        const queueChart =
          echarts.getInstanceByDom(document.getElementById('queueChart')) ||
          echarts.init(document.getElementById('queueChart'));

        queueChart.setOption({
          series: [
            {
              data: [
                { value: this.queueStats.highQueueDepth, name: '高频队列' },
                { value: this.queueStats.mediumQueueDepth, name: '中频队列' },
                { value: this.queueStats.lowQueueDepth, name: '低频队列' },
              ],
              type: 'pie',
            },
          ],
          legend: { orient: 'vertical', left: 'left' },
          tooltip: { trigger: 'item' },
        });
      },
      calculateQPS(stat) {
        return (stat.totalCount / 10).toFixed(1);
      },
      calculateSuccessRate(stat) {
        return stat.totalCount > 0
          ? Math.round((stat.successCount / stat.totalCount) * 100)
          : 0;
      },
      calculateAvgLatency(stat) {
        return stat.totalCount > 0
          ? (stat.totalTime / stat.totalCount).toFixed(2)
          : '0.00';
      },
      getSuccessRateColor(row) {
        const rate = this.calculateSuccessRate(row);
        if (rate >= 99) return '#67c23a';
        if (rate >= 95) return '#e6a23c';
        return '#f56c6c';
      },
      startAutoRefresh() {
        this.autoRefreshEnabled = true;
        this.autoRefreshTimer = setInterval(() => {
          this.refreshSystemStats();
          this.refreshCategoryStats();
          this.refreshQueueStats();
          this.refreshContextStats();
        }, 10000);
        this.$message.success('自动刷新已启用');
      },
      stopAutoRefresh() {
        this.autoRefreshEnabled = false;
        clearInterval(this.autoRefreshTimer);
        this.$message.success('自动刷新已停止');
      },
      async clearMonitorData() {
        try {
          const response = await logsApi.clearMonitorData();
          if (response && response.code === 20000) {
            this.$message.success('监控数据已清空');
            this.refreshSystemStats();
            this.refreshCategoryStats();
            this.refreshQueueStats();
            this.refreshContextStats();
          }
        } catch (error: unknown) {
          const msg = (error as any)?.message || 'Unknown error';
          this.$message.error(`清空数据失败: ${msg}`);
        }
      },
    },
  };
</script>

<style scoped>
  .log-monitor-container {
    padding: 0;
    background-color: transparent;
    min-height: 100%;
  }

  .monitor-card {
    background-color: white;
    border-radius: 6px;
    box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.08);
    margin-bottom: 20px;
    border: 1px solid #ebeef5;
    transition: box-shadow 0.3s ease, transform 0.3s ease;
  }

  .monitor-card:hover {
    box-shadow: 0 4px 20px 0 rgba(0, 0, 0, 0.12);
    transform: translateY(-2px);
  }

  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    width: 100%;
    font-weight: 600;
    color: #303133;
  }

  /* 统计指标样式 */
  ::v-deep .el-statistic__title {
    font-size: 12px;
    color: #909399;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  ::v-deep .el-statistic__content {
    font-size: 28px;
    font-weight: bold;
    color: #303133;
    font-family: 'Courier New', monospace;
  }

  /* 表格样式 */
  ::v-deep .el-table {
    font-size: 13px;
  }

  ::v-deep .el-table__header th {
    background-color: #f5f7fa;
    font-weight: 600;
    color: #303133;
  }

  ::v-deep .el-table__body tr:hover > td {
    background-color: #f5f7fa !important;
  }

  /* 按钮样式 */
  ::v-deep .el-button {
    border-radius: 4px;
    font-weight: 500;
    transition: all 0.3s ease;
  }

  ::v-deep .el-button:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px 0 rgba(0, 0, 0, 0.15);
  }

  /* 进度条样式 */
  ::v-deep .el-progress {
    margin: 0;
  }

  ::v-deep .el-progress__bar {
    border-radius: 3px;
  }

  /* 头部样式 - 统计面板 */
  ::v-deep .el-row {
    margin-bottom: 20px;
  }

  @media (max-width: 1200px) {
    .monitor-card {
      margin-bottom: 15px;
    }
  }

  @media (max-width: 768px) {
    .monitor-card {
      margin-bottom: 10px;
    }

    ::v-deep .el-statistic__content {
      font-size: 20px;
    }
  }
</style>