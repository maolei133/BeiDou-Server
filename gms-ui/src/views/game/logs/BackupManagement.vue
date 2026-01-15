<template>
  <div class="backup-container">
    <!-- 页面标题 -->
    <div class="page-header">
      <h1>{{ $t('logsystem.backup.title') }}</h1>
      <div class="header-actions">
        <a-button type="primary" @click="performFullBackup">
          <template #icon><icon-plus /></template>
          {{ $t('logsystem.backup.fullBackup') }}
        </a-button>
        <a-button
          type="primary"
          status="success"
          @click="performIncrementalBackup"
        >
          <template #icon><icon-plus /></template>
          {{ $t('logsystem.backup.incrementalBackup') }}
        </a-button>
        <a-button @click="loadBackups">
          <template #icon><icon-refresh /></template>
          {{ $t('common.refresh') }}
        </a-button>
      </div>
    </div>

    <!-- 统计卡片 -->
    <a-row :gutter="16" style="margin-bottom: 20px">
      <a-col :xs="24" :sm="12" :md="6">
        <a-statistic
          :title="$t('logsystem.backup.totalBackups')"
          :value="statistics.totalBackups || 0"
          :value-style="{ color: '#1890ff' }"
        />
      </a-col>
      <a-col :xs="24" :sm="12" :md="6">
        <a-statistic
          :title="$t('logsystem.backup.successBackups')"
          :value="statistics.successfulBackups || 0"
          :value-style="{ color: '#52c41a' }"
        />
      </a-col>
      <a-col :xs="24" :sm="12" :md="6">
        <a-statistic
          :title="$t('logsystem.backup.totalSize')"
          :value="statistics.totalBackupSize || 0"
        >
          <template #formatter="{ value }">
            {{ formatSize(Number(value)) }}
          </template>
        </a-statistic>
      </a-col>
      <a-col :xs="24" :sm="12" :md="6">
        <a-statistic
          :title="$t('logsystem.backup.avgCompression')"
          :value="
            statistics.averageCompressionRatio
              ? parseFloat(statistics.averageCompressionRatio)
              : 0
          "
          :precision="2"
        >
          <template #suffix>%</template>
        </a-statistic>
      </a-col>
    </a-row>

    <!-- 备份列表 -->
    <a-card class="backup-list-card">
      <template #title>
        {{ $t('logsystem.backup.backupList') }}
      </template>

      <a-table
        :columns="columns"
        :data-source="backups"
        :loading="loading"
        :pagination="pagination"
        :scroll="{ x: 1200 }"
        size="small"
        row-key="backupId"
      >
        <!-- 备份类型 -->
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'backupType'">
            <a-tag :color="getTypeColor(record.backupType)">
              {{ record.backupType }}
            </a-tag>
          </template>

          <!-- 状态 -->
          <template v-else-if="column.key === 'status'">
            <a-tag :color="getStatusColor(record.status)">
              {{ record.status }}
            </a-tag>
          </template>

          <!-- 大小 -->
          <template v-else-if="column.key === 'fileSize'">
            <span
              >{{ formatSize(record.fileSize) }} ({{
                formatSize(record.compressedSize)
              }})</span
            >
          </template>

          <!-- 压缩率 -->
          <template v-else-if="column.key === 'compressionRatio'">
            <a-progress
              :percent="record.compressionRatio || 0"
              :size="'small'"
              show-text
              :format="(percent) => `${percent}%`"
            />
          </template>

          <!-- 操作 -->
          <template v-else-if="column.key === 'operations'">
            <div class="operation-cell">
              <a-button type="text" size="small" @click="viewDetail(record)">
                {{ $t('common.detail') }}
              </a-button>
              <a-divider direction="vertical" />
              <a-popconfirm
                :title="$t('logsystem.backup.restoreConfirm')"
                @ok="restoreBackup(record.backupId)"
              >
                <template #okText>{{ $t('common.yes') }}</template>
                <template #cancelText>{{ $t('common.no') }}</template>
                <a-button
                  type="text"
                  size="small"
                  :disabled="record.status !== 'SUCCESS'"
                >
                  {{ $t('logsystem.backup.restore') }}
                </a-button>
              </a-popconfirm>
              <a-divider direction="vertical" />
              <a-popconfirm
                :title="$t('common.deleteConfirm')"
                @ok="deleteBackup(record.backupId)"
              >
                <template #okText>{{ $t('common.yes') }}</template>
                <template #cancelText>{{ $t('common.no') }}</template>
                <a-button type="text" status="danger" size="small">
                  {{ $t('common.delete') }}
                </a-button>
              </a-popconfirm>
            </div>
          </template>
        </template>
      </a-table>
    </a-card>

    <!-- 备份策略卡片 -->
    <a-card class="strategy-card" style="margin-top: 20px">
      <template #title>
        {{ $t('logsystem.backup.strategy') }}
      </template>

      <a-form
        :model="strategy"
        :label-col="{ span: 6 }"
        :wrapper-col="{ span: 18 }"
      >
        <!-- 备份类型 -->
        <a-form-item :label="$t('logsystem.backup.defaultType')">
          <a-select v-model="strategy.backupType">
            <a-option value="FULL">{{ $t('logsystem.backup.full') }}</a-option>
            <a-option value="INCREMENTAL">{{
              $t('logsystem.backup.incremental')
            }}</a-option>
          </a-select>
        </a-form-item>

        <!-- 压缩算法 -->
        <a-form-item :label="$t('logsystem.backup.compression')">
          <a-select v-model="strategy.compressionAlgorithm">
            <a-option value="GZIP">GZIP (高压缩率)</a-option>
            <a-option value="ZIP">ZIP (平衡)</a-option>
            <a-option value="7Z">7Z (超高压缩率)</a-option>
            <a-option value="NONE">NONE (无压缩)</a-option>
          </a-select>
        </a-form-item>

        <!-- 保留天数 -->
        <a-form-item :label="$t('logsystem.backup.retentionDays')">
          <a-input-number
            v-model="strategy.retentionDays"
            :min="1"
            :max="365"
          />
        </a-form-item>

        <!-- 是否启用 -->
        <a-form-item :label="$t('logsystem.backup.enabled')">
          <a-switch v-model="strategy.enabled" />
        </a-form-item>

        <!-- 完整性验证 -->
        <a-form-item :label="$t('logsystem.backup.verifyIntegrity')">
          <a-switch v-model="strategy.verifyIntegrity" />
        </a-form-item>

        <!-- 是否加密 -->
        <a-form-item :label="$t('logsystem.backup.encrypted')">
          <a-switch v-model="strategy.encrypted" />
        </a-form-item>

        <!-- 加密密钥 -->
        <a-form-item
          v-if="strategy.encrypted"
          :label="$t('logsystem.backup.encryptionKey')"
        >
          <a-input
            v-model="strategy.encryptionKey"
            type="password"
            :placeholder="$t('logsystem.backup.encryptionKeyPlaceholder')"
          />
        </a-form-item>

        <!-- 保存按钮 -->
        <a-form-item :wrapper-col="{ offset: 6, span: 18 }">
          <a-button type="primary" @click="saveStrategy">
            {{ $t('common.save') }}
          </a-button>
        </a-form-item>
      </a-form>
    </a-card>

    <!-- 详情对话框 -->
    <a-modal
      v-model:visible="showDetailModal"
      :title="$t('logsystem.backup.backupDetail')"
      width="800px"
    >
      <a-descriptions v-if="selectedBackup" :column="1" bordered>
        <a-descriptions-item :label="$t('logsystem.backup.backupId')">
          {{ selectedBackup.backupId }}
        </a-descriptions-item>
        <a-descriptions-item :label="$t('logsystem.backup.type')">
          <a-tag :color="getTypeColor(selectedBackup.backupType)">
            {{ selectedBackup.backupType }}
          </a-tag>
        </a-descriptions-item>
        <a-descriptions-item :label="$t('logsystem.backup.status')">
          <a-tag :color="getStatusColor(selectedBackup.status)">
            {{ selectedBackup.status }}
          </a-tag>
        </a-descriptions-item>
        <a-descriptions-item :label="$t('logsystem.backup.fileSize')">
          {{ formatSize(selectedBackup.fileSize) }}
        </a-descriptions-item>
        <a-descriptions-item :label="$t('logsystem.backup.compressedSize')">
          {{ formatSize(selectedBackup.compressedSize) }}
        </a-descriptions-item>
        <a-descriptions-item :label="$t('logsystem.backup.compressionRatio')">
          {{ selectedBackup.compressionRatio }}%
        </a-descriptions-item>
        <a-descriptions-item :label="$t('logsystem.backup.startTime')">
          {{ formatDateTime(selectedBackup.startTime) }}
        </a-descriptions-item>
        <a-descriptions-item :label="$t('logsystem.backup.endTime')">
          {{ formatDateTime(selectedBackup.endTime) }}
        </a-descriptions-item>
        <a-descriptions-item :label="$t('logsystem.backup.duration')">
          {{ selectedBackup.durationMillis }}ms
        </a-descriptions-item>
        <a-descriptions-item :label="$t('logsystem.backup.logCount')">
          {{ selectedBackup.logCount }}
        </a-descriptions-item>
        <a-descriptions-item :label="$t('logsystem.backup.checksum')">
          <span
            style="
              word-break: break-all;
              font-family: monospace;
              font-size: 12px;
            "
          >
            {{ selectedBackup.checksum }}
          </span>
        </a-descriptions-item>
        <a-descriptions-item :label="$t('logsystem.backup.integrityVerified')">
          <a-tag :color="selectedBackup.integrityVerified ? 'green' : 'red'">
            {{ selectedBackup.integrityVerified ? '已验证' : '未验证' }}
          </a-tag>
        </a-descriptions-item>
      </a-descriptions>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
  import { ref, onMounted } from 'vue';
  import { Message } from '@arco-design/web-vue';
  import { IconPlus, IconRefresh } from '@arco-design/web-vue/es/icon';
  import { useI18n } from 'vue-i18n';
  import logsApi from '@/api/logs';

  const { t } = useI18n();

  interface BackupMetadata {
    backupId: string;
    backupType: string;
    status: string;
    fileSize: number;
    compressedSize: number;
    compressionRatio: number;
    startTime: string;
    endTime: string;
    durationMillis: number;
    logCount: number;
    checksum: string;
    integrityVerified: boolean;
  }

  interface BackupStrategy {
    backupType: string;
    compressionAlgorithm: string;
    retentionDays: number;
    enabled: boolean;
    verifyIntegrity: boolean;
    encrypted: boolean;
    encryptionKey?: string;
  }

  // 备份列表
  const backups = ref<BackupMetadata[]>([]);
  const loading = ref(false);
  const pagination = ref({
    current: 1,
    pageSize: 10,
    total: 0,
  });

  // 统计信息
  const statistics = ref({
    totalBackups: 0,
    successfulBackups: 0,
    totalBackupSize: 0,
    averageCompressionRatio: '0%',
  });

  // 备份策略
  const strategy = ref<BackupStrategy>({
    backupType: 'FULL',
    compressionAlgorithm: 'GZIP',
    retentionDays: 30,
    enabled: true,
    verifyIntegrity: true,
    encrypted: false,
  });

  // 详情对话框
  const showDetailModal = ref(false);
  const selectedBackup = ref<BackupMetadata | null>(null);

  // 表格列定义
  const columns = [
    {
      title: t('logsystem.backup.backupId', '备份ID'),
      dataIndex: 'backupId',
      key: 'backupId',
      width: 200,
    },
    {
      title: t('logsystem.backup.type', '类型'),
      dataIndex: 'backupType',
      key: 'backupType',
      width: 100,
    },
    {
      title: t('logsystem.backup.status', '状态'),
      dataIndex: 'status',
      key: 'status',
      width: 100,
    },
    {
      title: t('logsystem.backup.size', '大小'),
      dataIndex: 'fileSize',
      key: 'fileSize',
      width: 180,
    },
    {
      title: t('logsystem.backup.compressionRatio', '压缩率'),
      dataIndex: 'compressionRatio',
      key: 'compressionRatio',
      width: 150,
    },
    {
      title: t('logsystem.backup.startTime', '开始时间'),
      dataIndex: 'startTime',
      key: 'startTime',
      width: 180,
    },
    {
      title: t('common.operations', '操作'),
      dataIndex: 'operations',
      key: 'operations',
      width: 200,
    },
  ];

  // 加载备份列表
  const loadBackups = async () => {
    loading.value = true;
    try {
      const { data: backupList } = await logsApi.getBackupList();
      backups.value = backupList || [];
      pagination.value.total = backups.value.length;
    } catch (error) {
      Message.error(t('common.loadFailed'));
    } finally {
      loading.value = false;
    }
  };

  // 加载统计信息
  const loadStatistics = async () => {
    try {
      const { data: stats } = await logsApi.getBackupStatistics();
      statistics.value = stats || {};
    } catch (error) {
      // ignore
    }
  };

  // 加载备份策略
  const loadStrategy = async () => {
    try {
      const { data: strategyData } = await logsApi.getBackupStrategy();
      strategy.value = strategyData || strategy.value;
    } catch (error) {
      // ignore
    }
  };

  // 执行完整备份
  const performFullBackup = async () => {
    try {
      await logsApi.performFullBackup();
      Message.success(t('logsystem.backup.backupStarted'));
      setTimeout(() => {
        loadBackups();
        loadStatistics();
      }, 2000);
    } catch (error) {
      Message.error(t('common.failed'));
    }
  };

  // 执行增量备份
  const performIncrementalBackup = async () => {
    try {
      await logsApi.performIncrementalBackup();
      Message.success(t('logsystem.backup.backupStarted'));
      setTimeout(() => {
        loadBackups();
        loadStatistics();
      }, 2000);
    } catch (error) {
      Message.error(t('common.failed'));
    }
  };

  // 恢复备份
  const restoreBackup = async (backupId: string) => {
    try {
      await logsApi.restoreBackup(backupId);
      Message.success(t('logsystem.backup.restoreSuccess'));
    } catch (error) {
      Message.error(t('common.failed'));
    }
  };

  // 删除备份
  const deleteBackup = async (backupId: string) => {
    try {
      await logsApi.deleteBackup(backupId);
      Message.success(t('common.deleted'));
      loadBackups();
      loadStatistics();
    } catch (error) {
      Message.error(t('common.failed'));
    }
  };

  // 查看详情
  const viewDetail = (backup: BackupMetadata) => {
    selectedBackup.value = backup;
    showDetailModal.value = true;
  };

  // 保存策略
  const saveStrategy = async () => {
    try {
      await logsApi.updateBackupStrategy(strategy.value);
      Message.success(t('common.saved'));
    } catch (error) {
      Message.error(t('common.failed'));
    }
  };

  const formatSize = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${Math.round((bytes / k ** i) * 100) / 100} ${sizes[i]}`;
  };

  const formatDateTime = (dateTime: string): string => {
    return new Date(dateTime).toLocaleString();
  };

  const getTypeColor = (type: string): string => {
    return type === 'FULL' ? 'blue' : 'green';
  };

  const getStatusColor = (status: string): string => {
    const colors: Record<string, string> = {
      SUCCESS: 'green',
      FAILURE: 'red',
      PARTIAL: 'orange',
      IN_PROGRESS: 'blue',
    };
    return colors[status] || 'default';
  };

  onMounted(() => {
    loadBackups();
    loadStatistics();
    loadStrategy();
  });
</script>

<style scoped lang="less">
  .backup-container {
    padding: 20px;

    .page-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;

      h1 {
        margin: 0;
        font-size: 24px;
      }

      .header-actions {
        display: flex;
        gap: 10px;
      }
    }

    .backup-list-card,
    .strategy-card {
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
    }

    .operation-cell {
      display: flex;
      align-items: center;
      gap: 4px;
    }
  }
</style>
