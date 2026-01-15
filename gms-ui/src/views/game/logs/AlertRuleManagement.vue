<template>
  <div class="alert-rule-container">
    <!-- 页面标题 -->
    <div class="page-header">
      <h1>{{ $t('logsystem.alertRules.title') }}</h1>
      <div class="header-actions">
        <a-button type="primary" @click="showCreateModal = true">
          <template #icon><icon-plus /></template>
          {{ $t('logsystem.alertRules.create') }}
        </a-button>
        <a-button @click="loadRules">
          <template #icon><icon-refresh /></template>
          {{ $t('common.refresh') }}
        </a-button>
      </div>
    </div>

    <!-- 统计卡片 -->
    <a-row :gutter="16" style="margin-bottom: 20px">
      <a-col :xs="24" :sm="12" :md="6">
        <a-statistic
          :title="$t('logsystem.alertRules.totalRules')"
          :value="statistics.totalRules || 0"
          :value-style="{ color: '#1890ff' }"
        />
      </a-col>
      <a-col :xs="24" :sm="12" :md="6">
        <a-statistic
          :title="$t('logsystem.alertRules.enabledRules')"
          :value="statistics.enabledRules || 0"
          :value-style="{ color: '#52c41a' }"
        />
      </a-col>
      <a-col :xs="24" :sm="12" :md="6">
        <a-statistic
          :title="$t('logsystem.alertRules.unresolvedAlerts')"
          :value="statistics.unresolvedAlerts || 0"
          :value-style="{ color: '#ff4d4f' }"
        />
      </a-col>
      <a-col :xs="24" :sm="12" :md="6">
        <a-statistic
          :title="$t('logsystem.alertRules.alertsLast24h')"
          :value="statistics.alertsLast24h || 0"
          :value-style="{ color: '#faad14' }"
        />
      </a-col>
    </a-row>

    <!-- 规则列表 -->
    <a-card class="rule-list-card">
      <a-table
        :columns="columns"
        :data-source="rules"
        :loading="loading"
        :pagination="pagination"
        :scroll="{ x: 1200 }"
        size="small"
        row-key="id"
      >
        <!-- 规则名称 -->
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'ruleName'">
            <div class="rule-name-cell">
              <span
                class="rule-badge"
                :style="{
                  backgroundColor: getConditionColor(record.conditionType),
                }"
              >
                {{ record.conditionType }}
              </span>
              <span class="rule-name">{{ record.ruleName }}</span>
            </div>
          </template>

          <!-- 条件显示 -->
          <template v-else-if="column.key === 'condition'">
            <div class="condition-display">
              <span
                >{{ record.conditionType }} {{ record.operator }}
                {{ record.threshold }}</span
              >
              <a-divider direction="vertical" />
              <span>{{ record.duration }}s</span>
            </div>
          </template>

          <!-- 动作 -->
          <template v-else-if="column.key === 'action'">
            <div class="action-display">
              <a-tag :color="getActionColor(record.actionType)">{{
                record.actionType
              }}</a-tag>
              <a-divider direction="vertical" />
              <span class="action-target">{{ record.actionTarget }}</span>
            </div>
          </template>

          <!-- 状态 -->
          <template v-else-if="column.key === 'status'">
            <a-switch
              v-model:checked="record.enabled"
              size="small"
              @change="toggleRuleStatus(record.id)"
            />
          </template>

          <!-- 操作 -->
          <template v-else-if="column.key === 'operations'">
            <div class="operation-cell">
              <a-button
                type="text"
                size="small"
                @click="viewHistory(record.id)"
              >
                {{ $t('logsystem.alertRules.history') }}
              </a-button>
              <a-divider direction="vertical" />
              <a-button type="text" size="small" @click="editRule(record)">
                {{ $t('common.edit') }}
              </a-button>
              <a-divider direction="vertical" />
              <a-popconfirm
                :title="$t('common.deleteConfirm')"
                @ok="deleteRule(record.id)"
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

    <!-- 创建/编辑规则对话框 -->
    <a-modal
      v-model:visible="showCreateModal"
      :title="
        editingRule
          ? $t('logsystem.alertRules.editRule')
          : $t('logsystem.alertRules.createRule')
      "
      @ok="saveRule"
    >
      <a-form
        :model="formData"
        :label-col="{ span: 6 }"
        :wrapper-col="{ span: 18 }"
      >
        <!-- 规则名称 -->
        <a-form-item
          :label="$t('logsystem.alertRules.ruleName')"
          field="ruleName"
        >
          <a-input
            v-model="formData.ruleName"
            :placeholder="$t('logsystem.alertRules.ruleNamePlaceholder')"
          />
        </a-form-item>

        <!-- 描述 -->
        <a-form-item
          :label="$t('logsystem.alertRules.description')"
          field="description"
        >
          <a-textarea
            v-model="formData.description"
            :placeholder="$t('logsystem.alertRules.descriptionPlaceholder')"
          />
        </a-form-item>

        <!-- 条件配置 -->
        <a-divider style="margin: 10px 0">
          {{ $t('logsystem.alertRules.conditionConfig') }}
        </a-divider>

        <!-- 条件类型 -->
        <a-form-item
          :label="$t('logsystem.alertRules.conditionType')"
          field="conditionType"
        >
          <a-select v-model="formData.conditionType">
            <a-option value="FailureRate">FailureRate (失败率)</a-option>
            <a-option value="Latency">Latency (延迟)</a-option>
            <a-option value="QPS">QPS (吞吐量)</a-option>
            <a-option value="MemoryUsage">MemoryUsage (内存)</a-option>
            <a-option value="CustomExpression"
              >CustomExpression (自定义)</a-option
            >
          </a-select>
        </a-form-item>

        <!-- 阈值 -->
        <a-form-item
          :label="$t('logsystem.alertRules.threshold')"
          field="threshold"
        >
          <a-input-number
            v-model="formData.threshold"
            :min="0"
            :placeholder="$t('logsystem.alertRules.thresholdPlaceholder')"
          />
        </a-form-item>

        <!-- 操作符 -->
        <a-form-item
          :label="$t('logsystem.alertRules.operator')"
          field="operator"
        >
          <a-select v-model="formData.operator">
            <a-option value="&gt;">大于 (&amp;gt;)</a-option>
            <a-option value="&lt;">小于 (&amp;lt;)</a-option>
            <a-option value="&gt;=">&amp;gt;=</a-option>
            <a-option value="&lt;=">&amp;lt;=</a-option>
            <a-option value="==">==</a-option>
            <a-option value="!=">!=</a-option>
          </a-select>
        </a-form-item>

        <!-- 持续时间 -->
        <a-form-item
          :label="$t('logsystem.alertRules.duration')"
          field="duration"
        >
          <a-input-number
            v-model="formData.duration"
            :min="1"
            :placeholder="$t('logsystem.alertRules.durationPlaceholder')"
          />
        </a-form-item>

        <!-- 动作配置 -->
        <a-divider style="margin: 10px 0">
          {{ $t('logsystem.alertRules.actionConfig') }}
        </a-divider>

        <!-- 动作类型 -->
        <a-form-item
          :label="$t('logsystem.alertRules.actionType')"
          field="actionType"
        >
          <a-select v-model="formData.actionType">
            <a-option value="LOG">LOG (日志)</a-option>
            <a-option value="EMAIL">EMAIL (邮件)</a-option>
            <a-option value="SMS">SMS (短信)</a-option>
            <a-option value="WEBHOOK">WEBHOOK (Webhook)</a-option>
            <a-option value="DATABASE">DATABASE (数据库)</a-option>
          </a-select>
        </a-form-item>

        <!-- 动作目标 -->
        <a-form-item
          :label="$t('logsystem.alertRules.actionTarget')"
          field="actionTarget"
        >
          <a-input
            v-model="formData.actionTarget"
            :placeholder="$t('logsystem.alertRules.actionTargetPlaceholder')"
          />
        </a-form-item>

        <!-- 告警间隔 -->
        <a-form-item
          :label="$t('logsystem.alertRules.alertInterval')"
          field="alertInterval"
        >
          <a-input-number
            v-model="formData.alertInterval"
            :min="1"
            :placeholder="$t('logsystem.alertRules.alertIntervalPlaceholder')"
          />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 告警历史对话框 -->
    <a-modal
      v-model:visible="showHistoryModal"
      :title="$t('logsystem.alertRules.alertHistory')"
      width="900px"
    >
      <a-table
        :columns="historyColumns"
        :data-source="alertHistory"
        :loading="historyLoading"
        size="small"
        row-key="id"
        :pagination="false"
      >
        <template #bodyCell="{ column, record }">
          <!-- 严重级别 -->
          <template v-if="column.key === 'severity'">
            <a-tag :color="getSeverityColor(record.severity)">
              {{ record.severity }}
            </a-tag>
          </template>

          <!-- 状态 -->
          <template v-else-if="column.key === 'status'">
            <a-tag :color="getStatusColor(record.status)">
              {{ record.status }}
            </a-tag>
          </template>
        </template>
      </a-table>
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

  interface AlertRule {
    id: number;
    ruleName: string;
    description: string;
    conditionType: string;
    threshold: number;
    operator: string;
    duration: number;
    actionType: string;
    actionTarget: string;
    alertInterval: number;
    enabled: boolean;
  }

  // 列表数据
  const rules = ref<AlertRule[]>([]);
  const loading = ref(false);
  const pagination = ref({
    current: 1,
    pageSize: 10,
    total: 0,
  });

  // 统计信息
  const statistics = ref({
    totalRules: 0,
    enabledRules: 0,
    unresolvedAlerts: 0,
    alertsLast24h: 0,
  });

  // 创建/编辑对话框
  const showCreateModal = ref(false);
  const editingRule = ref<AlertRule | null>(null);
  const formData = ref<Partial<AlertRule>>({
    conditionType: 'FailureRate',
    operator: '>',
    duration: 60,
    actionType: 'LOG',
    alertInterval: 60,
  });

  // 历史对话框
  const showHistoryModal = ref(false);
  const alertHistory = ref([]);
  const historyLoading = ref(false);
  const currentRuleId = ref<number | null>(null);

  // 表格列定义
  const columns = [
    {
      title: t('logsystem.alertRules.ruleName', '规则名称'),
      dataIndex: 'ruleName',
      key: 'ruleName',
      width: 200,
    },
    {
      title: t('logsystem.alertRules.condition', '条件'),
      dataIndex: 'condition',
      key: 'condition',
      width: 180,
    },
    {
      title: t('logsystem.alertRules.action', '动作'),
      dataIndex: 'action',
      key: 'action',
      width: 150,
    },
    {
      title: t('logsystem.alertRules.status', '状态'),
      dataIndex: 'status',
      key: 'status',
      width: 80,
    },
    {
      title: t('common.operations', '操作'),
      dataIndex: 'operations',
      key: 'operations',
      width: 200,
    },
  ];

  const historyColumns = [
    {
      title: t('logsystem.alertRules.alertTime', '告警时间'),
      dataIndex: 'alertTime',
      width: 180,
    },
    {
      title: t('logsystem.alertRules.actualValue', '实际值'),
      dataIndex: 'actualValue',
      width: 100,
    },
    {
      title: t('logsystem.alertRules.severity', '严重级别'),
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
    },
    {
      title: t('logsystem.alertRules.message', '消息'),
      dataIndex: 'message',
      width: 300,
    },
    {
      title: t('logsystem.alertRules.status', '状态'),
      dataIndex: 'status',
      key: 'status',
      width: 100,
    },
  ];

  // 加载规则列表
  const loadRules = async () => {
    loading.value = true;
    try {
      const { data: ruleList } = await logsApi.getAlertRules();
      rules.value = ruleList || [];
    } catch (error) {
      Message.error(t('common.loadFailed'));
    } finally {
      loading.value = false;
    }
  };

  // 加载统计信息
  const loadStatistics = async (): Promise<void> => {
    try {
      const { data: stats } = await logsApi.getAlertStatistics();
      statistics.value = stats || {};
    } catch (error) {
      // ignore
    }
  };

  // 重置表单
  const resetForm = (): void => {
    editingRule.value = null;
    formData.value = {
      conditionType: 'FailureRate',
      operator: '>',
      duration: 60,
      actionType: 'LOG',
      alertInterval: 60,
    };
  };

  // 保存规则
  const saveRule = async () => {
    try {
      if (!formData.value.ruleName) {
        Message.error(t('common.required'));
        return;
      }

      if (editingRule.value) {
        await logsApi.updateAlertRule(
          editingRule.value.id.toString(),
          formData.value
        );
      } else {
        await logsApi.createAlertRule(formData.value);
      }

      Message.success(t('common.success'));
      showCreateModal.value = false;
      resetForm();
      loadRules();
      loadStatistics();
    } catch (error) {
      Message.error(t('common.failed'));
    }
  };

  // 编辑规则
  const editRule = (rule: AlertRule) => {
    editingRule.value = rule;
    formData.value = { ...rule };
    showCreateModal.value = true;
  };

  // 删除规则
  const deleteRule = async (id: number) => {
    try {
      await logsApi.deleteAlertRule(id.toString());
      Message.success(t('common.deleted'));
      loadRules();
      loadStatistics();
    } catch (error) {
      Message.error(t('common.failed'));
    }
  };

  // 切换规则状态
  const toggleRuleStatus = async (id: number) => {
    try {
      const rule = rules.value.find((r) => r.id === id);
      if (!rule) return;

      if (rule.enabled) {
        await logsApi.disableAlertRule(id.toString());
      } else {
        await logsApi.enableAlertRule(id.toString());
      }

      Message.success(t('common.success'));
      loadStatistics();
    } catch (error) {
      Message.error(t('common.failed'));
    }
  };

  // 查看告警历史
  const viewHistory = async (id: number) => {
    historyLoading.value = true;
    currentRuleId.value = id;
    try {
      const { data: history } = await logsApi.getAlertHistory(id);
      alertHistory.value = history || [];
      showHistoryModal.value = true;
    } catch (error) {
      Message.error(t('common.loadFailed'));
    } finally {
      historyLoading.value = false;
    }
  };

  // 颜色辅助函数
  const getConditionColor = (type: string): string => {
    const colors: Record<string, string> = {
      FailureRate: '#ff4d4f',
      Latency: '#faad14',
      QPS: '#1890ff',
      MemoryUsage: '#722ed1',
      CustomExpression: '#13c2c2',
    };
    return colors[type] || '#999';
  };

  const getActionColor = (type: string): string => {
    const colors: Record<string, string> = {
      LOG: 'blue',
      EMAIL: 'green',
      SMS: 'orange',
      WEBHOOK: 'purple',
      DATABASE: 'cyan',
    };
    return colors[type] || 'default';
  };

  const getSeverityColor = (type: string): string => {
    const colors: Record<string, string> = {
      INFO: 'blue',
      WARN: 'orange',
      ERROR: 'red',
      CRITICAL: 'red',
    };
    return colors[type] || 'default';
  };

  const getStatusColor = (type: string): string => {
    const colors: Record<string, string> = {
      NEW: 'blue',
      ACKNOWLEDGED: 'orange',
      RESOLVED: 'green',
      IGNORED: 'gray',
    };
    return colors[type] || 'default';
  };

  onMounted(() => {
    loadRules();
    loadStatistics();
  });
</script>

<style scoped lang="less">
  .alert-rule-container {
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

    .rule-list-card {
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
    }

    .rule-name-cell {
      display: flex;
      align-items: center;
      gap: 10px;

      .rule-badge {
        color: white;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: bold;
      }

      .rule-name {
        font-weight: 500;
      }
    }

    .condition-display,
    .action-display {
      display: flex;
      align-items: center;
      font-size: 13px;

      .action-target {
        color: #666;
        font-size: 12px;
      }
    }

    .operation-cell {
      display: flex;
      align-items: center;
      gap: 4px;
    }
  }
</style>
