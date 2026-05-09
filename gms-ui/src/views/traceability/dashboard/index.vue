<template>
  <div class="container gms-page">
    <a-card :bordered="false">
      <a-row>
        <a-col :span="24">
          <a-typography-title :heading="5">
            {{ $t('menu.traceability.dashboard') }}
          </a-typography-title>
        </a-col>
      </a-row>
      <a-divider />
      <a-skeleton v-if="loading" :animation="true">
        <a-space direction="vertical" :style="{ width: '100%' }" size="large">
          <a-skeleton-line :rows="10" />
        </a-space>
      </a-skeleton>
      <a-space v-else direction="vertical" size="large" style="width: 100%">
        <a-row :gutter="20">
          <a-col :span="6">
            <a-statistic
              :title="$t('traceability.dashboard.stats.totalRecords')"
              :value="stats.totalRecords"
              show-group-separator
            />
          </a-col>
          <a-col :span="6">
            <a-statistic
              :title="$t('traceability.dashboard.stats.todayAdded')"
              :value="stats.todayAdded"
              show-group-separator
            />
          </a-col>
          <a-col :span="6">
            <a-statistic
              :title="$t('traceability.dashboard.stats.avgPerHour')"
              :value="stats.avgPerHour"
              :precision="0"
              show-group-separator
            />
          </a-col>
          <a-col :span="6">
            <a-statistic
              :title="$t('traceability.dashboard.stats.dbTableSizeMB')"
              :value="stats.dbTableSizeMB"
              :precision="2"
              suffix="MB"
            />
          </a-col>
        </a-row>
        <!-- 在这里可以添加图表和排行榜 -->
      </a-space>
    </a-card>
  </div>
</template>

<script lang="ts" setup>
  import { ref, onMounted } from 'vue';
  import { useI18n } from 'vue-i18n';
  import { getTraceabilityStats } from '@/api/traceability';
  import useLoading from '@/hooks/loading';

  const { t } = useI18n();
  const { loading, setLoading } = useLoading(true);
  const stats = ref({
    totalRecords: 0,
    todayAdded: 0,
    avgPerHour: 0,
    dbTableSizeMB: 0,
  });

  onMounted(async () => {
    setLoading(true);
    try {
      const { data } = await getTraceabilityStats();
      stats.value = data;
    } finally {
      setLoading(false);
    }
  });
</script>
