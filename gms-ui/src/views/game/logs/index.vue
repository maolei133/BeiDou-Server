<template>
  <div class="logs-container">
    <Breadcrumb />
    <div class="logs-tabs">
      <a-tabs v-model:active-key="activeTab" @change="handleTabChange">
        <a-tab-pane key="dashboard" :title="$t('logs.tab.dashboard')" />
        <a-tab-pane key="query" :title="$t('logs.tab.query')" />
        <a-tab-pane key="config" :title="$t('logs.tab.config')" />
        <a-tab-pane key="alert" :title="$t('logs.tab.alert')" />
        <a-tab-pane key="backup" :title="$t('logs.tab.backup')" />
      </a-tabs>
    </div>
    <router-view />
  </div>
</template>

<script lang="ts">
  import { defineComponent, ref, watch } from 'vue';
  import { useRoute, useRouter } from 'vue-router';

  export default defineComponent({
    name: 'LogsLayout',
    setup() {
      const route = useRoute();
      const router = useRouter();
      const activeTab = ref('dashboard');

      const tabMap: Record<string, string> = {
        LogsDashboard: 'dashboard',
        LogsQuery: 'query',
        LogsConfig: 'config',
        LogsAlert: 'alert',
        LogsBackup: 'backup',
      };

      const routeMap: Record<string, string> = {
        dashboard: 'LogsDashboard',
        query: 'LogsQuery',
        config: 'LogsConfig',
        alert: 'LogsAlert',
        backup: 'LogsBackup',
      };

      watch(
        () => route.name,
        (newName) => {
          if (newName && typeof newName === 'string' && tabMap[newName]) {
            activeTab.value = tabMap[newName];
          }
        },
        { immediate: true }
      );

      const handleTabChange = (tabName: string) => {
        const routeName = routeMap[tabName];
        if (routeName && routeName !== route.name) {
          router.push({ name: routeName });
        }
      };

      return {
        activeTab,
        handleTabChange,
      };
    },
  });
</script>

<style scoped lang="less">
  .logs-container {
    padding: 0;
    background-color: transparent;

    .logs-tabs {
      margin-bottom: 20px;
      background-color: white;
      border-radius: 4px;
      padding: 0 16px;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.06);

      :deep(.arco-tabs) {
        .arco-tabs-header {
          margin: 0;
          border-bottom: 1px solid #e5e7eb;
        }

        .arco-tabs-nav {
          background-color: transparent;
        }

        .arco-tabs-tab-active {
          color: #1890ff;
        }
      }
    }
  }
</style>
