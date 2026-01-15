<template>
  <div class="container" :loading="loading">
    <Breadcrumb />
    <a-card class="general-card" :title="$t('menu.dashboard.workplace')">
      <a-card
        class="status-card"
        :title="$t('workplace.gameServer.status')"
        :bordered="false"
      >
        <a-row>
          <a-col>
            {{ $t('workplace.gameServer.currently') }}
            <a-tag v-if="serverStatus === 'running'" color="green" bordered>
              {{ $t('workplace.running') }}
            </a-tag>
            <a-tag v-else color="gray" bordered>
              {{ $t('workplace.stopped') }}
            </a-tag>
          </a-col>
        </a-row>
      </a-card>

      <a-card
        class="control-card"
        :title="$t('workplace.gameServer.serverControl')"
        :bordered="false"
      >
        <a-space class="button-group" :size="16">
          <a-button
            v-for="(btn, index) in serverControlButtons"
            :key="index"
            :loading="loading && btn.action !== 'stop'"
            type="primary"
            :disabled="btn.disabled(serverStatus)"
            :status="btn.status"
            @click="handleButtonClick(btn.action)"
          >
            <template #icon>
              <component :is="btn.icon" />
            </template>
            {{ $t(`workplace.button.${btn.label}`) }}
          </a-button>
        </a-space>
      </a-card>

      <a-card
        class="reload-card"
        :title="$t('workplace.dataReload')"
        :bordered="false"
      >
        <a-space class="button-group" :size="16">
          <a-button
            v-for="(btn, index) in dataReloadButtons"
            :key="index + 'reload'"
            :loading="loading"
            type="primary"
            @click="handleButtonClick(btn.action)"
          >
            <template #icon>
              <component :is="btn.icon" />
            </template>
            {{ $t(`workplace.button.${btn.label}`) }}
          </a-button>
        </a-space>
      </a-card>

      <!-- 重启服务端的确认框 -->
      <a-modal
        v-model:visible="restartConfirmVisible"
        modal-class="arco-modal-auto"
        draggable
        @ok="handleRestartConfirm"
        @cancel="handleRestartCancel"
      >
        <template #title>
          {{ $t('workplace.button.restart') }}
        </template>
        <p>{{ $t('workplace.button.restart.confirm') }}</p>
      </a-modal>

      <!-- 停服/关服倒计时配置框 -->
      <a-modal
        v-model:visible="stopConfigVisible"
        modal-class="arco-modal-auto"
        draggable
        @ok="handleStopConfigOk"
        @cancel="handleStopConfigCancel"
      >
        <template #title>
          {{
            currentAction === 'shutdown'
              ? $t('workplace.button.shutdown')
              : $t('workplace.button.stop.config')
          }}
        </template>
        <a-form :model="stopConfigData" layout="vertical">
          <a-form-item :label="$t('workplace.stop.mode')">
            <a-radio-group v-model="stopConfigData.mode" direction="vertical">
              <a-radio value="minutes">
                <span style="margin-right: 10px">{{
                  $t('workplace.stop.mode.minutes')
                }}</span>
                <template v-if="stopConfigData.mode === 'minutes'">
                  <a-input-number
                    v-model="stopConfigData.minutes"
                    :min="0"
                    style="width: 120px; margin-right: 8px"
                    size="small"
                    placeholder="0"
                  />
                  <span>{{ $t('workplace.unit.minutes') }}</span>
                </template>
              </a-radio>
              <a-radio value="time" style="margin-top: 10px">
                <span style="margin-right: 10px">{{
                  $t('workplace.stop.mode.time')
                }}</span>
                <template v-if="stopConfigData.mode === 'time'">
                  <a-date-picker
                    v-model="stopConfigData.targetTime"
                    show-time
                    format="YYYY-MM-DD HH:mm:ss"
                    style="width: 200px"
                    size="small"
                    :disabled-date="
                      (current) => dayjs(current).isBefore(dayjs())
                    "
                    :disabled-time="
                      (current) =>
                        dayjs(current).isSame(dayjs(), 'day')
                          ? {
                              disabledHours: () =>
                                range(0, 24).splice(0, dayjs().hour()),
                              disabledMinutes: () =>
                                dayjs(current).isSame(dayjs(), 'hour')
                                  ? range(0, 60).splice(0, dayjs().minute())
                                  : [],
                              disabledSeconds: () => [],
                            }
                          : {}
                    "
                  />
                </template>
              </a-radio>
            </a-radio-group>
          </a-form-item>

          <a-form-item>
            <template #label>
              <div style="display: flex; align-items: center">
                <span>{{ $t('workplace.stop.shutdownMsg') }}</span>
                <a-tooltip :content="$t('workplace.stop.shutdownMsgDefault')">
                  <icon-info-circle style="margin-left: 8px" />
                </a-tooltip>
              </div>
            </template>
            <a-textarea v-model="stopConfigData.shutdownMsg" />
          </a-form-item>

          <a-form-item :label="$t('workplace.stop.messageTypes')">
            <a-space class="button-group" :size="16">
              <a-checkbox v-model="stopConfigData.showServerMsg">
                {{ $t('workplace.stop.showServerMsg') }}
              </a-checkbox>
              <a-checkbox v-model="stopConfigData.showCenterMsg">
                {{ $t('workplace.stop.showCenterMsg') }}
              </a-checkbox>
              <a-checkbox v-model="stopConfigData.showChatMsg">
                {{ $t('workplace.stop.showChatMsg') }}
              </a-checkbox>
            </a-space>
          </a-form-item>
        </a-form>
      </a-modal>
    </a-card>
  </div>
</template>

<script lang="ts" setup>
  import { onMounted, reactive, ref } from 'vue';
  import {
    getServerStatus,
    restartServer,
    shutdown,
    startServer,
    stopServer,
  } from '@/api/dashboard';
  import { Message } from '@arco-design/web-vue';
  import useLoading from '@/hooks/loading';
  import {
    reloadDropsByGMCommand,
    reloadEventsByGMCommand,
    reloadMapsByGMCommand,
    reloadMonstersByGMCommand,
    reloadPortalsByGMCommand,
    reloadQuestsByGMCommand,
    reloadReactorsByGMCommand,
    reloadShopsByGMCommand,
    reloadSkillsByGMCommand,
  } from '@/api/command';
  import { useI18n } from 'vue-i18n';
  import dayjs from 'dayjs';

  const { t } = useI18n();
  const { loading, setLoading } = useLoading(false);
  const serverStatus = ref<'resting' | 'running'>('resting');
  const stopConfigVisible = ref(false);
  const restartConfirmVisible = ref(false); // 新增用于确认重启的模态框可见性控制
  const currentAction = ref<'stop' | 'shutdown'>('stop'); // 记录当前操作是停止服务还是关闭程序

  const stopConfigData = reactive({
    mode: 'minutes' as 'minutes' | 'time',
    minutes: 0,
    targetTime: undefined as string | undefined,
    shutdownMsg: '',
    showServerMsg: false,
    showCenterMsg: false,
    showChatMsg: false,
  });

  const range = (start: number, end: number) => {
    const result = [];
    for (let i = start; i < end; i += 1) {
      result.push(i);
    }
    return result;
  };

  const serverControlButtons = [
    {
      label: 'start',
      action: 'start',
      disabled: (status: 'resting' | 'running') => status === 'running',
      status: 'success' as const,
      icon: 'icon-play-arrow-fill',
    },
    {
      label: 'stop',
      action: 'stop',
      disabled: (status: 'resting' | 'running') => status === 'resting',
      status: 'danger' as const,
      icon: 'icon-stop',
    },
    {
      label: 'restart',
      action: 'restart',
      disabled: (status: 'resting' | 'running') => status === 'resting',
      status: 'warning' as const,
      icon: 'icon-refresh',
    },
    {
      label: 'shutdown',
      action: 'shutdown',
      disabled: () => false,
      status: 'danger' as const,
      icon: 'icon-poweroff',
    },
  ];

  const dataReloadButtons = [
    { label: 'dataReloadEvents', action: 'reloadEvents', icon: 'icon-compass' },
    {
      label: 'dataReloadMaps',
      action: 'reloadMaps',
      icon: 'icon-mind-mapping',
    },
    {
      label: 'dataReloadPortals',
      action: 'reloadPortals',
      icon: 'icon-common',
    },
    {
      label: 'dataReloadDrops',
      action: 'reloadDrops',
      icon: 'icon-cloud-download',
    },
    {
      label: 'dataReloadShops',
      action: 'reloadShops',
      icon: 'icon-shopping-cart',
    },
    {
      label: 'dataReloadQuests',
      action: 'reloadQuests',
      icon: 'icon-schedule',
    },
    {
      label: 'dataReloadSkills',
      action: 'reloadSkills',
      icon: 'icon-thunderbolt',
    },
    {
      label: 'dataReloadMonsters',
      action: 'reloadMonsters',
      icon: 'icon-bug',
    },
    {
      label: 'dataReloadReactors',
      action: 'reloadReactors',
      icon: 'icon-interaction',
    },
  ];

  const loadSeverStatus = async () => {
    setLoading(true);
    try {
      const { data } = await getServerStatus();
      serverStatus.value = data ? 'running' : 'resting';
    } finally {
      setLoading(false);
    }
  };

  onMounted(() => {
    loadSeverStatus();
  });

  const handleButtonClick = async (action: string) => {
    if (action === 'shutdown') {
      currentAction.value = 'shutdown';
      stopConfigVisible.value = true;
      return;
    }
    if (action === 'stop') {
      currentAction.value = 'stop';
      stopConfigVisible.value = true;
      return;
    }
    if (action === 'restart') {
      restartConfirmVisible.value = true;
      return;
    }

    setLoading(true);
    try {
      switch (action) {
        case 'start':
          await startServer();
          break;
        case 'reloadEvents':
          await reloadEventsByGMCommand();
          break;
        case 'reloadMaps':
          await reloadMapsByGMCommand();
          break;
        case 'reloadPortals':
          await reloadPortalsByGMCommand();
          break;
        case 'reloadDrops':
          await reloadDropsByGMCommand();
          break;
        case 'reloadShops':
          await reloadShopsByGMCommand();
          break;
        case 'reloadQuests':
          await reloadQuestsByGMCommand();
          break;
        case 'reloadSkills':
          await reloadSkillsByGMCommand();
          break;
        case 'reloadMonsters':
          await reloadMonstersByGMCommand();
          break;
        case 'reloadReactors':
          await reloadReactorsByGMCommand();
          break;
        default:
          break;
      }

      Message.success(t('common.operationSuccess'));
    } catch (err) {
      // console.error(err);
      Message.error(t('common.requestFailed'));
    } finally {
      await loadSeverStatus();
      setLoading(false);
    }
  };

  const handleRestartConfirm = async () => {
    try {
      setLoading(true);
      await restartServer();
      Message.success(t('common.operationSuccess'));
    } catch (err) {
      // console.error(err);
      Message.error(t('common.requestFailed'));
    } finally {
      restartConfirmVisible.value = false;
      setLoading(false);
    }
  };

  const handleRestartCancel = () => {
    restartConfirmVisible.value = false;
  };
  const handleStopConfigOk = async () => {
    try {
      setLoading(true);
      let minutes = 0;

      if (stopConfigData.mode === 'minutes') {
        minutes = stopConfigData.minutes;
      } else if (stopConfigData.mode === 'time' && stopConfigData.targetTime) {
        const now = dayjs();
        const target = dayjs(stopConfigData.targetTime);
        const diff = target.diff(now, 'minute');
        minutes = diff > 0 ? diff : 0;
      }

      const stopConfigParams = {
        minutes,
        shutdownMsg: stopConfigData.shutdownMsg,
        showServerMsg: stopConfigData.showServerMsg,
        showCenterMsg: stopConfigData.showCenterMsg,
        showChatMsg: stopConfigData.showChatMsg,
      };

      if (currentAction.value === 'shutdown') {
        await shutdown(stopConfigParams);
      } else {
        await stopServer(stopConfigParams);
      }

      Message.success(t('workplace.stop.shutdownInProgress'));

      // 如果设置了延迟时间，则启动一个定时器，在延迟时间结束后更新服务器状态
      if (minutes > 0) {
        setTimeout(async () => {
          await loadSeverStatus();
        }, minutes * 60 * 1000);
      } else {
        // 如果没有设置延迟时间，立即更新服务器状态
        await loadSeverStatus();
      }

      stopConfigVisible.value = false;
    } catch (err) {
      // console.error(err);
      Message.error(t('common.requestFailed'));
    } finally {
      setLoading(false);
    }
  };

  const handleStopConfigCancel = () => {
    Object.assign(stopConfigData, {
      mode: 'minutes',
      minutes: 0,
      targetTime: undefined,
      shutdownMsg: '',
      showServerMsg: false,
      showCenterMsg: false,
      showChatMsg: false,
    });
    stopConfigVisible.value = false;
  };
</script>

<script lang="ts">
  export default {
    name: 'Dashboard',
  };
</script>

<style lang="less" scoped>
  .button-group {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
  }
</style>
