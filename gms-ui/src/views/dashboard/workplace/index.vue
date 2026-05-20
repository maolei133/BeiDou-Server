<template>
  <div class="container workbench-page" :loading="loading">
    <Breadcrumb />
    <div class="workbench-content">
      <a-alert v-if="monitorError" type="error" class="monitor-alert">
        {{ $t('workplace.monitor.failedDesc') }}
      </a-alert>
      <a-alert v-if="gameError" type="warning" class="monitor-alert">
        {{ $t('workplace.game.failedDesc') }}
      </a-alert>
      <a-alert
        v-if="monitorWarnings.length"
        type="warning"
        class="monitor-alert"
      >
        <div v-for="warning in monitorWarnings" :key="warning">{{
          warning
        }}</div>
      </a-alert>

      <section class="section gms-section">
        <div class="section-head gms-section-head">
          <div>
            <div class="section-title gms-section-title">{{
              $t('workplace.section.today')
            }}</div>
            <div class="section-subtitle gms-section-subtitle"
              >先判断游戏服是否正常、玩家是否受影响、数据是否新鲜。</div
            >
          </div>
          <div class="toolbar section-toolbar gms-toolbar">
            <a-tag v-if="monitorSnapshot?.sample?.partial" color="orange">
              {{ $t('workplace.monitor.partial') }}
            </a-tag>
            <a-tag v-if="monitorError" color="red">
              {{ $t('workplace.monitor.failed') }}
            </a-tag>
            <span class="tag gms-tag info">{{
              $t('workplace.monitor.realtime')
            }}</span>
            <span class="version-pill gms-pill">
              {{ $t('workplace.monitor.updatedAt') }}:
              {{
                formatDateTime(
                  monitorSnapshot?.sample?.sampledAtIso ||
                    monitorSnapshot?.sample?.sampledAt
                )
              }}
            </span>
            <a-button
              size="small"
              :loading="monitorLoading"
              @click="refreshAll(true)"
            >
              <template #icon><icon-refresh /></template>
              {{ $t('workplace.monitor.refresh') }}
            </a-button>
          </div>
        </div>
        <div class="body gms-section-body">
          <div class="status-bar">
            <div class="status-main">
              <span
                :class="[
                  'status-label',
                  serverStatus === 'running' ? '' : 'gray',
                ]"
              >
                <i class="pulse" />
                {{
                  serverStatus === 'running'
                    ? $t('workplace.running')
                    : $t('workplace.stopped')
                }}
              </span>
              <div class="status-name">
                {{
                  serverStatus === 'running'
                    ? $t('workplace.game.online')
                    : $t('workplace.game.offline')
                }}
              </div>
              <div class="meta-line">
                <span
                  >{{ $t('workplace.monitor.version') }}:
                  {{ monitorSnapshot?.server?.version || '-' }}</span
                >
                <span
                  >{{ $t('workplace.monitor.uptime') }}:
                  {{ formatDuration(monitorSnapshot?.runtime?.uptimeMs) }}</span
                >
              </div>
            </div>
            <div class="mini-stat">
              <div class="mini-label">{{
                $t('workplace.game.currentOnline')
              }}</div>
              <div class="mini-value">{{ onlinePlayerCountText }}</div>
              <div class="mini-foot">{{
                $t('workplace.game.onlineScope')
              }}</div>
            </div>
            <div class="mini-stat">
              <div class="mini-label">{{
                $t('workplace.game.loginHealth')
              }}</div>
              <div class="mini-value small">{{
                monitorError
                  ? $t('workplace.monitor.failed')
                  : $t('workplace.game.healthNormal')
              }}</div>
              <div class="mini-foot"
                >{{ $t('workplace.monitor.partial') }}:
                {{
                  monitorSnapshot?.sample?.partial
                    ? $t('workplace.yes')
                    : $t('workplace.no')
                }}</div
              >
            </div>
            <div class="mini-stat">
              <div class="mini-label">{{ $t('workplace.game.worlds') }}</div>
              <div class="mini-value">{{ worldList.length }}</div>
              <div class="mini-foot"
                >{{ $t('workplace.game.channels') }}:
                {{ channelList.length }}</div
              >
            </div>
            <div class="mini-stat">
              <div class="mini-label">{{
                $t('workplace.game.refreshStatus')
              }}</div>
              <div class="mini-value small">{{
                $t('workplace.monitor.realtime')
              }}</div>
              <div class="mini-foot"
                >{{ $t('workplace.monitor.updatedAt') }}:
                {{
                  formatDateTime(
                    monitorSnapshot?.sample?.sampledAtIso ||
                      monitorSnapshot?.sample?.sampledAt
                  )
                }}</div
              >
            </div>
          </div>
        </div>
      </section>

      <section class="section gms-section">
        <div class="section-head gms-section-head">
          <div>
            <div class="section-title gms-section-title">{{
              $t('workplace.section.host')
            }}</div>
            <div class="section-subtitle gms-section-subtitle">{{
              $t('workplace.monitor.scopeNote')
            }}</div>
          </div>
          <span class="tag gms-tag gray">{{
            $t('workplace.monitor.resourceScopeShort')
          }}</span>
        </div>
        <div class="body gms-section-body">
          <div class="resource-grid">
            <div class="metric-card gms-metric-card resource-scroll-card">
              <div class="metric-head"
                ><span>{{ $t('workplace.monitor.hostCpu') }}</span
                ><span class="tag gms-tag info">{{
                  formatPercent(monitorSnapshot?.cpu?.systemCpuLoad)
                }}</span></div
              >
              <a-progress
                :percent="
                  percentToProgress(monitorSnapshot?.cpu?.systemCpuLoad)
                "
                :status="progressStatus(monitorSnapshot?.cpu?.systemCpuLoad)"
                :show-text="false"
              />
              <div class="kv gms-kv"
                ><span>{{ $t('workplace.monitor.host') }}</span
                ><b>{{
                  formatPercent(monitorSnapshot?.cpu?.systemCpuLoad)
                }}</b></div
              >
              <div class="kv gms-kv"
                ><span>{{ $t('workplace.monitor.gameProcess') }}</span
                ><b>{{
                  formatPercent(monitorSnapshot?.cpu?.processCpuLoad)
                }}</b></div
              >
              <div
                class="cpu-model"
                :title="monitorSnapshot?.cpu?.processorModel || '-'"
                >{{ monitorSnapshot?.cpu?.processorModel || '-' }}</div
              >
              <div class="mini-foot"
                >{{ monitorSnapshot?.cpu?.availableProcessors || '-' }} 核 ·
                负载
                {{ formatNumber(monitorSnapshot?.cpu?.systemLoadAverage) }}</div
              >
            </div>
            <div class="metric-card gms-metric-card resource-scroll-card">
              <div class="metric-head"
                ><span>{{ $t('workplace.monitor.memory') }}</span
                ><span class="tag gms-tag info">{{
                  formatPercent(monitorSnapshot?.cpu?.systemMemory?.usage)
                }}</span></div
              >
              <a-progress
                :percent="
                  percentToProgress(monitorSnapshot?.cpu?.systemMemory?.usage)
                "
                :status="
                  progressStatus(monitorSnapshot?.cpu?.systemMemory?.usage)
                "
                :show-text="false"
              />
              <div class="kv gms-kv"
                ><span>{{
                  formatBytes(monitorSnapshot?.cpu?.systemMemory?.used)
                }}</span
                ><b>{{
                  formatPercent(monitorSnapshot?.cpu?.systemMemory?.usage)
                }}</b></div
              >
              <div class="mini-foot"
                >{{ $t('workplace.monitor.total') }}:
                {{ formatBytes(monitorSnapshot?.cpu?.systemMemory?.max) }}</div
              >
              <div class="mini-foot"
                >{{ $t('workplace.monitor.free') }}:
                {{ formatBytes(systemMemoryFree) }}</div
              >
            </div>
            <div class="metric-card gms-metric-card resource-scroll-card">
              <div class="metric-head"
                ><span>{{ $t('workplace.monitor.disk') }}</span
                ><span class="tag gms-tag gray">{{
                  monitorDisks.length || '-'
                }}</span></div
              >
              <template v-if="monitorDisks.length">
                <div
                  v-for="disk in monitorDisks"
                  :key="disk.path || 'disk'"
                  class="disk-item"
                >
                  <div class="kv gms-kv"
                    ><span>{{ disk.path || '-' }}</span
                    ><b>{{ formatPercent(disk.usage) }}</b></div
                  >
                  <a-progress
                    :percent="percentToProgress(disk.usage)"
                    :status="progressStatus(disk.usage)"
                    :show-text="false"
                  />
                  <div class="mini-foot"
                    >{{ formatBytes(disk.used) }} /
                    {{ formatBytes(disk.total) }}</div
                  >
                </div>
              </template>
              <a-empty v-else :description="$t('workplace.monitor.noData')" />
            </div>
            <div class="metric-card gms-metric-card">
              <div class="metric-head"
                ><span
                  >{{ $t('workplace.monitor.hostNetworkIo') }} /
                  {{ $t('workplace.monitor.hostDiskIo') }}</span
                ><a-select
                  v-model="selectedNetworkInterface"
                  size="mini"
                  :options="networkInterfaceOptions"
                  :disabled="!networkInterfaceOptions.length"
                  style="width: 168px"
              /></div>
              <div class="io-groups">
                <div class="io-group">
                  <div class="io-group-title">{{
                    $t('workplace.monitor.hostNetworkIo')
                  }}</div>
                  <div class="io-row rx"
                    ><span><i>↓</i>{{ $t('workplace.monitor.networkRx') }}</span
                    ><b>{{
                      formatBytesPerSec(
                        monitorSnapshot?.network?.hostRxBytesPerSecond ??
                          monitorSnapshot?.network?.rxBytesPerSecond
                      )
                    }}</b></div
                  >
                  <div class="io-row tx"
                    ><span><i>↑</i>{{ $t('workplace.monitor.networkTx') }}</span
                    ><b>{{
                      formatBytesPerSec(
                        monitorSnapshot?.network?.hostTxBytesPerSecond ??
                          monitorSnapshot?.network?.txBytesPerSecond
                      )
                    }}</b></div
                  >
                </div>
                <div class="io-group">
                  <div class="io-group-title">{{
                    $t('workplace.monitor.hostDiskIo')
                  }}</div>
                  <div class="io-row read"
                    ><span><i>R</i>{{ $t('workplace.monitor.diskRead') }}</span
                    ><b>{{
                      formatBytesPerSec(
                        monitorSnapshot?.diskIo?.hostReadBytesPerSecond ??
                          monitorSnapshot?.diskIo?.readBytesPerSecond
                      )
                    }}</b></div
                  >
                  <div class="io-row write"
                    ><span><i>W</i>{{ $t('workplace.monitor.diskWrite') }}</span
                    ><b>{{
                      formatBytesPerSec(
                        monitorSnapshot?.diskIo?.hostWriteBytesPerSecond ??
                          monitorSnapshot?.diskIo?.writeBytesPerSecond
                      )
                    }}</b></div
                  >
                </div>
              </div>
              <div class="mini-foot">{{
                $t('workplace.monitor.networkScopeNote')
              }}</div>
              <div class="mini-foot"
                >{{ $t('workplace.monitor.interfaces') }}:
                {{ networkInterfacesText }}</div
              >
            </div>
          </div>
        </div>
      </section>

      <section class="section gms-section">
        <div class="section-head gms-section-head">
          <div>
            <div class="section-title with-help gms-section-title">
              <span>{{ $t('workplace.section.trend') }}</span>
              <a-tooltip :content="$t('workplace.mvp.desc')">
                <icon-question-circle class="section-help-icon" />
              </a-tooltip>
            </div>
            <div class="section-subtitle gms-section-subtitle">{{
              $t('workplace.trend.subtitle')
            }}</div>
          </div>
          <div class="trend-range-controls">
            <a-radio-group
              v-model="trendRange"
              type="button"
              size="small"
              class="range-switch-arco"
            >
              <a-radio
                v-for="option in trendRangeOptions"
                :key="option.value"
                :value="option.value"
                >{{ option.label }}</a-radio
              >
            </a-radio-group>
            <a-range-picker
              v-if="trendRange === 'custom'"
              v-model="customTrendRange"
              show-time
              format="YYYY-MM-DD HH:mm:ss"
              size="small"
              style="width: 360px"
              @change="refreshMonitorHistory(true)"
            />
          </div>
        </div>
        <div class="body gms-section-body">
          <div class="trend-grid">
            <div class="chart-card gms-chart-card trend-main-card">
              <div class="chart-top">
                <div class="chart-title">{{
                  $t('workplace.trend.resourceTitle')
                }}</div>
                <span class="tag gms-tag info">{{ trendLabel }}</span>
              </div>
              <Chart
                v-if="sampleCount >= 2"
                :options="resourceTrendOptions"
                height="300px"
                @legendselectchanged="handleResourceLegendSelectChanged"
              />
              <a-empty v-else :description="$t('workplace.trend.waiting')" />
              <div v-if="historyError" class="mini-foot error">{{
                $t('workplace.trend.historyFailed')
              }}</div>
              <div class="mini-foot">{{
                $t('workplace.trend.historySource')
              }}</div>
            </div>
            <div class="chart-card gms-chart-card trend-io-card">
              <div class="chart-top">
                <div class="chart-title">{{
                  $t('workplace.trend.ioTitle')
                }}</div>
                <span class="tag gms-tag gray">IO</span>
              </div>
              <Chart
                v-if="sampleCount >= 2"
                :options="ioTrendOptions"
                height="300px"
                @legendselectchanged="handleIoLegendSelectChanged"
              />
              <a-empty v-else :description="$t('workplace.trend.waiting')" />
            </div>
            <div class="chart-card gms-chart-card trend-event-card">
              <div class="chart-top">
                <div class="chart-title">{{
                  $t('workplace.trend.anomalyTitle')
                }}</div>
                <a-button
                  size="mini"
                  :loading="cpuConfigLoading"
                  @click="cpuConfigVisible = true"
                >
                  {{ $t('workplace.cpuConfig.title') }}
                </a-button>
                <span class="tag gms-tag gray">{{ anomalyEvents.length }}</span>
              </div>
              <a-timeline v-if="anomalyEvents.length" class="anomaly-timeline">
                <a-timeline-item
                  v-for="event in anomalyEvents"
                  :key="`${event.occurredAt}-${event.level}-${event.message}`"
                  :dot-color="eventLevelColor(event.level)"
                >
                  <div class="event-title compact">
                    <a-tag :color="eventLevelColor(event.level)">{{
                      event.level || 'WARN'
                    }}</a-tag>
                    <span>{{
                      formatDateTime(event.occurredAtIso || event.occurredAt)
                    }}</span>
                  </div>
                  <div class="event-desc">{{
                    event.message || $t('workplace.trend.cpuSpike')
                  }}</div>
                </a-timeline-item>
              </a-timeline>
              <a-empty v-else :description="$t('workplace.trend.noAnomaly')" />
            </div>
          </div>
        </div>
      </section>

      <section class="section gms-section">
        <div class="section-head gms-section-head">
          <div>
            <div class="section-title gms-section-title">{{
              $t('workplace.section.game')
            }}</div>
            <div class="section-subtitle gms-section-subtitle"
              >游戏服务是玩家连接的世界实例；JVM 是承载进程。</div
            >
          </div>
          <span class="tag gms-tag info">{{
            $t('workplace.section.jvm')
          }}</span>
        </div>
        <div class="body gms-section-body">
          <div class="split-grid">
            <div class="service-panel gms-panel">
              <div class="panel-title">
                <span>{{ $t('workplace.game.worldChannel') }}</span>
                <span class="tag">{{ worldRows.length || '-' }}</span>
              </div>
              <div class="health-list">
                <div
                  v-for="world in worldRows"
                  :key="world.id"
                  class="health-row"
                >
                  <div class="health-name">World {{ world.id }}</div>
                  <div class="health-content">
                    <div class="channel-counts">
                      <span
                        v-for="channel in world.channels"
                        :key="channel.id"
                        class="tag info channel-pill"
                      >
                        {{ channel.label }}:
                        {{
                          $t('workplace.game.playerCount', {
                            count: channel.playerCountText,
                          })
                        }}
                      </span>
                      <span v-if="!world.channels.length" class="tag gray">{{
                        $t('workplace.game.noChannels')
                      }}</span>
                    </div>
                    <div class="health-desc">
                      EXP {{ world.expRateText }} · Drop
                      {{ world.dropRateText }} · Meso {{ world.mesoRateText }}
                    </div>
                  </div>
                  <span class="tag">{{ $t('workplace.running') }}</span>
                </div>
                <a-empty
                  v-if="!worldRows.length"
                  :description="$t('workplace.monitor.noData')"
                />
              </div>
            </div>
            <div class="env-panel gms-panel">
              <div class="panel-title">
                <span>{{ $t('workplace.section.jvm') }}</span>
                <span class="tag gms-tag gray"
                  >PID {{ monitorSnapshot?.runtime?.pid || '-' }}</span
                >
              </div>
              <div class="kv gms-kv"
                ><span>Heap</span
                ><b>{{
                  formatPercent(monitorSnapshot?.jvm?.heap?.usage)
                }}</b></div
              >
              <a-progress
                :percent="percentToProgress(monitorSnapshot?.jvm?.heap?.usage)"
                :status="progressStatus(monitorSnapshot?.jvm?.heap?.usage)"
                :show-text="false"
              />
              <div class="mini-foot"
                >{{ formatBytes(monitorSnapshot?.jvm?.heap?.used) }} /
                {{ formatBytes(monitorSnapshot?.jvm?.heap?.max) }}</div
              >
              <div class="kv gms-kv"
                ><span>Threads</span
                ><b>{{ monitorSnapshot?.jvm?.threadCount || '-' }}</b></div
              >
              <div class="kv gms-kv"
                ><span>GC</span
                ><b
                  >{{ monitorSnapshot?.jvm?.gcCount || '-' }} /
                  {{ formatDuration(monitorSnapshot?.jvm?.gcTimeMs) }}</b
                ></div
              >
              <div class="mini-foot"
                >Java: {{ monitorSnapshot?.jvm?.javaVersion || '-' }} ·
                {{ monitorSnapshot?.jvm?.vmName || '-' }}</div
              >
              <div class="mini-foot"
                >{{ $t('workplace.monitor.container') }}: {{ containerText }} ·
                Profiles: {{ activeProfilesText }}</div
              >
            </div>
          </div>
        </div>
      </section>

      <section class="section gms-section">
        <div class="section-head gms-section-head">
          <div>
            <div class="section-title gms-section-title">{{
              $t('workplace.section.ops')
            }}</div>
            <div class="section-subtitle gms-section-subtitle"
              >高危操作与监控信息分离，执行前保留确认与影响范围。</div
            >
          </div>
          <span class="tag gms-tag warn"
            >{{ $t('workplace.ops.impact') }}: {{ onlinePlayerCountText }}</span
          >
        </div>
        <div class="body gms-section-body">
          <div class="action-zone">
            <div class="action-head">
              <div>
                <div class="panel-title compact">{{
                  $t('workplace.gameServer.serverControl')
                }}</div>
                <div class="action-note"
                  >{{ $t('workplace.ops.warning') }}
                  {{ $t('workplace.ops.impact') }}:
                  {{ onlinePlayerCountText }}</div
                >
              </div>
            </div>
            <a-space class="button-row gms-button-row" :size="10">
              <a-button
                v-for="(btn, index) in serverControlButtons"
                :key="index"
                :loading="loading && btn.action !== 'stop'"
                type="primary"
                :disabled="btn.disabled(serverStatus)"
                :status="btn.status"
                @click="handleButtonClick(btn.action)"
              >
                <template #icon><component :is="btn.icon" /></template>
                {{ $t(`workplace.button.${btn.label}`) }}
              </a-button>
            </a-space>
          </div>
          <div class="service-panel reload-panel">
            <div class="panel-title compact">{{
              $t('workplace.dataReload')
            }}</div>
            <a-space class="button-row gms-button-row" :size="10">
              <a-button
                v-for="(btn, index) in dataReloadButtons"
                :key="index + 'reload'"
                :loading="loading"
                type="primary"
                @click="handleButtonClick(btn.action)"
              >
                <template #icon><component :is="btn.icon" /></template>
                {{ $t(`workplace.button.${btn.label}`) }}
              </a-button>
            </a-space>
          </div>
        </div>
      </section>

      <a-modal
        v-model:visible="cpuConfigVisible"
        modal-class="arco-modal-auto"
        draggable
        :ok-loading="cpuConfigSaving"
        @ok="handleCpuConfigSave"
        @cancel="handleCpuConfigCancel"
      >
        <template #title>{{ $t('workplace.cpuConfig.title') }}</template>
        <a-alert type="info" class="monitor-alert">{{
          $t('workplace.cpuConfig.desc')
        }}</a-alert>
        <a-form :model="cpuRules" layout="vertical">
          <div
            v-for="(rule, index) in cpuRules"
            :key="index"
            class="cpu-rule-row"
          >
            <a-form-item :label="$t('workplace.cpuConfig.threshold')">
              <a-input-number
                v-model="rule.percent"
                :min="1"
                :max="100"
                :step="1"
                :precision="0"
                hide-button
              >
                <template #suffix>%</template>
              </a-input-number>
            </a-form-item>
            <a-form-item :label="$t('workplace.cpuConfig.level')">
              <a-select v-model="rule.lv">
                <a-option value="WARN">WARN</a-option>
                <a-option value="ERROR">ERROR</a-option>
              </a-select>
            </a-form-item>
          </div>
        </a-form>
      </a-modal>

      <a-modal
        v-model:visible="restartConfirmVisible"
        modal-class="arco-modal-auto"
        draggable
        @ok="handleRestartConfirm"
        @cancel="handleRestartCancel"
      >
        <template #title>{{ $t('workplace.button.restart') }}</template>
        <a-alert type="warning" class="monitor-alert"
          >{{ $t('workplace.ops.impact') }}:
          {{ onlinePlayerCountText }}</a-alert
        >
        <p>{{ $t('workplace.button.restart.confirm') }}</p>
      </a-modal>

      <a-modal
        v-model:visible="stopConfigVisible"
        modal-class="arco-modal-auto"
        draggable
        @ok="handleStopConfigOk"
        @cancel="handleStopConfigCancel"
      >
        <template #title>{{
          currentAction === 'shutdown'
            ? $t('workplace.button.shutdown')
            : $t('workplace.button.stop.config')
        }}</template>
        <a-alert type="warning" class="monitor-alert">
          {{ $t('workplace.ops.impact') }}: {{ onlinePlayerCountText }} ·
          {{ $t('workplace.ops.forceOffline') }}
        </a-alert>
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
                <a-tooltip :content="$t('workplace.stop.shutdownMsgDefault')"
                  ><icon-info-circle style="margin-left: 8px"
                /></a-tooltip>
              </div>
            </template>
            <a-textarea v-model="stopConfigData.shutdownMsg" />
          </a-form-item>
          <a-form-item :label="$t('workplace.stop.messageTypes')">
            <a-space class="button-group gms-button-row" :size="16">
              <a-checkbox v-model="stopConfigData.showServerMsg">{{
                $t('workplace.stop.showServerMsg')
              }}</a-checkbox>
              <a-checkbox v-model="stopConfigData.showCenterMsg">{{
                $t('workplace.stop.showCenterMsg')
              }}</a-checkbox>
              <a-checkbox v-model="stopConfigData.showChatMsg">{{
                $t('workplace.stop.showChatMsg')
              }}</a-checkbox>
            </a-space>
          </a-form-item>
        </a-form>
      </a-modal>
    </div>
  </div>
</template>

<script lang="ts" setup>
  import {
    computed,
    onBeforeUnmount,
    onMounted,
    reactive,
    ref,
    watch,
  } from 'vue';
  import {
    getAllWorldsOnlinePlayersCount,
    getCpuMonitorConfig,
    getServerChannelList,
    getServerMonitorHistory,
    getServerMonitorSnapshot,
    getServerStatus,
    getServerWorldList,
    restartServer,
    shutdown,
    startServer,
    stopServer,
    updateCpuMonitorConfig,
  } from '@/api/dashboard';
  import type {
    CpuMonitorRule,
    MonitorDiskInfo,
    ServerChannelInfo,
    ServerMonitorEvent,
    ServerMonitorHistoryPoint,
    ServerMonitorSnapshot,
    ServerWorldInfo,
  } from '@/api/dashboard';
  import { Message } from '@arco-design/web-vue';
  import useLoading from '@/hooks/loading';
  import useThemes from '@/hooks/themes';
  import {
    reloadDropsByGMCommand,
    reloadEventsByGMCommand,
    reloadMapsByGMCommand,
    reloadMonstersByGMCommand,
    reloadOpcodesByGMCommand,
    reloadPacketCreatorScript,
    reloadPacketsByGMCommand,
    reloadPortalsByGMCommand,
    reloadQuestsByGMCommand,
    reloadReactorsByGMCommand,
    reloadShopsByGMCommand,
    reloadSkillsByGMCommand,
  } from '@/api/command';
  import { useI18n } from 'vue-i18n';
  import dayjs from 'dayjs';
  import {
    formatBytes,
    formatBytesPerSec,
    formatDateTime,
    formatDuration,
    formatNumber,
    formatPercent,
  } from '@/utils/format-monitor';

  interface TrendSample {
    time: number;
    label: string;
    cpu?: number;
    gameCpu?: number;
    memory?: number;
    jvmHeap?: number;
    rx?: number;
    tx?: number;
    diskRead?: number;
    diskWrite?: number;
    cpuAnomaly?: boolean;
    cpuAnomalyLevel?: string | null;
    cpuAnomalyReason?: string | null;
  }

  const { t } = useI18n();
  const { isDark } = useThemes();
  const { loading, setLoading } = useLoading(false);
  const serverStatus = ref<'resting' | 'running'>('resting');
  const monitorSnapshot = ref<ServerMonitorSnapshot | null>(null);
  const monitorLoading = ref(false);
  const monitorError = ref(false);
  const gameError = ref(false);
  const pageVisible = ref(true);
  type TrendRange = '1m' | '5m' | '10m' | '30m' | '1h' | '1d' | '7d' | 'custom';
  const trendRange = ref<TrendRange>('5m');
  const customTrendRange = ref<[string, string] | undefined>();
  const trendRangeOptions = [
    { label: '1m', value: '1m' },
    { label: '5m', value: '5m' },
    { label: '10m', value: '10m' },
    { label: '30m', value: '30m' },
    { label: '1h', value: '1h' },
    { label: '1d', value: '1d' },
    { label: '7d', value: '7d' },
    { label: t('workplace.trend.customRange'), value: 'custom' },
  ] as const;
  const trendSamples = ref<TrendSample[]>([]);
  const anomalyEvents = ref<ServerMonitorEvent[]>([]);
  const cpuConfigVisible = ref(false);
  const cpuConfigLoading = ref(false);
  const cpuConfigSaving = ref(false);
  const defaultCpuRules = [
    { percent: 30, lv: 'WARN' },
    { percent: 50, lv: 'WARN' },
    { percent: 70, lv: 'ERROR' },
    { percent: 90, lv: 'ERROR' },
  ];
  const cpuRules = ref<{ percent: number; lv: string }[]>(
    defaultCpuRules.map((rule) => ({ ...rule }))
  );
  const historyError = ref(false);
  const resourceLegendSelected = ref<Record<string, boolean>>({});
  const ioLegendSelected = ref<Record<string, boolean>>({});
  const worldList = ref<ServerWorldInfo[]>([]);
  const channelList = ref<ServerChannelInfo[]>([]);
  const onlinePlayerCount = ref<number | null>(null);
  const selectedNetworkInterface = ref<string>();
  let monitorTimer: number | undefined;
  let historyTimer: number | undefined;
  const stopConfigVisible = ref(false);
  const restartConfirmVisible = ref(false);
  const currentAction = ref<'stop' | 'shutdown'>('stop');

  const stopConfigData = reactive({
    mode: 'minutes' as 'minutes' | 'time',
    minutes: 0,
    targetTime: undefined as string | undefined,
    shutdownMsg: '',
    showServerMsg: false,
    showCenterMsg: false,
    showChatMsg: false,
  });

  const toPercentNumber = (value?: number | null) => {
    if (value === null || value === undefined || Number.isNaN(Number(value)))
      return undefined;
    return Number((Math.max(0, Math.min(Number(value), 1)) * 100).toFixed(2));
  };

  const historyParams = computed(() => {
    if (trendRange.value === 'custom') {
      const [start, end] = customTrendRange.value || [];
      if (start && end)
        return { start: dayjs(start).valueOf(), end: dayjs(end).valueOf() };
      return { range: '5m' };
    }
    return { range: trendRange.value };
  });
  const trendLabel = computed(() => {
    if (trendRange.value !== 'custom') return trendRange.value;
    const [start, end] = customTrendRange.value || [];
    return start && end
      ? `${dayjs(start).format('MM-DD HH:mm')} ~ ${dayjs(end).format(
          'MM-DD HH:mm'
        )}`
      : t('workplace.trend.customRange');
  });
  const historyPointToSample = (
    point: ServerMonitorHistoryPoint
  ): TrendSample => {
    const sampledAt = point.sampledAt || Date.now();
    return {
      time: sampledAt,
      label:
        trendRange.value === '1d' ||
        trendRange.value === '7d' ||
        trendRange.value === 'custom'
          ? dayjs(sampledAt).format('MM-DD HH:mm')
          : dayjs(sampledAt).format('HH:mm:ss'),
      cpu: toPercentNumber(point.systemCpuLoad),
      gameCpu: toPercentNumber(point.processCpuLoad),
      memory: toPercentNumber(point.systemMemoryUsage),
      jvmHeap: toPercentNumber(point.jvmHeapUsage),
      rx: point.networkRxBytesPerSecond ?? undefined,
      tx: point.networkTxBytesPerSecond ?? undefined,
      diskRead: point.diskReadBytesPerSecond ?? undefined,
      diskWrite: point.diskWriteBytesPerSecond ?? undefined,
      cpuAnomaly: Boolean(point.cpuAnomaly),
      cpuAnomalyLevel: point.cpuAnomalyLevel,
      cpuAnomalyReason: point.cpuAnomalyReason,
    };
  };

  const sampleCount = computed(() => trendSamples.value.length);

  const monitorWarnings = computed(
    () => monitorSnapshot.value?.sample?.warnings?.filter(Boolean) || []
  );
  const monitorDisks = computed<MonitorDiskInfo[]>(
    () => monitorSnapshot.value?.disks || []
  );
  const systemMemoryFree = computed(() => {
    const memory = monitorSnapshot.value?.cpu?.systemMemory;
    if (memory?.max === null || memory?.max === undefined) return undefined;
    if (memory?.used === null || memory?.used === undefined) return undefined;
    return Math.max(memory.max - memory.used, 0);
  });
  const networkInterfaces = computed(
    () => monitorSnapshot.value?.network?.interfaces || []
  );
  const networkInterfaceOptions = computed(() =>
    networkInterfaces.value
      .map((item) => {
        const name = item.name || item.displayName || '-';
        const address = item.primaryAddress || item.addresses?.[0];
        return {
          label: `${name}${item.defaultInterface ? '（默认）' : ''}${
            address ? ` · ${address}` : ''
          }`,
          value: item.name || '',
        };
      })
      .filter((item) => item.value)
  );
  const networkInterfacesText = computed(() => {
    const names = networkInterfaces.value
      .map((item) => item.name || item.displayName)
      .filter(Boolean);
    return names.length ? names.join(', ') : '-';
  });
  const containerText = computed(() => {
    const container = monitorSnapshot.value?.container;
    if (!container) return '-';
    if (!container.detected) return t('workplace.monitor.notDetected');
    return container.runtime || 'container';
  });
  const activeProfilesText = computed(() => {
    const profiles = monitorSnapshot.value?.runtime?.activeProfiles || [];
    return profiles.length ? profiles.join(', ') : '-';
  });
  const onlinePlayerCountText = computed(() =>
    onlinePlayerCount.value === null ? '-' : String(onlinePlayerCount.value)
  );

  const handleResourceLegendSelectChanged = (params: {
    selected?: Record<string, boolean>;
  }) => {
    resourceLegendSelected.value = { ...(params?.selected || {}) };
  };

  const handleIoLegendSelectChanged = (params: {
    selected?: Record<string, boolean>;
  }) => {
    ioLegendSelected.value = { ...(params?.selected || {}) };
  };

  const worldRows = computed(() =>
    worldList.value.map((world) => {
      const channels = channelList.value
        .filter((item) => item.worldId === world.id)
        .map((item) => ({
          id: item.id,
          label: `CH${item.id}`,
          playerCountText:
            item.playerCount === null || item.playerCount === undefined
              ? '-'
              : String(item.playerCount),
        }))
        .sort((a, b) => a.id - b.id);
      const rate = (value?: number | null) =>
        value === null || value === undefined ? '-' : `${value}x`;
      return {
        id: world.id,
        channels,
        expRateText: rate(world.expRate),
        dropRateText: rate(world.dropRate),
        mesoRateText: rate(world.mesoRate),
      };
    })
  );

  const anomalyMarkPoints = computed(() =>
    trendSamples.value
      .map((sample, index) => ({ sample, index }))
      .filter(({ sample }) => sample.cpuAnomaly && sample.cpu !== undefined)
      .map(({ sample, index }) => {
        const isError =
          sample.cpuAnomalyLevel === 'ERROR' ||
          sample.cpuAnomalyLevel === 'CRITICAL';
        return {
          name: sample.cpuAnomalyLevel || 'WARN',
          coord: [index, sample.cpu],
          value: isError ? '严重' : '异常',
          itemStyle: { color: isError ? '#ef4444' : '#f97316' },
          label: { formatter: isError ? '严重' : '波动' },
        };
      })
  );

  const cpuMarkLines = computed(() =>
    cpuRules.value.map((rule) => ({
      yAxis: rule.percent,
      name: `CPU ${rule.lv}`,
      lineStyle: { color: rule.lv === 'ERROR' ? '#ef4444' : '#f97316' },
    }))
  );

  const resourceTrendOptions = computed(() => {
    const labels = trendSamples.value.map((item) => item.label);
    const percentSeries = [
      { name: t('workplace.monitor.hostCpu'), key: 'cpu' },
      { name: t('workplace.monitor.gameCpu'), key: 'gameCpu' },
      { name: `${t('workplace.monitor.memory')} %`, key: 'memory' },
      { name: t('workplace.trend.jvmHeap'), key: 'jvmHeap' },
    ];
    const axisColor = isDark.value ? '#3a3a3c' : '#e6ebf3';
    const splitLineColor = isDark.value ? '#303033' : '#eef2f7';
    return {
      color: ['#1677ff', '#f97316', '#16a34a', '#f59e0b'],
      tooltip: {
        trigger: 'axis',
        formatter: (params: any[]) => {
          if (!Array.isArray(params) || !params.length) return '';
          const sample = trendSamples.value[params[0].dataIndex];
          const rows = params.map(
            (item) =>
              `${item.marker}${item.seriesName}: ${
                Number.isFinite(Number(item.value))
                  ? Number(item.value).toFixed(2)
                  : '-'
              }%`
          );
          if (sample?.cpuAnomaly)
            rows.push(
              `<span style="color:#ef4444">${
                sample.cpuAnomalyReason || t('workplace.trend.cpuSpike')
              }</span>`
            );
          return [`${params[0].axisValue}`, ...rows].join('<br/>');
        },
      },
      legend: {
        top: 0,
        icon: 'roundRect',
        type: 'scroll',
        selected: resourceLegendSelected.value,
      },
      grid: { left: 42, right: 18, top: 66, bottom: 34 },
      xAxis: {
        type: 'category',
        boundaryGap: false,
        data: labels,
        axisTick: { show: false },
        axisLine: { lineStyle: { color: axisColor } },
      },
      yAxis: {
        type: 'value',
        min: 0,
        max: 100,
        name: '%',
        axisLabel: { formatter: '{value}%' },
        splitLine: { lineStyle: { color: splitLineColor } },
      },
      series: percentSeries.map((item) => ({
        name: item.name,
        type: 'line',
        smooth: true,
        showSymbol: false,
        lineStyle: { width: 3 },
        areaStyle: item.key === 'cpu' ? { opacity: 0.1 } : undefined,
        markLine:
          item.key === 'cpu'
            ? {
                symbol: 'none',
                lineStyle: { type: 'dashed', color: '#f97316' },
                data: cpuMarkLines.value,
              }
            : undefined,
        markPoint:
          item.key === 'cpu' && anomalyMarkPoints.value.length
            ? { symbol: 'pin', symbolSize: 46, data: anomalyMarkPoints.value }
            : undefined,
        data: trendSamples.value.map(
          (sample) => sample[item.key as keyof TrendSample] ?? null
        ),
      })),
    };
  });

  const ioTrendOptions = computed(() => {
    const labels = trendSamples.value.map((item) => item.label);
    const ioSeries = [
      { name: t('workplace.monitor.networkRx'), key: 'rx' },
      { name: t('workplace.monitor.networkTx'), key: 'tx' },
      { name: t('workplace.monitor.diskRead'), key: 'diskRead' },
      { name: t('workplace.monitor.diskWrite'), key: 'diskWrite' },
    ];
    const axisColor = isDark.value ? '#3a3a3c' : '#e6ebf3';
    const splitLineColor = isDark.value ? '#303033' : '#eef2f7';
    return {
      color: ['#06b6d4', '#6366f1', '#f97316', '#ef4444'],
      tooltip: {
        trigger: 'axis',
        formatter: (params: any[]) => {
          if (!Array.isArray(params) || !params.length) return '';
          const rows = params.map(
            (item) =>
              `${item.marker}${item.seriesName}: ${formatBytesPerSec(
                Number(item.value)
              )}`
          );
          return [`${params[0].axisValue}`, ...rows].join('<br/>');
        },
      },
      legend: {
        top: 0,
        icon: 'roundRect',
        type: 'scroll',
        selected: ioLegendSelected.value,
      },
      grid: { left: 52, right: 16, top: 66, bottom: 34 },
      xAxis: {
        type: 'category',
        boundaryGap: false,
        data: labels,
        axisTick: { show: false },
        axisLine: { lineStyle: { color: axisColor } },
      },
      yAxis: {
        type: 'value',
        name: 'IO/s',
        axisLabel: {
          formatter: (value: number) => formatBytesPerSec(value, 0),
        },
        splitLine: { lineStyle: { color: splitLineColor } },
      },
      series: ioSeries.map((item) => ({
        name: item.name,
        type: 'line',
        smooth: true,
        showSymbol: false,
        lineStyle: { width: 2 },
        data: trendSamples.value.map(
          (sample) => sample[item.key as keyof TrendSample] ?? null
        ),
      })),
    };
  });

  const percentToProgress = (value?: number | null) => {
    if (value === null || value === undefined || Number.isNaN(Number(value)))
      return 0;
    return Math.max(0, Math.min(Number(value), 1));
  };
  const progressStatus = (value?: number | null) => {
    const ratio = Number(value);
    if (!Number.isFinite(ratio)) return 'normal' as const;
    const errorThreshold = Math.min(
      ...cpuRules.value
        .filter((rule) => rule.lv === 'ERROR')
        .map((rule) => rule.percent / 100),
      0.9
    );
    const warnThreshold = Math.min(
      ...cpuRules.value
        .filter((rule) => rule.lv === 'WARN')
        .map((rule) => rule.percent / 100),
      0.75
    );
    if (ratio >= errorThreshold) return 'danger' as const;
    if (ratio >= warnThreshold) return 'warning' as const;
    return 'normal' as const;
  };

  const eventLevelColor = (level?: string | null) =>
    level === 'ERROR' || level === 'CRITICAL' ? 'red' : 'orange';

  const normalizeCpuRules = (rules?: CpuMonitorRule[] | null) => {
    const normalized = (rules || [])
      .filter((rule) => rule?.p !== null && rule?.p !== undefined)
      .map((rule) => ({
        percent: Math.max(1, Math.min(Math.round(Number(rule.p) * 100), 100)),
        lv: rule.lv === 'ERROR' ? 'ERROR' : 'WARN',
      }))
      .sort((a, b) => a.percent - b.percent);
    return normalized.length
      ? normalized
      : defaultCpuRules.map((rule) => ({ ...rule }));
  };

  const loadCpuMonitorConfig = async () => {
    cpuConfigLoading.value = true;
    try {
      const { data } = await getCpuMonitorConfig();
      cpuRules.value = normalizeCpuRules(data?.rules);
    } catch (err) {
      Message.warning(t('workplace.cpuConfig.loadFailed'));
    } finally {
      cpuConfigLoading.value = false;
    }
  };

  const handleCpuConfigSave = async () => {
    cpuConfigSaving.value = true;
    try {
      const payload = {
        rules: cpuRules.value.map((rule) => ({
          p: Math.max(1, Math.min(Number(rule.percent), 100)) / 100,
          lv: rule.lv === 'ERROR' ? 'ERROR' : 'WARN',
        })),
      };
      const { data } = await updateCpuMonitorConfig(payload);
      cpuRules.value = normalizeCpuRules(data?.rules);
      cpuConfigVisible.value = false;
      Message.success(t('common.operationSuccess'));
      await refreshMonitorHistory(true);
    } catch (err) {
      Message.error(t('common.requestFailed'));
    } finally {
      cpuConfigSaving.value = false;
    }
  };

  const handleCpuConfigCancel = () => {
    cpuConfigVisible.value = false;
    loadCpuMonitorConfig();
  };

  const refreshMonitorHistory = async (manual = false) => {
    if (!pageVisible.value && !manual) return;
    try {
      const { data } = await getServerMonitorHistory(historyParams.value);
      trendSamples.value = (data?.points || [])
        .map(historyPointToSample)
        .sort((a, b) => a.time - b.time);
      anomalyEvents.value = data?.events || [];
      historyError.value = false;
    } catch (err) {
      historyError.value = true;
    }
  };

  const refreshMonitor = async (manual = false) => {
    if (!pageVisible.value && !manual) return;
    if (monitorLoading.value) return;
    monitorLoading.value = true;
    try {
      const { data } = await getServerMonitorSnapshot({
        interfaceName: selectedNetworkInterface.value,
      });
      monitorSnapshot.value = data;
      const defaultInterfaceName =
        data?.network?.selectedInterfaceName ||
        data?.network?.defaultInterfaceName ||
        data?.network?.interfaces?.find((item) => item.defaultInterface)
          ?.name ||
        data?.network?.interfaces?.[0]?.name;
      if (!selectedNetworkInterface.value && defaultInterfaceName) {
        selectedNetworkInterface.value = defaultInterfaceName;
      }
      monitorError.value = false;
      if (typeof data?.server?.online === 'boolean')
        serverStatus.value = data.server.online ? 'running' : 'resting';
    } catch (err) {
      monitorError.value = true;
    } finally {
      monitorLoading.value = false;
    }
  };

  const refreshGameInfo = async (includeStructure = false) => {
    try {
      const { data: statusData } = await getServerStatus();
      serverStatus.value = statusData ? 'running' : 'resting';
      if (includeStructure || !worldList.value.length) {
        const { data: worldData } = await getServerWorldList();
        worldList.value = worldData || [];
      }
      const worldIds = worldList.value
        .map((item) => item.id)
        .filter((id) => Number.isFinite(id));

      const channelResponses = await Promise.all(
        (worldIds.length ? worldIds : [0]).map((worldId) =>
          getServerChannelList(worldId)
            .then(({ data }) => data || [])
            .catch(() => [] as ServerChannelInfo[])
        )
      );
      channelList.value = channelResponses.flat();

      const onlineDataResult = await getAllWorldsOnlinePlayersCount(
        worldIds.length ? worldIds : [0]
      );
      const onlineData = onlineDataResult.data;
      onlinePlayerCount.value = onlineData ?? null;
      gameError.value = false;
    } catch (err) {
      gameError.value = true;
    }
  };

  const refreshAll = async (manual = false) => {
    await Promise.all([
      refreshMonitor(manual),
      refreshMonitorHistory(manual),
      refreshGameInfo(manual || !worldList.value.length),
    ]);
  };

  const handleVisibilityChange = () => {
    pageVisible.value = document.visibilityState === 'visible';
    if (pageVisible.value) refreshAll(true);
  };
  const startMonitorRefresh = () => {
    if (monitorTimer) window.clearInterval(monitorTimer);
    if (historyTimer) window.clearInterval(historyTimer);
    monitorTimer = window.setInterval(
      () => Promise.all([refreshMonitor(), refreshGameInfo(false)]),
      3000
    );
    historyTimer = window.setInterval(() => refreshMonitorHistory(), 30000);
  };
  const stopMonitorRefresh = () => {
    if (monitorTimer) {
      window.clearInterval(monitorTimer);
      monitorTimer = undefined;
    }
    if (historyTimer) {
      window.clearInterval(historyTimer);
      historyTimer = undefined;
    }
  };
  watch(trendRange, () => refreshMonitorHistory(true));
  watch(selectedNetworkInterface, (value, oldValue) => {
    if (value && oldValue && value !== oldValue) {
      refreshMonitor(true);
    }
  });

  const range = (start: number, end: number) => {
    const result = [];
    for (let i = start; i < end; i += 1) result.push(i);
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
    { label: 'dataReloadMonsters', action: 'reloadMonsters', icon: 'icon-bug' },
    {
      label: 'dataReloadReactors',
      action: 'reloadReactors',
      icon: 'icon-interaction',
    },
    { label: 'dataReloadOpcodes', action: 'reloadOpcodes', icon: 'icon-code' },
    {
      label: 'dataReloadPackets',
      action: 'reloadPackets',
      icon: 'icon-code-block',
    },
    {
      label: 'dataReloadPacketCreator',
      action: 'reloadPacketCreator',
      icon: 'icon-sync',
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
    pageVisible.value = document.visibilityState === 'visible';
    document.addEventListener('visibilitychange', handleVisibilityChange);
    loadCpuMonitorConfig();
    refreshAll();
    startMonitorRefresh();
  });
  onBeforeUnmount(() => {
    stopMonitorRefresh();
    document.removeEventListener('visibilitychange', handleVisibilityChange);
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
        case 'reloadOpcodes':
          await reloadOpcodesByGMCommand();
          break;
        case 'reloadPackets':
          await reloadPacketsByGMCommand();
          break;
        case 'reloadPacketCreator':
          await reloadPacketCreatorScript();
          break;
        default:
          break;
      }
      Message.success(t('common.operationSuccess'));
    } catch (err) {
      Message.error(t('common.requestFailed'));
    } finally {
      await refreshAll(true);
      setLoading(false);
    }
  };

  const handleRestartConfirm = async () => {
    try {
      setLoading(true);
      await restartServer();
      Message.success(t('common.operationSuccess'));
    } catch (err) {
      Message.error(t('common.requestFailed'));
    } finally {
      restartConfirmVisible.value = false;
      await refreshAll(true);
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
      if (stopConfigData.mode === 'minutes') minutes = stopConfigData.minutes;
      else if (stopConfigData.mode === 'time' && stopConfigData.targetTime) {
        const diff = dayjs(stopConfigData.targetTime).diff(dayjs(), 'minute');
        minutes = diff > 0 ? diff : 0;
      }
      const stopConfigParams = {
        minutes,
        shutdownMsg: stopConfigData.shutdownMsg,
        showServerMsg: stopConfigData.showServerMsg,
        showCenterMsg: stopConfigData.showCenterMsg,
        showChatMsg: stopConfigData.showChatMsg,
      };
      if (currentAction.value === 'shutdown') await shutdown(stopConfigParams);
      else await stopServer(stopConfigParams);
      Message.success(t('workplace.stop.shutdownInProgress'));
      if (minutes > 0)
        setTimeout(async () => {
          await loadSeverStatus();
        }, minutes * 60 * 1000);
      else await loadSeverStatus();
      stopConfigVisible.value = false;
    } catch (err) {
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
  export default { name: 'Dashboard' };
</script>

<style lang="less" scoped>
  .workbench-page {
    --bg: var(--gms-bg);
    --surface: var(--gms-surface);
    --surface-soft: var(--gms-surface-soft);
    --border: var(--gms-border);
    --border-soft: var(--gms-border-soft);
    --text: var(--gms-text);
    --muted: var(--gms-muted);
    --muted-2: var(--gms-muted-2);
    --blue: var(--gms-primary);
    --blue-soft: var(--gms-primary-soft);
    --green: var(--gms-success);
    --green-soft: var(--gms-success-soft);
    --orange: var(--gms-warning);
    --orange-soft: var(--gms-warning-soft);
    --red: var(--gms-danger);
    --red-soft: var(--gms-danger-soft);
    --cyan: var(--gms-cyan);
    --cyan-soft: var(--gms-cyan-soft);
    --shadow: var(--gms-shadow);
    --radius: var(--gms-radius);
    --radius-sm: var(--gms-radius-sm);
    --scroll-thumb: var(--gms-muted-2);
    --danger-border: var(--gms-danger);
    min-height: 100%;
    background: var(--bg);
    color: var(--text);
    font-family: Inter, 'PingFang SC', 'Microsoft YaHei', system-ui,
      -apple-system, BlinkMacSystemFont, sans-serif;
  }

  .toolbar {
    display: flex;
    align-items: center;
    gap: 10px;
    color: var(--muted);
    font-size: 13px;
    flex-wrap: wrap;
    justify-content: flex-end;
  }

  .version-pill {
    border: 1px solid var(--border);
    background: var(--surface-soft);
    color: var(--muted);
    padding: 5px 10px;
    border-radius: 999px;
    font-size: 12px;
  }

  .section {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    margin-bottom: 18px;
    overflow: hidden;
  }

  .section-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    padding: 16px 18px;
    border-bottom: 1px solid var(--border);
    background: linear-gradient(var(--surface), var(--surface-soft));
  }

  .section-title {
    color: var(--text);
    font-size: 16px;
    font-weight: 800;
  }

  .section-title.with-help {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .section-help-icon {
    color: var(--muted-2);
    cursor: help;
    font-size: 15px;
  }

  .section-help-icon:hover {
    color: var(--blue);
  }

  .section-subtitle {
    color: var(--muted);
    font-size: 12px;
    margin-top: 3px;
  }

  .body {
    padding: 18px;
  }

  .status-bar {
    display: grid;
    grid-template-columns: minmax(260px, 1.2fr) repeat(4, minmax(120px, 0.8fr));
    gap: 14px;
  }

  .status-main {
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 16px;
    background: linear-gradient(135deg, var(--surface-soft), var(--surface));
  }

  .status-label {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 9px;
    border-radius: 999px;
    background: var(--green-soft);
    color: var(--green);
    font-weight: 800;
    font-size: 12px;
  }

  .status-label.gray {
    background: var(--surface-soft);
    color: var(--muted);
  }

  .status-label.gray .pulse {
    background: var(--muted-2);
    box-shadow: 0 0 0 4px rgba(152, 162, 179, 0.13);
  }

  .pulse {
    width: 7px;
    height: 7px;
    background: var(--green);
    border-radius: 999px;
    box-shadow: 0 0 0 4px rgba(22, 163, 74, 0.13);
  }

  .status-name {
    margin-top: 12px;
    font-size: 22px;
    font-weight: 850;
    color: var(--blue);
  }

  .meta-line {
    margin-top: 8px;
    color: var(--muted);
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    font-size: 12px;
  }

  .mini-stat {
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--surface);
    padding: 14px;
  }

  .mini-label {
    color: var(--muted);
    font-size: 12px;
  }

  .mini-value {
    margin-top: 8px;
    font-size: 22px;
    font-weight: 850;
    color: var(--text);
  }

  .mini-value.small {
    font-size: 16px;
  }

  .mini-foot {
    margin-top: 6px;
    color: var(--muted-2);
    font-size: 12px;
    line-height: 1.55;
    word-break: break-all;
  }

  .trend-grid {
    display: grid;
    grid-template-columns: minmax(360px, 1.05fr) minmax(340px, 0.95fr) minmax(
        220px,
        0.46fr
      );
    gap: 14px;
    align-items: stretch;
    width: 100%;
  }

  .trend-grid > .chart-card {
    min-width: 0;
  }

  .trend-event-card {
    min-width: 220px;
  }

  .trend-event-card :deep(.arco-timeline-item-content) {
    padding-bottom: 12px;
  }

  .trend-event-card .event-title.compact {
    align-items: flex-start;
    flex-direction: column;
    gap: 4px;
  }

  .anomaly-timeline {
    max-height: 318px;
    overflow: auto;
    padding-right: 4px;
  }

  .resource-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 14px;
  }

  .metric-card {
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 14px;
    background: var(--surface);
    min-height: 150px;
  }

  .resource-scroll-card {
    height: 220px;
    overflow-y: auto;
    overscroll-behavior: contain;
    padding-right: 10px;
  }

  .resource-scroll-card::-webkit-scrollbar,
  .hot-scroll::-webkit-scrollbar {
    width: 6px;
  }

  .resource-scroll-card::-webkit-scrollbar-thumb,
  .hot-scroll::-webkit-scrollbar-thumb {
    border-radius: 999px;
    background: var(--scroll-thumb);
  }

  .resource-scroll-card::-webkit-scrollbar-track,
  .hot-scroll::-webkit-scrollbar-track {
    background: transparent;
  }

  .metric-head {
    display: flex;
    justify-content: space-between;
    gap: 8px;
    font-weight: 800;
    margin-bottom: 14px;
    color: var(--text);
  }

  .tag {
    display: inline-flex;
    align-items: center;
    border-radius: 999px;
    padding: 3px 8px;
    font-size: 11px;
    font-weight: 800;
    background: var(--green-soft);
    color: var(--green);
    white-space: nowrap;
  }

  .tag.warn {
    background: var(--orange-soft);
    color: var(--orange);
  }

  .tag.info {
    background: var(--blue-soft);
    color: var(--blue);
  }

  .tag.gray {
    background: var(--surface-soft);
    color: var(--muted);
  }

  .kv {
    display: flex;
    justify-content: space-between;
    gap: 8px;
    margin-top: 8px;
    color: var(--muted);
    font-size: 12px;
  }

  .kv b {
    color: var(--text);
  }

  .disk-item + .disk-item {
    margin-top: 12px;
    padding-top: 12px;
    border-top: 1px solid var(--border-soft);
  }

  .traffic-line {
    margin: 8px 0;
    color: var(--text);
    font-size: 16px;
    font-weight: 800;
  }

  .traffic-line.rx {
    color: var(--green);
  }

  .traffic-line.tx {
    color: var(--blue);
  }

  .cpu-model {
    margin-top: 10px;
    color: var(--text);
    font-size: 12px;
    font-weight: 750;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .io-groups {
    display: grid;
    gap: 10px;
  }

  .io-group {
    border: 1px solid var(--border-soft);
    border-radius: var(--radius-sm);
    padding: 10px;
    background: var(--surface-soft);
  }

  .io-group-title {
    margin-bottom: 6px;
    color: var(--muted);
    font-size: 12px;
    font-weight: 800;
  }

  .io-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
    padding: 5px 0;
    color: var(--muted);
    font-size: 12px;
  }

  .io-row span {
    display: inline-flex;
    align-items: center;
    gap: 7px;
  }

  .io-row i {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 18px;
    height: 18px;
    border-radius: 999px;
    font-style: normal;
    font-size: 11px;
    font-weight: 850;
    background: var(--border-soft);
  }

  .io-row b {
    color: var(--text);
    font-size: 13px;
    white-space: nowrap;
  }

  .io-row.rx i {
    background: var(--cyan-soft);
    color: var(--cyan);
  }
  .io-row.tx i {
    background: var(--blue-soft);
    color: var(--blue);
  }
  .io-row.read i {
    background: var(--orange-soft);
    color: var(--orange);
  }
  .io-row.write i {
    background: var(--red-soft);
    color: var(--red);
  }

  .chart-card {
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--surface);
    padding: 14px;
    min-height: 230px;
  }

  .chart-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;
  }

  .chart-title {
    font-weight: 850;
    color: var(--text);
  }

  .cpu-rule-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }

  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    margin-top: 10px;
    color: var(--muted);
    font-size: 12px;
  }

  .legend i {
    display: inline-block;
    width: 9px;
    height: 9px;
    border-radius: 999px;
    margin-right: 5px;
  }

  .split-grid {
    display: grid;
    grid-template-columns: 1.05fr 0.95fr;
    gap: 18px;
  }

  .service-panel,
  .env-panel {
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 16px;
    background: var(--surface);
  }

  .reload-panel {
    margin-top: 14px;
  }

  .panel-title {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 16px;
    font-weight: 850;
    margin-bottom: 14px;
    color: var(--text);
  }

  .panel-title.compact {
    display: block;
    margin-bottom: 6px;
    font-size: 14px;
  }

  .health-list {
    display: grid;
    gap: 10px;
  }

  .health-row {
    display: grid;
    grid-template-columns: 120px minmax(0, 1fr) auto;
    gap: 12px;
    align-items: center;
    padding: 10px 0;
    border-top: 1px solid var(--border-soft);
  }

  .health-row:first-child {
    border-top: 0;
  }

  .health-name {
    font-weight: 750;
    color: var(--text);
  }

  .health-desc {
    color: var(--muted);
    font-size: 12px;
  }

  .health-content {
    display: grid;
    gap: 6px;
    min-width: 0;
  }

  .channel-counts {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    min-width: 0;
  }

  .channel-pill {
    font-variant-numeric: tabular-nums;
  }

  .action-zone {
    background: var(--surface);
    border: 1px dashed var(--danger-border);
    border-radius: var(--radius-sm);
    padding: 14px;
  }

  .action-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;
  }

  .action-note {
    color: var(--muted);
    font-size: 12px;
  }

  .button-row,
  .button-group {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
  }

  .monitor-alert {
    margin-bottom: 16px;
  }

  :deep(.arco-progress-line-wrapper) {
    border-radius: 999px;
    background: var(--border-soft);
  }

  :deep(.arco-progress-line-bar) {
    border-radius: 999px;
  }

  .trend-range-controls {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    justify-content: flex-end;
    align-items: center;
  }

  :deep(.range-switch-arco.arco-radio-group-button) {
    padding: 3px;
    border-radius: 999px;
    background: var(--surface-soft);
  }

  :deep(.range-switch-arco .arco-radio-button) {
    border-radius: 999px;
  }

  @media (max-width: 1400px) {
    .status-bar,
    .resource-grid {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }

  @media (max-width: 1100px) {
    .trend-grid,
    .split-grid {
      grid-template-columns: 1fr;
    }
  }

  @media (max-width: 768px) {
    .section-head,
    .action-head {
      flex-direction: column;
      align-items: flex-start;
    }

    .toolbar {
      justify-content: flex-start;
    }

    .status-bar,
    .resource-grid {
      grid-template-columns: 1fr;
    }

    .resource-scroll-card {
      height: auto;
      max-height: none;
      overflow-y: visible;
    }

    .health-row {
      grid-template-columns: 1fr;
      gap: 6px;
    }
  }
</style>
