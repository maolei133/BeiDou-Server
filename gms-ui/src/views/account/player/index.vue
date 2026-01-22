<template>
  <div class="container" :loading="true">
    <Breadcrumb />
    <a-card class="general-card" :title="$t('menu.account.player')">
      <!-- 搜索表单 -->
      <a-form :model="filterForm" class="a-from-keyword">
        <a-row :gutter="16">
          <a-col :span="isMobile ? 24 : 6">
            <a-form-item :label="$t('account.player.character')">
              <a-select
                v-model="filterForm.name"
                allow-search
                :placeholder="$t('account.player.character.placeholder')"
                allow-create
                allow-clear
              >
                <a-option v-for="name in uniqueNames" :key="name" :value="name">
                  {{ name }}
                </a-option>
              </a-select>
            </a-form-item>
          </a-col>
          <a-col :span="isMobile ? 24 : 6">
            <a-form-item :label="$t('account.player.accountId')">
              <a-select
                v-model="filterForm.accountId"
                allow-search
                :placeholder="$t('account.player.accountId.placeholder')"
                allow-create
                allow-clear
              >
                <a-option
                  v-for="acc in uniqueAccounts"
                  :key="acc.id"
                  :value="acc.id"
                >
                  [ {{ acc.id }} ] {{ acc.name }}
                </a-option>
              </a-select>
            </a-form-item>
          </a-col>
          <a-col :span="isMobile ? 24 : 6">
            <a-form-item :label="$t('account.player.mapId')">
              <a-select
                v-model="filterForm.map"
                allow-search
                :placeholder="$t('account.player.mapId.placeholder')"
                allow-create
                allow-clear
              >
                <a-option
                  v-for="map in uniqueMaps"
                  :key="map.id"
                  :value="map.id"
                >
                  {{ map.name }} ({{ map.id }})
                </a-option>
              </a-select>
            </a-form-item>
          </a-col>
          <a-col :span="isMobile ? 24 : 6">
            <a-form-item :label="$t('account.player.status')">
              <a-select
                v-model="filterForm.status"
                :placeholder="$t('account.player.status.placeholder')"
                allow-clear
              >
                <a-option :value="0">{{
                  $t('account.player.status.all')
                }}</a-option>
                <a-option :value="1">{{
                  $t('account.player.status.online')
                }}</a-option>
                <a-option :value="2">{{
                  $t('account.player.status.offline')
                }}</a-option>
              </a-select>
            </a-form-item>
          </a-col>
          <template v-if="!isMobile || showMoreFilters">
            <a-col :span="isMobile ? 24 : 6">
              <a-form-item :label="$t('account.player.banStatus')">
                <a-select
                  v-model="filterForm.banStatus"
                  :placeholder="$t('account.player.banStatus.placeholder')"
                  allow-clear
                >
                  <a-option :value="0">{{
                    $t('account.player.banStatus.all')
                  }}</a-option>
                  <a-option :value="1">{{
                    $t('account.player.banStatus.normal')
                  }}</a-option>
                  <a-option :value="4">{{
                    $t('account.player.banStatus.banned')
                  }}</a-option>
                  <a-option :value="2">{{
                    $t('account.player.banStatus.permanent')
                  }}</a-option>
                  <a-option :value="3">{{
                    $t('account.player.banStatus.temporary')
                  }}</a-option>
                </a-select>
              </a-form-item>
            </a-col>
            <a-col :span="isMobile ? 24 : 6">
              <a-form-item :label="$t('account.player.channel')">
                <a-select
                  v-model="filterForm.channel"
                  allow-search
                  :placeholder="$t('account.player.channel.placeholder')"
                  allow-clear
                >
                  <a-option v-for="ch in 20" :key="ch" :value="ch">
                    {{ ch }}
                  </a-option>
                </a-select>
              </a-form-item>
            </a-col>
            <a-col :span="isMobile ? 24 : 6">
              <a-form-item :label="$t('account.player.job')">
                <a-select
                  v-model="filterForm.job"
                  allow-search
                  :placeholder="$t('account.player.job.placeholder')"
                  :loading="jobLoading"
                  allow-clear
                >
                  <a-option
                    v-for="job in jobList"
                    :key="job.id"
                    :value="job.id"
                  >
                    {{ job.name }} ({{ job.id }})
                  </a-option>
                </a-select>
              </a-form-item>
            </a-col>
            <a-col :span="isMobile ? 24 : 6">
              <a-form-item :label="$t('account.player.partyId')">
                <a-select
                  v-model="filterForm.partyId"
                  allow-search
                  :placeholder="$t('account.player.partyId.placeholder')"
                  allow-create
                  allow-clear
                >
                  <a-option
                    v-for="pid in uniquePartyIds"
                    :key="pid"
                    :value="pid"
                  >
                    {{ pid }}
                  </a-option>
                </a-select>
              </a-form-item>
            </a-col>
            <a-col :span="isMobile ? 24 : 6">
              <a-form-item :label="$t('account.player.guild')">
                <a-select
                  v-model="filterForm.guildId"
                  allow-search
                  :placeholder="$t('account.player.guild.placeholder')"
                  allow-create
                  :loading="guildLoading"
                  allow-clear
                >
                  <a-option
                    v-for="guild in guildList"
                    :key="guild.id"
                    :value="guild.id"
                  >
                    [ {{ guild.id }} ] {{ guild.name }}
                  </a-option>
                </a-select>
              </a-form-item>
            </a-col>
            <a-col :span="isMobile ? 24 : 6">
              <a-form-item :label="$t('account.player.level')">
                <a-input-group>
                  <a-input-number
                    v-model="filterForm.minLevel"
                    :placeholder="$t('account.player.level.min')"
                    :min="1"
                    allow-clear
                  />
                  <span style="padding: 0 8px">-</span>
                  <a-input-number
                    v-model="filterForm.maxLevel"
                    :placeholder="$t('account.player.level.max')"
                    :min="1"
                    allow-clear
                  />
                </a-input-group>
              </a-form-item>
            </a-col>
            <a-col :span="isMobile ? 24 : 6">
              <a-form-item :label="$t('account.player.onlineTime')">
                <a-input-group>
                  <a-input-number
                    v-model="filterForm.minOnlineTime"
                    :placeholder="$t('account.player.onlineTime.min')"
                    :min="0"
                    allow-clear
                  />
                  <span style="padding: 0 8px">-</span>
                  <a-input-number
                    v-model="filterForm.maxOnlineTime"
                    :placeholder="$t('account.player.onlineTime.max')"
                    :min="0"
                    allow-clear
                  />
                </a-input-group>
              </a-form-item>
            </a-col>
          </template>
        </a-row>
      </a-form>
      <a-space>
        <a-button type="primary" @click="loadData()">
          <template #icon>
            <icon-search />
          </template>
          {{ $t('button.load') }}
        </a-button>
        <a-button @click="resetClick">
          <template #icon>
            <icon-refresh />
          </template>
          {{ $t('button.reset') }}
        </a-button>
        <a-button v-if="isMobile" @click="toggleMoreFilters">
          <template #icon>
            <icon-down v-if="!showMoreFilters" />
            <icon-up v-else />
          </template>
          {{
            showMoreFilters
              ? $t('account.player.filter.collapse')
              : $t('account.player.filter.expand')
          }}
        </a-button>
      </a-space>
      <a-divider />
      <!-- 操作按钮 -->
      <a-row style="margin-bottom: 16px">
        <a-col>
          <a-space>
            <a-button type="primary" @click="refreshClick">
              <template #icon>
                <icon-refresh />
              </template>
              {{ $t('button.refresh') }}
            </a-button>
            <a-dropdown @select="handleGlobalAction">
              <a-button type="primary">
                {{ $t('account.player.button.globalAction') }} <icon-down />
              </a-button>
              <template #content>
                <a-doption value="warp">{{
                  $t('account.player.button.globalWarp')
                }}</a-doption>
                <a-doption value="give">{{
                  $t('account.player.button.globalGive')
                }}</a-doption>
                <a-doption value="disconnect">{{
                  $t('account.player.button.globalDisconnect')
                }}</a-doption>
                <a-doption value="duey">发放快递</a-doption>
              </template>
            </a-dropdown>
          </a-space>
        </a-col>
      </a-row>

      <!-- 桌面端表格 -->
      <a-table
        v-if="!isMobile"
        row-key="id"
        :loading="loading"
        :data="tableData"
        column-resizable
        :pagination="false"
        :bordered="{ cell: true }"
        :scroll="{ x: 'max-content', y: 'calc(90vh - 480px)' }"
      >
        <template #columns>
          <a-table-column
            :title="$t('account.player.channel')"
            data-index="channel"
            :width="70"
            align="center"
          />
          <a-table-column
            :title="$t('account.player.accountId')"
            :width="150"
            align="center"
          >
            <template #cell="{ record }">
              <div class="cell-flex">
                <span class="cell-id">{{ record.accountId }}</span>
                <a-divider direction="vertical" class="cell-divider" />
                <router-link
                  :to="{ name: 'AccountList', query: { id: record.accountId } }"
                  class="cell-text"
                >
                  {{ record.accountName }}
                </router-link>
              </div>
            </template>
          </a-table-column>
          <a-table-column
            :title="$t('account.player.id')"
            data-index="id"
            :width="80"
            align="center"
          />
          <a-table-column
            :title="$t('account.player.name')"
            data-index="name"
            :width="150"
            align="center"
          >
            <template #cell="{ record }">
              <div class="cell-flex">
                <template v-if="hasBannedPlayerInPage">
                  <div class="cell-icon">
                    <span v-if="record.banStatus === 1">
                      <a-tooltip>
                        <template #content>
                          <div>
                            {{ $t('account.player.banStatus.permanent') }}
                          </div>
                          <div
                            v-if="record.banReason"
                            style="white-space: pre-wrap"
                          >
                            {{ $t('account.player.ban.reason') }}:
                            {{ record.banReason }}
                          </div>
                        </template>
                        <icon-stop style="color: red" />
                      </a-tooltip>
                    </span>
                    <span v-else-if="record.banStatus === 2">
                      <a-tooltip>
                        <template #content>
                          <div>
                            {{ $t('account.player.banStatus.temporary') }}
                          </div>
                          <div v-if="record.tempBanTime">
                            {{ $t('account.player.tempBanTime') }}:
                            {{ record.tempBanTime }}
                          </div>
                          <div
                            v-if="record.banReason"
                            style="white-space: pre-wrap"
                          >
                            {{ $t('account.player.ban.reason') }}:
                            {{ record.banReason }}
                          </div>
                        </template>
                        <icon-clock-circle style="color: orange" />
                      </a-tooltip>
                    </span>
                  </div>
                  <a-divider direction="vertical" class="cell-divider" />
                </template>
                <span class="cell-text">{{ record.name }}</span>
              </div>
            </template>
          </a-table-column>
          <a-table-column
            :title="$t('account.player.gender')"
            :width="70"
            align="center"
          >
            <template #cell="{ record }">
              <span v-if="record.gender === 0">
                {{ $t('account.list.column.gender.male') }}
              </span>
              <span v-else-if="record.gender === 1">
                {{ $t('account.list.column.gender.female') }}
              </span>
              <span v-else>{{ $t('account.list.column.gender.other') }}</span>
            </template>
          </a-table-column>
          <a-table-column
            :title="$t('account.player.map')"
            align="center"
            :width="250"
            ellipsis
            tooltip
          >
            <template #cell="{ record }">
              <span style="white-space: nowrap">
                {{ record.mapName }} ({{ record.map }})
              </span>
            </template>
          </a-table-column>
          <a-table-column
            :title="$t('account.player.job')"
            :width="150"
            align="center"
          >
            <template #cell="{ record }">
              {{ record.jobName }} ({{ record.job }})
            </template>
          </a-table-column>
          <a-table-column
            :title="$t('account.player.level')"
            data-index="level"
            :width="70"
            align="center"
          />
          <a-table-column
            :title="$t('account.player.fame')"
            data-index="fame"
            :width="70"
            align="center"
          />
          <a-table-column
            :title="$t('account.player.maxHp')"
            data-index="maxHp"
            :width="90"
            align="center"
          />
          <a-table-column
            :title="$t('account.player.maxMp')"
            data-index="maxMp"
            :width="90"
            align="center"
          />
          <a-table-column
            :title="$t('account.player.partyId')"
            data-index="partyId"
            :width="120"
            align="center"
          />
          <a-table-column
            :title="$t('account.player.guild')"
            :width="150"
            align="center"
          >
            <template #cell="{ record }">
              <span v-if="record.guildId > 0">
                [ {{ record.guildId }} ] {{ record.guildName }}
              </span>
            </template>
          </a-table-column>
          <a-table-column
            v-if="filterForm.status === 1 || filterForm.status === 0"
            :title="$t('account.player.loginTime')"
            data-index="loginTime"
            :width="180"
            align="center"
          />
          <a-table-column
            v-if="filterForm.status === 1"
            :title="$t('account.player.onlineTime')"
            :width="120"
            align="center"
          >
            <template #cell="{ record }">
              {{ calculateOnlineTime(record.loginTime) }}
            </template>
          </a-table-column>
          <a-table-column
            v-if="filterForm.status === 2"
            :title="$t('account.player.lastLogoutTime')"
            data-index="lastLogoutTime"
            :width="180"
            align="center"
          />
          <a-table-column
            :title="$t('account.player.gm.level')"
            data-index="gm"
            :width="70"
            align="center"
          />
          <a-table-column
            :title="$t('account.list.column.operate')"
            align="center"
            fixed="right"
            :width="100"
          >
            <template #cell="{ record }">
              <a-dropdown @select="(val) => handleSingleAction(val, record)">
                <a-button type="primary" size="mini">
                  {{ $t('account.list.column.operate') }} <icon-down />
                </a-button>
                <template #content>
                  <a-doption value="edit">{{
                    $t('account.player.button.edit')
                  }}</a-doption>
                  <a-doption value="warp">{{
                    $t('account.player.button.warp')
                  }}</a-doption>
                  <a-doption value="give">{{
                    $t('account.player.button.give')
                  }}</a-doption>
                  <a-doption value="disconnect">{{
                    $t('account.player.button.disconnect')
                  }}</a-doption>
                  <a-doption v-if="!record.banned" value="ban">{{
                    $t('account.player.button.ban')
                  }}</a-doption>
                  <a-doption v-else value="unban">{{
                    $t('account.player.button.unban')
                  }}</a-doption>
                  <a-doption value="duey">发放快递</a-doption>
                </template>
              </a-dropdown>
            </template>
          </a-table-column>
        </template>
      </a-table>

      <!-- 移动端列表 -->
      <a-list v-else :data="tableData" :loading="loading">
        <template #item="{ item }">
          <a-list-item>
            <a-card :title="item.name" class="mobile-card">
              <template #extra>
                <a-space>
                  <a-button
                    type="primary"
                    size="mini"
                    @click="handleWarp(item)"
                  >
                    {{ $t('account.player.button.warp') }}
                  </a-button>
                  <a-dropdown @select="(val) => handleSingleAction(val, item)">
                    <a-button size="mini">
                      {{ $t('account.list.column.operate') }} <icon-down />
                    </a-button>
                    <template #content>
                      <a-doption value="edit">
                        {{ $t('account.player.button.edit') }}
                      </a-doption>
                      <a-doption value="give">
                        {{ $t('account.player.button.give') }}
                      </a-doption>
                      <a-doption value="disconnect">
                        {{ $t('account.player.button.disconnect') }}
                      </a-doption>
                      <a-doption v-if="!item.banned" value="ban">
                        {{ $t('account.player.button.ban') }}
                      </a-doption>
                      <a-doption v-else value="unban">
                        {{ $t('account.player.button.unban') }}
                      </a-doption>
                      <a-doption value="duey">发放快递</a-doption>
                    </template>
                  </a-dropdown>
                </a-space>
              </template>
              <a-descriptions
                :column="1"
                size="small"
                layout="inline-horizontal"
              >
                <a-descriptions-item :label="$t('account.player.accountId')">
                  <router-link
                    :to="{ name: 'AccountList', query: { id: item.accountId } }"
                  >
                    [ {{ item.accountId }} ] {{ item.accountName }}
                  </router-link>
                </a-descriptions-item>
                <a-descriptions-item :label="$t('account.player.id')">
                  {{ item.id }}
                </a-descriptions-item>
                <a-descriptions-item :label="$t('account.player.level')">
                  {{ item.level }}
                </a-descriptions-item>
                <a-descriptions-item :label="$t('account.player.map')">
                  {{ item.mapName }} ({{ item.map }})
                </a-descriptions-item>
                <a-descriptions-item :label="$t('account.player.job')">
                  {{ item.jobName }} ({{ item.job }})
                </a-descriptions-item>
                <a-descriptions-item :label="$t('account.player.maxHp')">
                  {{ item.maxHp }}
                </a-descriptions-item>
                <a-descriptions-item :label="$t('account.player.maxMp')">
                  {{ item.maxMp }}
                </a-descriptions-item>
                <a-descriptions-item :label="$t('account.player.partyId')">
                  {{ item.partyId }}
                </a-descriptions-item>
                <a-descriptions-item
                  v-if="item.guildId > 0"
                  :label="$t('account.player.guild')"
                >
                  [ {{ item.guildId }} ] {{ item.guildName }}
                </a-descriptions-item>
                <a-descriptions-item
                  v-if="item.loginTime"
                  :label="$t('account.player.loginTime')"
                >
                  {{ item.loginTime }}
                </a-descriptions-item>
                <a-descriptions-item
                  v-if="item.loginTime && filterForm.status === 1"
                  :label="$t('account.player.onlineTime')"
                >
                  {{ calculateOnlineTime(item.loginTime) }}
                </a-descriptions-item>
                <a-descriptions-item
                  v-if="item.lastLogoutTime"
                  :label="$t('account.player.lastLogoutTime')"
                >
                  {{ item.lastLogoutTime }}
                </a-descriptions-item>
              </a-descriptions>
            </a-card>
          </a-list-item>
        </template>
      </a-list>

      <a-pagination
        style="margin-top: 20px"
        :total="total"
        :page-size="size"
        :current="page"
        show-total
        show-jumper
        show-page-size
        :page-size-options="[10, 20, 50, 100]"
        @change="pageChange"
        @page-size-change="pageSizeChange"
      />
    </a-card>

    <!-- 弹窗 -->
    <GiveItemModal
      v-model:visible="giveFormVisible"
      :title="giveFormTitle"
      :initial-data="formData"
      @success="loadData"
    />
    <warp-modal
      v-model:visible="warpFormVisible"
      :loading="loading"
      @submit="submitWarp"
    />
    <edit-player-modal
      v-model:visible="editFormVisible"
      :player="editTarget"
      @success="loadData"
    />
    <ban-player-modal
      v-model:visible="banFormVisible"
      :player="banTarget"
      :all="banAll"
      :loading="loading"
      @success="loadData"
    />
    <SendDueyModal
      v-model:visible="dueyFormVisible"
      :default-receiver="dueyTargetName"
      @success="loadData"
    />
    <UnbanPlayerModal
      v-model:visible="unbanFormVisible"
      :player="unbanTarget"
      :loading="loading"
      @success="loadData"
    />
  </div>
</template>

<script setup lang="ts">
  import { ref, onMounted, onUnmounted, computed } from 'vue';
  import { Message, Modal } from '@arco-design/web-vue';
  import { useI18n } from 'vue-i18n';
  import useLoading from '@/hooks/loading';
  import {
    getPlayerList,
    GiveForm,
    givePlayerSrc,
    OnlinePlayer,
    disconnectPlayer,
  } from '@/api/player';
  import { getJobs, getGuilds, InformationResult } from '@/api/information';
  import SendDueyModal from '@/views/game/duey/list/components/SendDueyModal.vue';
  import WarpModal from './WarpModal.vue';
  import EditPlayerModal from './EditPlayerModal.vue';
  import BanPlayerModal from './BanPlayerModal.vue';
  import GiveItemModal from './components/GiveItemModal.vue';
  import UnbanPlayerModal from './UnbanPlayerModal.vue';

  const { t } = useI18n();
  const { loading, setLoading } = useLoading(false);
  const tableData = ref<OnlinePlayer[]>([]);
  const total = ref(0);
  const page = ref(1);
  const size = ref(14);
  const isMobile = ref(false);
  const showMoreFilters = ref(false);

  const filterForm = ref<{
    id?: number;
    name?: string;
    map?: number;
    status: number;
    accountId?: number;
    channel?: number;
    job?: number;
    partyId?: number;
    guildId?: number;
    minLevel?: number;
    maxLevel?: number;
    minOnlineTime?: number;
    maxOnlineTime?: number;
    banStatus?: number;
  }>({
    id: undefined,
    name: undefined,
    map: undefined,
    status: 1,
    accountId: undefined,
    channel: undefined,
    job: undefined,
    partyId: undefined,
    guildId: undefined,
    minLevel: undefined,
    maxLevel: undefined,
    minOnlineTime: undefined,
    maxOnlineTime: undefined,
    banStatus: 0,
  });
  const giveFormVisible = ref(false);
  const giveFormTitle = ref('');
  const warpFormVisible = ref(false);
  const warpTarget = ref<OnlinePlayer | null>(null);
  const editFormVisible = ref(false);
  const editTarget = ref<OnlinePlayer | null>(null);
  const banFormVisible = ref(false);
  const banTarget = ref<OnlinePlayer | null>(null);
  const banAll = ref(false);
  const dueyFormVisible = ref(false);
  const dueyTargetName = ref('');
  const unbanFormVisible = ref(false);
  const unbanTarget = ref<OnlinePlayer | null>(null);

  const formData = ref<GiveForm>({
    type: 5,
    expireType: 0,
  });

  const jobList = ref<InformationResult[]>([]);
  const jobLoading = ref(false);
  const guildList = ref<InformationResult[]>([]);
  const guildLoading = ref(false);

  // Computed properties for unique dropdown options
  const uniqueNames = computed(() => {
    const names = new Set<string>();
    tableData.value.forEach((player) => {
      if (player.name) names.add(`[ ${player.id} ] ${player.name}`);
    });
    return Array.from(names);
  });

  const uniqueAccounts = computed(() => {
    const accounts = new Map<number, string>();
    tableData.value.forEach((player) => {
      if (player.accountId) {
        accounts.set(player.accountId, player.accountName || '');
      }
    });
    return Array.from(accounts).map(([id, name]) => ({ id, name }));
  });

  const uniqueMaps = computed(() => {
    const maps = new Map<number, string>();
    tableData.value.forEach((player) => {
      if (player.map) {
        maps.set(player.map, player.mapName || '');
      }
    });
    return Array.from(maps).map(([id, name]) => ({ id, name }));
  });

  const uniquePartyIds = computed(() => {
    const partyIds = new Set<number>();
    tableData.value.forEach((player) => {
      if (player.partyId && player.partyId > 0) partyIds.add(player.partyId);
    });
    return Array.from(partyIds);
  });

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const uniqueGuilds = computed(() => {
    const guilds = new Map<number, string>();
    tableData.value.forEach((player) => {
      if (player.guildId && player.guildId > 0) {
        guilds.set(player.guildId, player.guildName || '');
      }
    });
    return Array.from(guilds).map(([id, name]) => ({ id, name }));
  });

  const hasBannedPlayerInPage = computed(() => {
    return tableData.value.some(
      (player) => player.banStatus === 1 || player.banStatus === 2
    );
  });

  const checkScreen = () => {
    isMobile.value = window.innerWidth < 768;
  };

  const fetchJobs = async () => {
    jobLoading.value = true;
    try {
      const { data } = await getJobs();
      jobList.value = data;
    } finally {
      jobLoading.value = false;
    }
  };

  const fetchGuilds = async () => {
    guildLoading.value = true;
    try {
      const { data } = await getGuilds();
      guildList.value = data;
    } finally {
      guildLoading.value = false;
    }
  };

  onMounted(() => {
    checkScreen();
    window.addEventListener('resize', checkScreen);
    fetchJobs();
    fetchGuilds();
  });

  onUnmounted(() => {
    window.removeEventListener('resize', checkScreen);
  });

  const loadData = async () => {
    setLoading(true);
    try {
      // 处理角色名筛选，如果包含 [ ID ] 格式，提取 ID 或名称
      let searchName = filterForm.value.name;
      let searchId = filterForm.value.id;

      if (searchName && searchName.includes('[') && searchName.includes(']')) {
        // 尝试提取 ID
        const match = searchName.match(/\[\s*(\d+)\s*\]/);
        if (match) {
          searchId = parseInt(match[1], 10);
          searchName = undefined; // 如果按ID搜，就不传name了，或者后端支持同时传
        } else {
          // 如果提取失败，可能只是名字里有方括号，去掉格式部分
          searchName = searchName.replace(/\[\s*\d+\s*\]\s*/, '');
        }
      }

      // 处理家族筛选，如果包含 [ ID ] 格式，提取 ID
      let searchGuildId = filterForm.value.guildId;
      // 这里我们假设用户输入的是字符串，但 filterForm.guildId 是 number 类型
      // 如果用户通过 allow-create 输入了非数字字符串，v-model 可能会绑定为字符串
      // 我们需要在这里进行处理
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const rawGuildInput = filterForm.value.guildId as any;
      if (typeof rawGuildInput === 'string') {
        if (rawGuildInput.includes('[') && rawGuildInput.includes(']')) {
          const match = rawGuildInput.match(/\[\s*(\d+)\s*\]/);
          if (match) {
            searchGuildId = parseInt(match[1], 10);
          } else {
            // 如果无法提取ID，且输入不是纯数字，则无法搜索（因为后端只支持ID）
            // 除非后端支持按名称搜索，目前暂不支持
            // 尝试解析纯数字
            const parsed = parseInt(rawGuildInput, 10);
            if (!Number.isNaN(parsed)) {
              searchGuildId = parsed;
            } else {
              searchGuildId = undefined;
            }
          }
        } else {
          // 尝试解析纯数字
          const parsed = parseInt(rawGuildInput, 10);
          if (!Number.isNaN(parsed)) {
            searchGuildId = parsed;
          } else {
            searchGuildId = undefined;
          }
        }
      }

      const { data } = await getPlayerList({
        pageNo: page.value,
        pageSize: size.value,
        ...filterForm.value,
        id: searchId,
        name: searchName,
        guildId: searchGuildId,
      });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const result = data as any;
      tableData.value = result.records;
      total.value = result.totalRow;
    } finally {
      setLoading(false);
    }
  };
  loadData();

  const refreshClick = () => {
    page.value = 1;
    loadData();
  };

  const pageChange = (data: number) => {
    page.value = data;
    loadData();
  };

  const pageSizeChange = (data: number) => {
    page.value = 1;
    size.value = data;
    loadData();
  };

  const resetClick = () => {
    filterForm.value = {
      id: undefined,
      name: undefined,
      map: undefined,
      status: 1,
      accountId: undefined,
      channel: undefined,
      job: undefined,
      partyId: undefined,
      guildId: undefined,
      minLevel: undefined,
      maxLevel: undefined,
      minOnlineTime: undefined,
      maxOnlineTime: undefined,
      banStatus: 0,
    };
    page.value = 1;
    loadData();
  };

  const toggleMoreFilters = () => {
    showMoreFilters.value = !showMoreFilters.value;
  };

  const globalGiveClick = () => {
    giveFormTitle.value = t('account.player.give.title.global');
    formData.value = {
      type: 5,
      playerId: 0,
      expireType: 0,
    };
    giveFormVisible.value = true;
  };

  const giveClick = (data: OnlinePlayer) => {
    giveFormTitle.value = t('account.player.give.title');
    formData.value = {
      worldId: data.world,
      playerId: data.id,
      player: data.name,
      type: 5,
      expireType: 0,
    };
    giveFormVisible.value = true;
  };

  const editClick = (record: OnlinePlayer) => {
    editTarget.value = record;
    editFormVisible.value = true;
  };

  const handleAllPlayerWarp = () => {
    warpTarget.value = null;
    warpFormVisible.value = true;
  };

  const handleDisconnect = (record: OnlinePlayer) => {
    Modal.confirm({
      title: t('account.player.disconnect.confirm.title'),
      content: t('account.player.disconnect.confirm.content', {
        name: record.name,
      }),
      onOk: async () => {
        setLoading(true);
        try {
          await disconnectPlayer({ ids: [record.id], all: false });
          Message.success(t('message.success'));
          loadData();
        } finally {
          setLoading(false);
        }
      },
    });
  };

  const handleGlobalDisconnect = () => {
    Modal.confirm({
      title: t('account.player.disconnect.global.confirm.title'),
      content: t('account.player.disconnect.global.confirm.content'),
      onOk: async () => {
        setLoading(true);
        try {
          await disconnectPlayer({ ids: [], all: true });
          Message.success(t('message.success'));
          loadData();
        } finally {
          setLoading(false);
        }
      },
    });
  };

  const handleBan = (record: OnlinePlayer) => {
    banTarget.value = record;
    banAll.value = false;
    banFormVisible.value = true;
  };

  const handleUnban = (record: OnlinePlayer) => {
    unbanTarget.value = record;
    unbanFormVisible.value = true;
  };

  const handleDuey = (record: OnlinePlayer) => {
    dueyTargetName.value = record.name;
    dueyFormVisible.value = true;
  };

  const handleGlobalDuey = () => {
    dueyTargetName.value = '';
    dueyFormVisible.value = true;
  };

  const handleGlobalAction = (
    value: string | number | Record<string, any> | undefined
  ) => {
    if (value === 'warp') {
      handleAllPlayerWarp();
    } else if (value === 'give') {
      globalGiveClick();
    } else if (value === 'disconnect') {
      handleGlobalDisconnect();
    } else if (value === 'duey') {
      handleGlobalDuey();
    }
  };

  const calculateOnlineTime = (loginTime?: string) => {
    if (!loginTime) return '-';
    const start = new Date(loginTime).getTime();
    const now = new Date().getTime();
    const diff = now - start;

    const hours = Math.floor(diff / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));

    return `${hours}h ${minutes}m`;
  };

  const handleWarp = (record: OnlinePlayer) => {
    warpTarget.value = record;
    warpFormVisible.value = true;
  };

  const submitWarp = async (mapId: number) => {
    setLoading(true);
    try {
      const data: GiveForm = {
        type: 13,
        quantity: mapId,
      };
      if (warpTarget.value) {
        data.worldId = warpTarget.value.world;
        data.playerId = warpTarget.value.id;
        data.player = warpTarget.value.name;
      } else {
        data.playerId = 0;
      }
      await givePlayerSrc(data);
      Message.success(t('message.success'));
      warpFormVisible.value = false;
      loadData();
    } finally {
      setLoading(false);
    }
  };

  const handleSingleAction = (
    value: string | number | Record<string, any> | undefined,
    record: OnlinePlayer
  ) => {
    if (value === 'edit') {
      editClick(record);
    } else if (value === 'warp') {
      handleWarp(record);
    } else if (value === 'give') {
      giveClick(record);
    } else if (value === 'disconnect') {
      handleDisconnect(record);
    } else if (value === 'ban') {
      handleBan(record);
    } else if (value === 'unban') {
      handleUnban(record);
    } else if (value === 'duey') {
      handleDuey(record);
    }
  };
</script>

<style scoped>
  .mobile-card {
    margin-bottom: 1rem;
    border: 1px solid var(--color-border-2);
  }
  .form-aligned :deep(.arco-form-item-label-col) {
    flex: 0 0 120px !important;
    width: 120px !important;
    display: flex;
    align-items: center;
    justify-content: flex-end;
    white-space: nowrap;
    padding-right: 12px;
  }
  .form-aligned :deep(.arco-form-item-wrapper-col) {
    flex: 1;
    width: auto;
    max-width: none;
  }
  .item-info-container {
    display: flex;
    margin-bottom: 20px;
    border: 1px solid var(--color-neutral-3);
    padding: 10px;
    border-radius: 4px;
    margin-left: 120px; /* Align with form inputs */
  }
  .item-icon-wrapper {
    margin-right: 16px;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 60px;
  }
  .item-icon {
    max-width: 100%;
    max-height: 100%;
  }
  .item-details {
    flex: 1;
  }
  .cell-flex {
    display: flex;
    align-items: center;
    justify-content: flex-start;
  }
  .cell-id {
    margin-right: 0;
  }
  .cell-divider {
    margin: 0 4px;
    height: 1.2em;
    border-color: var(--color-neutral-3);
  }
  .cell-text {
    flex: 1;
    text-align: left;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .cell-icon {
    width: 20px;
    margin-right: 0;
    display: flex;
    justify-content: center;
    align-items: center;
  }
</style>
