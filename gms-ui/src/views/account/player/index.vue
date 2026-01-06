<template>
  <div class="container" :loading="true">
    <Breadcrumb />
    <a-card class="general-card" :title="$t('menu.account.player')">
      <!-- 搜索表单 -->
      <a-form :model="filterForm" class="a-from-keyword">
        <a-row :gutter="16">
          <a-col :span="6">
            <a-form-item :label="$t('account.player.id')">
              <a-input-number v-model="filterForm.id" />
            </a-form-item>
          </a-col>
          <a-col :span="6">
            <a-form-item :label="$t('account.player.name')">
              <a-input v-model="filterForm.name" />
            </a-form-item>
          </a-col>
          <a-col :span="6">
            <a-form-item :label="$t('account.player.mapId')">
              <a-input-number v-model="filterForm.map" />
            </a-form-item>
          </a-col>
          <a-col :span="6">
            <a-form-item :label="$t('account.player.status')">
              <a-select
                v-model="filterForm.status"
                :placeholder="$t('account.player.status.placeholder')"
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
              <router-link
                :to="{ name: 'AccountList', query: { id: record.accountId } }"
              >
                [ {{ record.accountId }} ] {{ record.accountName }}
              </router-link>
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
          />
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
            :min-width="250"
            align="center"
            ellipsis
            tooltip
          >
            <template #cell="{ record }">
              <span style="white-space: nowrap">
                {{ record.mapName }} ({{ record.map }})
                <a-button type="text" @click="handleWarp(record)">
                  {{ $t('account.player.button.warp') }}
                </a-button>
              </span>
            </template>
          </a-table-column>
          <a-table-column
            :title="$t('account.player.job')"
            :width="180"
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
            :width="90"
            align="center"
          />
          <a-table-column
            :title="$t('account.player.guild')"
            :width="180"
            align="center"
          >
            <template #cell="{ record }">
              <span v-if="record.guildId > 0">
                {{ record.guildName }} ({{ record.guildId }})
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
          <a-table-column :title="$t('account.list.column.operate')">
            <template #cell="{ record }">
              <a-button type="text" size="mini" @click="giveClick(record)">
                {{ $t('account.player.button.give') }}
              </a-button>
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
                    传送
                  </a-button>
                  <a-button size="mini" @click="giveClick(item)">发放</a-button>
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
                  {{ item.guildName }} ({{ item.guildId }})
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
    <a-modal
      v-model:visible="giveFormVisible"
      :title="giveFormTitle"
      :ok-loading="loading"
      :mask-closable="false"
      :esc-to-close="false"
      :ok-text="$t('account.player.give')"
      :on-before-ok="submitClick"
    >
      <!-- ... give form content ... -->
    </a-modal>
    <warp-modal
      v-model:visible="warpFormVisible"
      :loading="loading"
      @submit="submitWarp"
    />
  </div>
</template>

<script setup lang="ts">
  import { ref, onMounted, onUnmounted } from 'vue';
  import { Message } from '@arco-design/web-vue';
  import { useI18n } from 'vue-i18n';
  import useLoading from '@/hooks/loading';
  import {
    getPlayerList,
    GiveForm,
    givePlayerSrc,
    OnlinePlayer,
  } from '@/api/player';
  import WarpModal from './WarpModal.vue';

  const { t } = useI18n();
  const { loading, setLoading } = useLoading(false);
  const tableData = ref<OnlinePlayer[]>([]);
  const total = ref(0);
  const page = ref(1);
  const size = ref(14);
  const isMobile = ref(false);

  const filterForm = ref<{
    id?: number;
    name?: string;
    map?: number;
    status: number;
  }>({
    id: undefined,
    name: undefined,
    map: undefined,
    status: 1,
  });
  const giveFormVisible = ref(false);
  const giveFormTitle = ref('');
  const warpFormVisible = ref(false);
  const warpTarget = ref<OnlinePlayer | null>(null);

  const formData = ref<GiveForm>({
    type: 0,
  });

  const checkScreen = () => {
    isMobile.value = window.innerWidth < 768;
  };

  onMounted(() => {
    checkScreen();
    window.addEventListener('resize', checkScreen);
  });

  onUnmounted(() => {
    window.removeEventListener('resize', checkScreen);
  });

  const loadData = async () => {
    setLoading(true);
    try {
      const { data } = await getPlayerList(
        page.value,
        size.value,
        filterForm.value.id,
        filterForm.value.name,
        filterForm.value.map,
        filterForm.value.status
      );
      tableData.value = data.records;
      total.value = data.totalRow;
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
    filterForm.value.id = undefined;
    filterForm.value.name = undefined;
    filterForm.value.map = undefined;
    filterForm.value.status = 1;
    page.value = 1;
    loadData();
  };

  const globalGiveClick = () => {
    giveFormTitle.value = '全服发放资源';
    formData.value = {
      type: 0,
      playerId: 0,
    };
    giveFormVisible.value = true;
  };

  const giveClick = (data: OnlinePlayer) => {
    giveFormTitle.value = '发放资源';
    formData.value = {
      worldId: data.world,
      playerId: data.id,
      player: data.name,
      type: 0,
    };
    giveFormVisible.value = true;
  };

  const submitClick = async () => {
    setLoading(true);
    try {
      await givePlayerSrc(formData.value);
      Message.success(t('message.success'));
    } finally {
      setLoading(false);
    }
  };

  const handleAllPlayerWarp = () => {
    warpTarget.value = null;
    warpFormVisible.value = true;
  };

  const handleGlobalAction = (
    value: string | number | Record<string, any> | undefined
  ) => {
    if (value === 'warp') {
      handleAllPlayerWarp();
    } else if (value === 'give') {
      globalGiveClick();
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
</script>

<style scoped>
  .mobile-card {
    margin-bottom: 1rem;
    border: 1px solid var(--color-border-2);
  }
</style>
