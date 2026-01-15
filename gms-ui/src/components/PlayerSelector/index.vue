<template>
  <a-modal
    v-model:visible="visibleModel"
    :title="$t('playerSelector.title')"
    width="800px"
    @cancel="handleCancel"
    @ok="handleOk"
  >
    <a-form :model="filterForm" class="a-from-keyword">
      <a-row :gutter="16">
        <a-col :span="8">
          <a-form-item :label="$t('account.player.character')">
            <a-input
              v-model="filterForm.name"
              :placeholder="$t('account.player.character.placeholder')"
              allow-clear
            />
          </a-form-item>
        </a-col>
        <a-col :span="8">
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
        <a-col :span="8">
          <a-space>
            <a-button type="primary" @click="searchData">
              <template #icon>
                <icon-search />
              </template>
              {{ $t('button.search') }}
            </a-button>
            <a-button @click="resetSearch">
              <template #icon>
                <icon-refresh />
              </template>
              {{ $t('button.reset') }}
            </a-button>
            <a-button @click="toggleMoreFilters">
              <template #icon>
                <icon-down v-if="!showMoreFilters" />
                <icon-up v-else />
              </template>
            </a-button>
          </a-space>
        </a-col>
      </a-row>
      <a-row v-if="showMoreFilters" :gutter="16">
        <a-col :span="8">
          <a-form-item :label="$t('account.player.job')">
            <a-select
              v-model="filterForm.job"
              allow-search
              :placeholder="$t('account.player.job.placeholder')"
              :loading="jobLoading"
              allow-clear
            >
              <a-option v-for="job in jobList" :key="job.id" :value="job.id">
                {{ job.name }} ({{ job.id }})
              </a-option>
            </a-select>
          </a-form-item>
        </a-col>
        <a-col :span="8">
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
      </a-row>
    </a-form>

    <a-table
      row-key="id"
      :loading="loading"
      :data="playerList"
      :pagination="pagination"
      :row-selection="rowSelection"
      @page-change="onPageChange"
      @page-size-change="onPageSizeChange"
      @selection-change="handleSelectionChange"
    >
      <template #columns>
        <a-table-column title="ID" data-index="id" :width="100" />
        <a-table-column title="角色名" data-index="name" />
        <a-table-column title="职业" data-index="jobName" />
        <a-table-column title="等级" data-index="level" :width="80" />
      </template>
    </a-table>
  </a-modal>
</template>

<script lang="ts" setup>
  import { ref, reactive, computed, watch, onMounted } from 'vue';
  import { useI18n } from 'vue-i18n';
  import useLoading from '@/hooks/loading';
  import { getPlayerList, OnlinePlayer } from '@/api/player';
  import { getJobs, InformationResult } from '@/api/information';
  import { TableRowSelection } from '@arco-design/web-vue';
  import {
    IconSearch,
    IconRefresh,
    IconDown,
    IconUp,
  } from '@arco-design/web-vue/es/icon';

  const props = defineProps<{
    visible: boolean;
    multiple?: boolean;
  }>();

  const emit = defineEmits(['update:visible', 'select']);

  const { t } = useI18n();
  const { loading, setLoading } = useLoading(false);

  const visibleModel = computed({
    get: () => props.visible,
    set: (val) => emit('update:visible', val),
  });

  const playerList = ref<OnlinePlayer[]>([]);
  const filterForm = ref<{
    name?: string;
    status: number;
    job?: number;
    minLevel?: number;
    maxLevel?: number;
  }>({
    name: undefined,
    status: 0,
    job: undefined,
    minLevel: undefined,
    maxLevel: undefined,
  });

  const pagination = reactive({
    current: 1,
    pageSize: 10,
    total: 0,
    showTotal: true,
    showPageSize: true,
    pageSizeOptions: [10, 20, 50],
  });

  const selectedRowKeys = ref<(string | number)[]>([]);
  const showMoreFilters = ref(false);
  const jobList = ref<InformationResult[]>([]);
  const jobLoading = ref(false);

  const rowSelection = computed<TableRowSelection>(() => ({
    type: props.multiple ? 'checkbox' : 'radio',
    showCheckedAll: props.multiple,
  }));

  const fetchJobs = async () => {
    jobLoading.value = true;
    try {
      const { data } = await getJobs();
      jobList.value = data;
    } finally {
      jobLoading.value = false;
    }
  };

  const fetchData = async () => {
    setLoading(true);
    try {
      const { data } = await getPlayerList({
        pageNo: pagination.current,
        pageSize: pagination.pageSize,
        ...filterForm.value,
      });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const result = data as any;
      playerList.value = result.records;
      pagination.total = result.totalRow;
    } finally {
      setLoading(false);
    }
  };

  const searchData = () => {
    pagination.current = 1;
    fetchData();
  };

  const resetSearch = () => {
    filterForm.value = {
      name: undefined,
      status: 0,
      job: undefined,
      minLevel: undefined,
      maxLevel: undefined,
    };
    searchData();
  };

  const onPageChange = (current: number) => {
    pagination.current = current;
    fetchData();
  };

  const onPageSizeChange = (pageSize: number) => {
    pagination.pageSize = pageSize;
    pagination.current = 1;
    fetchData();
  };

  const handleSelectionChange = (rowKeys: (string | number)[]) => {
    selectedRowKeys.value = rowKeys;
  };

  const handleCancel = () => {
    visibleModel.value = false;
  };

  const handleOk = () => {
    if (selectedRowKeys.value.length > 0) {
      const selectedPlayers = playerList.value.filter((player) =>
        selectedRowKeys.value.includes(player.id)
      );
      if (props.multiple) {
        emit('select', selectedPlayers);
      } else {
        emit('select', selectedPlayers[0]);
      }
      visibleModel.value = false;
    }
  };

  const toggleMoreFilters = () => {
    showMoreFilters.value = !showMoreFilters.value;
  };

  watch(
    () => props.visible,
    (val) => {
      if (val) {
        searchData();
        selectedRowKeys.value = [];
      }
    }
  );

  onMounted(() => {
    fetchJobs();
  });
</script>
