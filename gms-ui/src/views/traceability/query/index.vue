<template>
  <div class="container">
    <a-card class="general-card" :bordered="false">
      <!-- 标题区 -->
      <a-row>
        <a-col :span="24">
          <a-typography-title :heading="5">
            {{ $t('menu.traceability.query') }}
          </a-typography-title>
        </a-col>
      </a-row>
      <a-divider />

      <!-- 搜索表单 -->
      <a-form :model="formModel" layout="inline" @submit="handleSearch">
        <!-- 日期范围 -->
        <a-form-item
          field="dateRange"
          :label="$t('traceability.query.form.dateRange')"
        >
          <a-range-picker v-model="formModel.dateRange" show-time />
        </a-form-item>

        <!-- 物品ID -->
        <a-form-item
          field="itemId"
          :label="$t('traceability.query.form.itemId')"
        >
          <a-input
            v-model="formModel.itemName"
            :placeholder="$t('common.placeholder.select')"
            allow-clear
            @clear="formModel.itemId = undefined"
          >
            <template #append>
              <a-button @click="itemSelectorVisible = true">
                <icon-search />
              </a-button>
            </template>
          </a-input>
        </a-form-item>

        <!-- 角色ID -->
        <a-form-item
          field="characterId"
          :label="$t('traceability.query.form.characterId')"
        >
          <a-input
            v-model="formModel.characterName"
            :placeholder="$t('common.placeholder.select')"
            allow-clear
            @clear="formModel.characterId = undefined"
          >
            <template #append>
              <a-button @click="playerSelectorVisible = true">
                <icon-search />
              </a-button>
            </template>
          </a-input>
        </a-form-item>

        <!-- 物品UID (改为a-input处理长整型) -->
        <a-form-item field="uid" :label="$t('traceability.query.form.uid')">
          <a-input
            v-model="formModel.uid"
            :placeholder="$t('common.placeholder.input')"
            allow-clear
          />
        </a-form-item>

        <!-- 行为类型 (改为a-select) -->
        <a-form-item
          field="actionType"
          :label="$t('traceability.query.form.actionType')"
        >
          <a-select
            v-model="formModel.actionType"
            :placeholder="$t('common.placeholder.select')"
            allow-clear
          >
            <a-option
              v-for="type in actionTypes"
              :key="type.value"
              :value="type.value"
              >{{ type.label }}</a-option
            >
          </a-select>
        </a-form-item>

        <!-- 行为来源 -->
        <a-form-item
          field="actionSource"
          :label="$t('traceability.query.form.actionSource')"
        >
          <a-input
            v-model="formModel.actionSource"
            :placeholder="$t('common.placeholder.input')"
            allow-clear
          />
        </a-form-item>

        <!-- 操作按钮 -->
        <a-form-item>
          <a-space>
            <a-button type="primary" html-type="submit" :loading="loading">
              {{ $t('common.button.search') }}
            </a-button>
            <a-button @click="handleReset">
              {{ $t('button.reset') }}
            </a-button>
          </a-space>
        </a-form-item>
      </a-form>
      <a-divider />

      <!-- 表格 -->
      <div ref="tableContainerRef" class="table-container">
        <a-table
          :columns="columns"
          :data="tableData"
          :loading="loading"
          :pagination="pagination"
          :scroll="{ y: tableHeight }"
          @page-change="handlePageChange"
          @page-size-change="handlePageSizeChange"
        >
          <!-- 时间列 -->
          <template #timestamp="{ record }">
            {{ dayjs(record.timestamp).format('YYYY-MM-DD HH:mm:ss.SSS') }}
          </template>

          <!-- 物品列 -->
          <template #item="{ record }">
            <div class="item-cell">
              <a-popover
                position="right"
                :content-style="{
                  padding: 0,
                  border: 'none',
                  background: 'transparent',
                  boxShadow: 'none',
                }"
                :arrow-style="{ display: 'none' }"
              >
                <img
                  :src="getIconUrl('item', record.itemId)"
                  alt="item icon"
                  class="item-icon"
                />
                <template #content>
                  <keep-alive>
                    <component
                      :is="getTooltipComponent(record.itemId)"
                      :item="getItemProps(record)"
                    />
                  </keep-alive>
                </template>
              </a-popover>
              <div class="item-info">
                <div class="item-name">{{ record.itemName }}</div>
                <div class="item-id">ID: {{ record.itemId }}</div>
                <div class="item-id">UID: {{ record.uid }}</div>
              </div>
            </div>
          </template>

          <!-- 角色列 -->
          <template #character="{ record }">
            <div class="character-cell">
              <div>
                <div class="character-name">
                  {{ record.characterName || '-' }}
                </div>
                <div class="character-id">ID: {{ record.characterId }}</div>
              </div>
            </div>
          </template>

          <!-- 地图列 -->
          <template #map="{ record }">
            <div class="map-cell">
              <div>
                <div class="map-name">{{ record.mapName }}</div>
                <div class="map-id">ID: {{ record.mapId }}</div>
              </div>
            </div>
          </template>

          <!-- 行为列 -->
          <template #action="{ record }">
            <div class="action-cell">
              <div class="action-row">
                <span class="action-label"
                  >{{ $t('traceability.query.columns.actionSource') }}:</span
                >
                <span class="action-value">{{ record.actionSource }}</span>
              </div>
              <div class="action-row">
                <span class="action-label"
                  >{{ $t('traceability.query.columns.actionType') }}:</span
                >
                <span class="action-value">{{ record.actionType }}</span>
              </div>
            </div>
          </template>
        </a-table>
      </div>
    </a-card>

    <!-- 选择器弹窗 -->
    <ItemSelector
      v-model:visible="itemSelectorVisible"
      @select="handleItemSelect"
    />
    <PlayerSelector
      v-model:visible="playerSelectorVisible"
      @select="handlePlayerSelect"
    />
  </div>
</template>

<script lang="ts" setup>
  import {
    ref,
    reactive,
    computed,
    onMounted,
    onUnmounted,
    nextTick,
    defineAsyncComponent,
  } from 'vue';
  import { useI18n } from 'vue-i18n';
  import axios from 'axios'; // 导入axios
  import { queryTraceLogs, TraceLog } from '@/api/traceability';
  import type { ActionTypeDTO } from '@/api/traceability'; // 导入ActionTypeDTO
  import { InformationResult } from '@/api/information';
  import { OnlinePlayer } from '@/api/player';
  import { PaginationProps } from '@arco-design/web-vue';
  import { IconSearch } from '@arco-design/web-vue/es/icon';
  import useLoading from '@/hooks/loading';
  import dayjs from 'dayjs';
  import { getIconUrl } from '@/utils/mapleStoryAPI';
  import { isEquip } from '@/utils/mapleStoryItem';

  // 异步加载组件
  const EquipTooltip = defineAsyncComponent(
    () => import('@/components/ToolTip/EquipTooltip.vue')
  );
  const ItemTooltip = defineAsyncComponent(
    () => import('@/components/ToolTip/ItemTooltip.vue')
  );
  const ItemSelector = defineAsyncComponent(
    () => import('@/components/ItemSelector/index.vue')
  );
  const PlayerSelector = defineAsyncComponent(
    () => import('@/components/PlayerSelector/index.vue')
  );

  const { t } = useI18n();
  const { loading, setLoading } = useLoading(false);

  // 表单模型
  const formModel = reactive({
    uid: undefined as string | undefined, // [FIXED] Changed to string
    itemId: undefined as number | undefined,
    itemName: '',
    characterId: undefined as number | undefined,
    characterName: '',
    actionType: undefined as string | undefined, // [CHANGED] for a-select
    actionSource: undefined as string | undefined,
    dateRange: [] as (Date | string)[],
  });

  // 行为类型数据 (从后端获取)
  const actionTypes = ref<ActionTypeDTO[]>([]);

  // 表格数据
  const tableData = ref<TraceLog[]>([]);
  const pagination = reactive<PaginationProps>({
    current: 1,
    pageSize: 20,
    total: 0,
    showTotal: true,
    showJumper: true,
    showPageSize: true,
    pageSizeOptions: [20, 50, 100, 200],
  });

  // 选择器可见性
  const itemSelectorVisible = ref(false);
  const playerSelectorVisible = ref(false);

  /**
   * @zh-CN 处理物品选择
   */
  const handleItemSelect = (item: InformationResult) => {
    formModel.itemId = item.id;
    formModel.itemName = `[${item.id}] ${item.name}`;
    itemSelectorVisible.value = false;
  };

  /**
   * @zh-CN 处理角色选择
   */
  const handlePlayerSelect = (player: OnlinePlayer) => {
    formModel.characterId = player.id;
    formModel.characterName = `[${player.id}] ${player.name}`;
    playerSelectorVisible.value = false;
  };

  /**
   * @zh-CN 获取物品悬浮提示组件
   */
  const getTooltipComponent = (itemId: number) => {
    return isEquip(itemId) ? EquipTooltip : ItemTooltip;
  };

  /**
   * @zh-CN 构造并返回传递给 Tooltip 组件的 props 对象
   */
  const getItemProps = (record: TraceLog) => {
    if (isEquip(record.itemId)) {
      let itemDetails = {};
      try {
        if (record.itemSnapshot) {
          itemDetails = JSON.parse(record.itemSnapshot);
        }
      } catch (e) {
        console.error('Failed to parse itemSnapshot:', e);
      }
      return {
        ...itemDetails,
        itemId: record.itemId,
        name: record.itemName,
      };
    }
    return {
      itemId: record.itemId,
      name: record.itemName,
      quantity: record.quantityChange,
    };
  };

  // 表格列定义
  const columns = computed(() => [
    {
      title: t('traceability.query.columns.timestamp'),
      slotName: 'timestamp',
      width: 200,
    },
    {
      title: t('traceability.query.columns.item'),
      slotName: 'item',
      width: 250,
    },
    {
      title: t('traceability.query.columns.character'),
      slotName: 'character',
      width: 180,
    },
    {
      title: t('traceability.query.columns.map'),
      slotName: 'map',
      width: 180,
    },
    {
      title: t('traceability.query.columns.action'),
      slotName: 'action',
      width: 250,
    },
    {
      title: t('traceability.query.columns.quantityChange'),
      dataIndex: 'quantityChange',
      width: 80,
    },
    {
      title: t('traceability.query.columns.targetInfo'),
      dataIndex: 'targetInfo',
      width: 200,
    },
    {
      title: t('traceability.query.columns.memo'),
      dataIndex: 'memo',
      width: 280,
    },
  ]);

  // 表格高度自适应
  const tableContainerRef = ref<HTMLElement | null>(null);
  const tableHeight = ref(500);

  const updateTableHeight = () => {
    if (tableContainerRef.value) {
      const { top } = tableContainerRef.value.getBoundingClientRect();
      const windowHeight = window.innerHeight;
      tableHeight.value = windowHeight - top - 100;
    }
  };

  /**
   * @zh-CN 获取数据
   */
  const fetchData = async () => {
    setLoading(true);
    try {
      const { data } = await queryTraceLogs({
        pageNumber: pagination.current,
        pageSize: pagination.pageSize,
        // 确保 uid 是 string 或 undefined
        uid: formModel.uid === '' ? undefined : formModel.uid,
        itemId: formModel.itemId,
        characterId: formModel.characterId,
        actionType: formModel.actionType,
        actionSource:
          formModel.actionSource === '' ? undefined : formModel.actionSource,
        startTime: formModel.dateRange?.[0]
          ? dayjs(formModel.dateRange[0]).valueOf()
          : undefined,
        endTime: formModel.dateRange?.[1]
          ? dayjs(formModel.dateRange[1]).valueOf()
          : undefined,
      });
      tableData.value = data.records;
      pagination.total = data.totalRow;
    } finally {
      setLoading(false);
    }
  };

  /**
   * @zh-CN 搜索
   */
  const handleSearch = () => {
    pagination.current = 1;
    fetchData();
  };

  /**
   * @zh-CN 重置表单
   */
  const handleReset = () => {
    formModel.uid = undefined;
    formModel.itemId = undefined;
    formModel.itemName = '';
    formModel.characterId = undefined;
    formModel.characterName = '';
    formModel.actionType = undefined; // Reset to undefined for select
    formModel.actionSource = undefined;
    formModel.dateRange = [];
    handleSearch();
  };

  const handlePageChange = (page: number) => {
    pagination.current = page;
    fetchData();
  };

  const handlePageSizeChange = (pageSize: number) => {
    pagination.pageSize = pageSize;
    pagination.current = 1;
    fetchData();
  };

  onMounted(async () => {
    fetchData();
    window.addEventListener('resize', updateTableHeight);
    nextTick(() => {
      updateTableHeight();
    });

    // [FIXED] 从后端获取行为类型列表
    try {
      const { data } = await axios.get<ActionTypeDTO[]>(
        '/v1/traceability/action-types'
      );
      actionTypes.value = data;
    } catch (error) {
      console.error('Failed to fetch action types:', error);
      // 可以在这里设置一个默认值或者显示错误信息
    }
  });

  onUnmounted(() => {
    window.removeEventListener('resize', updateTableHeight);
  });
</script>

<style scoped lang="less">
  .container {
    padding: 0 20px 20px 20px;
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .general-card {
    flex: 1;
    display: flex;
    flex-direction: column;

    :deep(.arco-card-body) {
      flex: 1;
      display: flex;
      flex-direction: column;
      padding-bottom: 0;
    }
  }

  .table-container {
    flex: 1;
    overflow: hidden;
  }

  .item-cell,
  .character-cell,
  .map-cell {
    display: flex;
    align-items: center;
  }

  .item-icon {
    width: 32px;
    height: 32px;
    margin-right: 8px;
    flex-shrink: 0;
  }

  .item-info,
  .character-cell > div,
  .map-cell > div {
    display: flex;
    flex-direction: column;
    justify-content: center;
  }

  .item-name,
  .character-name,
  .map-name {
    font-weight: bold;
    color: var(--color-text-1);
  }

  .item-id,
  .character-id,
  .map-id {
    font-size: 12px;
    color: var(--color-text-3);
  }

  .action-cell {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .action-row {
    display: flex;
    align-items: center;
    font-size: 12px;
  }

  .action-label {
    color: var(--color-text-3);
    margin-right: 4px;
    min-width: 36px; /* 对齐标签 */
  }

  .action-value {
    color: var(--color-text-1);
  }
</style>
