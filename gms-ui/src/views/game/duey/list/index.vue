<template>
  <div class="container">
    <a-card class="general-card" :title="$t('duey.list.title')">
      <a-row>
        <a-col :flex="1">
          <a-form
            :model="formModel"
            :label-col-props="{ span: 6 }"
            :wrapper-col-props="{ span: 18 }"
            label-align="left"
          >
            <a-row :gutter="16">
              <a-col :span="8">
                <a-form-item
                  field="receiverName"
                  :label="$t('duey.list.receiverName')"
                >
                  <a-input
                    v-model="formModel.receiverName"
                    :placeholder="$t('duey.send.receiver.placeholder')"
                    allow-clear
                  />
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item
                  field="senderName"
                  :label="$t('duey.list.senderName')"
                >
                  <a-input
                    v-model="formModel.senderName"
                    :placeholder="$t('duey.send.sender.placeholder')"
                    allow-clear
                  />
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item
                  field="timeRange"
                  :label="$t('duey.list.timeRange')"
                >
                  <a-range-picker
                    v-model="formModel.timeRange"
                    style="width: 100%"
                    show-time
                    format="YYYY-MM-DD HH:mm:ss"
                  />
                </a-form-item>
              </a-col>
              <!-- 更多筛选条件 -->
              <a-col :span="8">
                <a-form-item field="itemId" :label="$t('duey.list.itemId')">
                  <a-input-number
                    v-model="formModel.itemId"
                    :placeholder="$t('duey.list.itemId')"
                    allow-clear
                  />
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item field="checked" :label="$t('duey.list.status')">
                  <a-select
                    v-model="formModel.checked"
                    :placeholder="$t('duey.list.status')"
                    allow-clear
                  >
                    <a-option :value="1">{{
                      $t('duey.list.status.unread')
                    }}</a-option>
                    <a-option :value="0">{{
                      $t('duey.list.status.read')
                    }}</a-option>
                    <a-option :value="2">{{
                      $t('duey.list.status.claimed')
                    }}</a-option>
                    <a-option :value="3">{{
                      $t('duey.list.status.expired')
                    }}</a-option>
                    <a-option :value="4">{{
                      $t('duey.list.status.deleted')
                    }}</a-option>
                  </a-select>
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item field="itemType" :label="$t('duey.list.type')">
                  <a-select
                    v-model="formModel.itemType"
                    :placeholder="$t('duey.list.type')"
                    allow-clear
                  >
                    <a-option :value="0">{{
                      $t('duey.list.type.normal')
                    }}</a-option>
                    <a-option :value="1">{{
                      $t('duey.list.type.quick')
                    }}</a-option>
                  </a-select>
                </a-form-item>
              </a-col>
            </a-row>
          </a-form>
        </a-col>
        <a-divider style="height: 84px" direction="vertical" />
        <a-col :flex="'86px'" style="text-align: right">
          <a-space direction="vertical" :size="18">
            <a-button type="primary" @click="search">
              <template #icon>
                <icon-search />
              </template>
              {{ $t('button.search') }}
            </a-button>
            <a-button @click="reset">
              <template #icon>
                <icon-refresh />
              </template>
              {{ $t('button.reset') }}
            </a-button>
          </a-space>
        </a-col>
      </a-row>
      <a-divider style="margin-top: 0" />
      <a-row style="margin-bottom: 16px">
        <a-col :span="12">
          <a-space>
            <a-button type="primary" @click="handleSend">
              <template #icon>
                <icon-plus />
              </template>
              {{ $t('duey.list.send') }}
            </a-button>
          </a-space>
        </a-col>
        <a-col :span="12" style="text-align: right">
          <a-radio-group v-model="viewMode" type="button">
            <a-radio value="list">
              <template #icon><icon-list /></template>
            </a-radio>
            <a-radio value="card">
              <template #icon><icon-apps /></template>
            </a-radio>
          </a-radio-group>
        </a-col>
      </a-row>

      <template v-if="viewMode === 'list'">
        <a-table
          row-key="packageId"
          :loading="loading"
          :pagination="pagination"
          :columns="columns"
          :data="renderData"
          @page-change="onPageChange"
          @page-size-change="onPageSizeChange"
        >
          <template #mesos="{ record }">
            <span v-if="record.mesos > 0">{{ record.mesos }}</span>
            <span v-else>-</span>
          </template>
          <template #items="{ record }">
            <a-space wrap>
              <div
                v-for="item in record.items"
                :key="item.itemId"
                class="item-cell"
              >
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
                    :src="getIconUrl('item', item.itemId)"
                    class="item-icon"
                  />
                  <template #content>
                    <keep-alive>
                      <component
                        :is="getTooltipComponent(item.itemId)"
                        :item="item"
                      />
                    </keep-alive>
                  </template>
                </a-popover>
                <div class="item-info">
                  <div class="item-name">{{ item.name || item.itemId }}</div>
                  <div class="item-quantity">x {{ item.quantity }}</div>
                </div>
              </div>
            </a-space>
          </template>
          <template #type="{ record }">
            <a-tag :color="record.type === 1 ? 'red' : 'green'">
              {{
                record.type === 1
                  ? $t('duey.list.type.quick')
                  : $t('duey.list.type.normal')
              }}
            </a-tag>
          </template>
          <template #checked="{ record }">
            <a-tag v-if="record.checked === 1" color="orange">
              {{ $t('duey.list.status.unread') }}
            </a-tag>
            <a-tag v-else-if="record.checked === 0" color="gray">
              {{ $t('duey.list.status.read') }}
            </a-tag>
            <a-tag v-else-if="record.checked === 2" color="blue">
              {{ $t('duey.list.status.claimed') }}
            </a-tag>
            <a-tag v-else-if="record.checked === 3" color="red">
              {{ $t('duey.list.status.expired') }}
            </a-tag>
            <a-tag v-else-if="record.checked === 4" color="magenta">
              {{ $t('duey.list.status.deleted') }}
            </a-tag>
          </template>
          <template #timestamp="{ record }">
            {{ formatDate(record.timestamp) }}
          </template>
          <template #deliveryTime="{ record }">
            {{ formatDate(record.deliveryTime) }}
          </template>
          <template #expireTime="{ record }">
            {{ formatDate(record.expireTime) }}
          </template>
          <template #operations="{ record }">
            <a-space>
              <a-button type="text" size="small" @click="handleEdit(record)">
                {{ $t('button.edit') }}
              </a-button>
              <a-popconfirm
                :content="$t('duey.list.delete.confirm')"
                @ok="handleDelete(record)"
              >
                <a-button type="text" status="danger" size="small">
                  {{ $t('button.delete') }}
                </a-button>
              </a-popconfirm>
            </a-space>
          </template>
        </a-table>
      </template>

      <template v-else>
        <div class="card-list">
          <a-spin :loading="loading" style="width: 100%">
            <a-grid
              :cols="{ xs: 1, sm: 2, md: 3, lg: 4, xl: 4, xxl: 5 }"
              :col-gap="16"
              :row-gap="16"
            >
              <a-grid-item v-for="item in renderData" :key="item.packageId">
                <a-card class="duey-card" hoverable>
                  <template #actions>
                    <a-space>
                      <span class="action-button" @click="handleEdit(item)">
                        <icon-edit /> {{ $t('button.edit') }}
                      </span>
                      <a-popconfirm
                        :content="$t('duey.list.delete.confirm')"
                        @ok="handleDelete(item)"
                      >
                        <span class="action-button delete">
                          <icon-delete /> {{ $t('button.delete') }}
                        </span>
                      </a-popconfirm>
                    </a-space>
                  </template>
                  <a-card-meta>
                    <template #title>
                      <div class="card-title">
                        <span class="sender-name">{{ item.senderName }}</span>
                        <icon-right />
                        <span class="receiver-name">{{
                          item.receiverName
                        }}</span>
                      </div>
                    </template>
                    <template #description>
                      <div class="card-content">
                        <div class="card-info-row">
                          <a-tag
                            size="small"
                            :color="item.type === 1 ? 'red' : 'green'"
                          >
                            {{
                              item.type === 1
                                ? $t('duey.list.type.quick')
                                : $t('duey.list.type.normal')
                            }}
                          </a-tag>
                          <a-tag
                            v-if="item.checked === 1"
                            size="small"
                            color="orange"
                          >
                            {{ $t('duey.list.status.unread') }}
                          </a-tag>
                          <a-tag
                            v-else-if="item.checked === 0"
                            size="small"
                            color="gray"
                          >
                            {{ $t('duey.list.status.read') }}
                          </a-tag>
                          <a-tag
                            v-else-if="item.checked === 2"
                            size="small"
                            color="blue"
                          >
                            {{ $t('duey.list.status.claimed') }}
                          </a-tag>
                          <a-tag
                            v-else-if="item.checked === 3"
                            size="small"
                            color="red"
                          >
                            {{ $t('duey.list.status.expired') }}
                          </a-tag>
                          <a-tag
                            v-else-if="item.checked === 4"
                            size="small"
                            color="magenta"
                          >
                            {{ $t('duey.list.status.deleted') }}
                          </a-tag>
                        </div>
                        <div v-if="item.mesos > 0" class="card-info-row">
                          <span class="label"
                            >{{ $t('duey.list.mesos') }}:</span
                          >
                          <span class="value">{{ item.mesos }}</span>
                        </div>
                        <div
                          v-if="item.items && item.items.length > 0"
                          class="card-items"
                        >
                          <div
                            v-for="i in item.items"
                            :key="i.itemId"
                            class="mini-item"
                          >
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
                                :src="getIconUrl('item', i.itemId)"
                                :title="(i.name || i.itemId).toString()"
                              />
                              <template #content>
                                <keep-alive>
                                  <component
                                    :is="getTooltipComponent(i.itemId)"
                                    :item="i"
                                  />
                                </keep-alive>
                              </template>
                            </a-popover>
                            <span class="qty">x{{ i.quantity }}</span>
                          </div>
                        </div>
                        <div class="card-time">
                          {{ formatDate(item.timestamp) }}
                        </div>
                      </div>
                    </template>
                  </a-card-meta>
                </a-card>
              </a-grid-item>
            </a-grid>
            <div class="pagination-wrapper">
              <a-pagination
                :total="pagination.total"
                :current="pagination.current"
                :page-size="pagination.pageSize"
                @change="onPageChange"
                @page-size-change="onPageSizeChange"
              />
            </div>
          </a-spin>
        </div>
      </template>
    </a-card>

    <SendDueyModal v-model:visible="sendVisible" @success="search" />
    <SendDueyModal
      v-model:visible="editVisible"
      :initial-data="currentEditPackage"
      @success="search"
    />
  </div>
</template>

<script lang="ts" setup>
  import {
    computed,
    ref,
    reactive,
    onMounted,
    defineAsyncComponent,
  } from 'vue';
  import { useI18n } from 'vue-i18n';
  import dayjs from 'dayjs';
  import useLoading from '@/hooks/loading';
  import { Pagination } from '@/types/global';
  import {
    getDueyList,
    deleteDueyPackage,
    DueyPackage,
    DueyListParams,
  } from '@/api/duey';
  import { Message, TableColumnData } from '@arco-design/web-vue';
  import {
    IconSearch,
    IconRefresh,
    IconPlus,
    IconList,
    IconApps,
    IconRight,
    IconDelete,
    IconEdit,
  } from '@arco-design/web-vue/es/icon';
  import { getIconUrl } from '@/utils/mapleStoryAPI';
  import { isEquip } from '@/utils/mapleStoryItem';
  import SendDueyModal from './components/SendDueyModal.vue';

  // 异步加载 Tooltip 组件
  const EquipTooltip = defineAsyncComponent(
    () => import('@/components/ToolTip/EquipTooltip.vue')
  );
  const ItemTooltip = defineAsyncComponent(
    () => import('@/components/ToolTip/ItemTooltip.vue')
  );

  const { t } = useI18n();
  const { loading, setLoading } = useLoading(true);

  const renderData = ref<DueyPackage[]>([]);
  const formModel = reactive({
    receiverName: '',
    senderName: '',
    timeRange: [],
    itemId: undefined,
    checked: undefined,
    itemType: undefined,
  });

  const basePagination: Pagination = {
    current: 1,
    pageSize: 20,
  };
  const pagination = reactive({
    ...basePagination,
  });

  const sendVisible = ref(false);
  const editVisible = ref(false);
  const currentEditPackage = ref<DueyPackage | undefined>(undefined);
  const viewMode = ref('list');

  const formatDate = (date: string | number | Date) => {
    if (!date) return '-';
    return dayjs(date).format('YYYY-MM-DD HH:mm:ss');
  };

  const getTooltipComponent = (itemId: number) => {
    return isEquip(itemId) ? EquipTooltip : ItemTooltip;
  };

  const columns = computed<TableColumnData[]>(() => [
    {
      title: t('duey.list.packageId'),
      dataIndex: 'packageId',
      width: 80,
    },
    {
      title: t('duey.list.receiverName'),
      dataIndex: 'receiverName',
      width: 120,
    },
    {
      title: t('duey.list.senderName'),
      dataIndex: 'senderName',
      width: 120,
    },
    {
      title: t('duey.list.mesos'),
      slotName: 'mesos',
      width: 120,
    },
    {
      title: t('duey.list.items'),
      slotName: 'items',
      width: 180, // 增加宽度
    },
    {
      title: t('duey.list.message'),
      dataIndex: 'message',
      ellipsis: true,
      tooltip: true,
      minWidth: 150,
      wordBreak: 'break-all',
    },
    {
      title: t('duey.list.type'),
      slotName: 'type',
      width: 60,
    },
    {
      title: t('duey.list.status'),
      slotName: 'checked',
      width: 60,
    },
    {
      title: t('duey.list.timeRange'),
      slotName: 'timestamp',
      width: 170,
    },
    {
      title: t('duey.list.deliveryTime'),
      slotName: 'deliveryTime',
      width: 170,
    },
    {
      title: t('duey.list.statusChangeTime'), // 修改标题为状态变更时间
      slotName: 'expireTime',
      width: 170,
    },
    {
      title: t('duey.list.operation'),
      slotName: 'operations',
      width: 120,
      fixed: 'right',
    },
  ]);

  const fetchData = async (
    params: DueyListParams = { pageNo: 1, pageSize: 20 }
  ) => {
    setLoading(true);
    try {
      const { data } = await getDueyList(params);
      renderData.value = data.records;
      pagination.current = params.pageNo;
      pagination.total = data.totalRow;
    } catch (err) {
      // err
    } finally {
      setLoading(false);
    }
  };

  const search = () => {
    const params: DueyListParams = {
      pageNo: 1,
      pageSize: pagination.pageSize,
      ...formModel,
    } as unknown as DueyListParams;

    if (formModel.timeRange && formModel.timeRange.length === 2) {
      params.startTime = new Date(formModel.timeRange[0]).getTime();
      params.endTime = new Date(formModel.timeRange[1]).getTime();
    }

    fetchData(params);
  };

  const onPageChange = (current: number) => {
    fetchData({ ...basePagination, pageNo: current });
  };

  const onPageSizeChange = (pageSize: number) => {
    basePagination.pageSize = pageSize;
    fetchData({ ...basePagination, pageNo: 1 });
  };

  const reset = () => {
    formModel.receiverName = '';
    formModel.senderName = '';
    formModel.timeRange = [];
    formModel.itemId = undefined;
    formModel.checked = undefined;
    formModel.itemType = undefined;
    search();
  };

  const handleSend = () => {
    sendVisible.value = true;
  };

  const handleEdit = (record: DueyPackage) => {
    if (record.checked === 2) {
      Message.warning(t('duey.send.error.claimed'));
      return;
    }
    currentEditPackage.value = record;
    editVisible.value = true;
  };

  const handleDelete = async (record: DueyPackage) => {
    try {
      await deleteDueyPackage(record.packageId);
      Message.success(t('message.success'));
      search();
    } catch (err) {
      // err
    }
  };

  onMounted(() => {
    fetchData();
  });
</script>

<style scoped lang="less">
  .container {
    padding: 0 20px 20px 20px;
  }
  :deep(.arco-table-th) {
    &:last-child {
      .arco-table-th-item-title {
        margin-left: 16px;
      }
    }
  }
  .action-icon {
    margin-left: 12px;
    cursor: pointer;
  }
  .active {
    color: #0960bd;
    background-color: #e3f4fc;
  }
  .setting {
    display: flex;
    align-items: center;
    width: 200px;
    .title {
      margin-left: 12px;
      cursor: pointer;
    }
  }

  .item-cell {
    display: flex;
    align-items: center;
    border: 1px solid var(--color-neutral-3);
    padding: 4px 8px;
    border-radius: 4px;
    background-color: var(--color-bg-2);
    margin-right: 4px;
    margin-bottom: 4px;
    white-space: nowrap; /* 防止换行 */
    cursor: pointer; /* 添加手型光标 */
    transition: background-color 0.2s;

    &:hover {
      background-color: var(--color-fill-2);
    }

    .item-icon {
      width: 32px;
      height: 32px;
      margin-right: 8px;
      flex-shrink: 0;
    }

    .item-info {
      display: flex;
      flex-direction: column;
      justify-content: center;
      overflow: hidden;

      .item-name {
        font-size: 12px;
        font-weight: bold;
        overflow: hidden;
        text-overflow: ellipsis;
      }

      .item-quantity {
        font-size: 10px;
        color: var(--color-text-3);
      }
    }
  }

  /* 卡片模式样式 */
  .card-list {
    margin-top: 16px;
  }
  .duey-card {
    border-radius: 4px;
    transition: all 0.3s;
    &:hover {
      transform: translateY(-4px);
      box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
    }
  }
  .card-title {
    display: flex;
    align-items: center;
    font-size: 14px;
    font-weight: bold;
    .sender-name {
      color: var(--color-text-1);
    }
    .receiver-name {
      color: var(--color-text-1);
    }
    .arco-icon {
      margin: 0 8px;
      color: var(--color-text-3);
    }
  }
  .card-content {
    margin-top: 8px;
  }
  .card-info-row {
    display: flex;
    align-items: center;
    margin-bottom: 8px;
    gap: 8px;
    .label {
      color: var(--color-text-3);
      font-size: 12px;
    }
    .value {
      color: var(--color-text-1);
      font-weight: bold;
    }
  }
  .card-items {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-bottom: 8px;
    .mini-item {
      position: relative;
      width: 32px;
      height: 32px;
      border: 1px solid var(--color-neutral-3);
      border-radius: 4px;
      display: flex;
      align-items: center;
      justify-content: center;
      background-color: var(--color-bg-2);
      cursor: pointer;
      &:hover {
        background-color: var(--color-fill-2);
      }
      img {
        max-width: 100%;
        max-height: 100%;
      }
      .qty {
        position: absolute;
        bottom: 0;
        right: 0;
        font-size: 8px;
        background: rgba(0, 0, 0, 0.6);
        color: #fff;
        padding: 0 2px;
        border-radius: 2px;
      }
    }
  }
  .card-time {
    font-size: 12px;
    color: var(--color-text-3);
    text-align: right;
  }
  .action-button {
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    padding: 4px 0;
    color: var(--color-text-2);
    &:hover {
      color: rgb(var(--primary-6));
    }
    &.delete:hover {
      color: rgb(var(--danger-6));
    }
    .arco-icon {
      margin-right: 4px;
    }
  }
  .pagination-wrapper {
    margin-top: 16px;
    display: flex;
    justify-content: flex-end;
  }

  /* 移动端适配 */
  @media (max-width: 768px) {
    .arco-form-item {
      margin-bottom: 16px;
    }
    .arco-col-8 {
      width: 100% !important;
      flex: 0 0 100% !important;
      max-width: 100% !important;
    }
    .arco-divider-vertical {
      display: none;
    }
    .arco-col-flex-86px {
      text-align: left !important;
      margin-top: 10px;
      width: 100%;
      flex: 0 0 100% !important;
    }
  }
</style>
